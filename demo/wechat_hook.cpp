#include <iostream>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>

#include "hook.h"
#include "target/targetopt.h"
#include "log/log.h"

#define WECHAT_OFFSET 0x9b0a7a
#define NOP_PATTERN_SIZE 16

/* Import assembly labels directly */
extern "C" void wechat_hook(void);
extern "C" void wechat_hook_resume(void);

/*
 * Helper function to page-align an address and call mprotect
 */
static int mprotect_page(void *addr, size_t len, int prot) {
  long page_size = sysconf(_SC_PAGESIZE);

  // Align address down to page boundary
  uintptr_t aligned_addr = (uintptr_t) addr & ~(page_size - 1);

  // Adjust length to cover the original range
  size_t aligned_len = len + ((uintptr_t) addr - aligned_addr);

  // Round up length to page size
  aligned_len = (aligned_len + page_size - 1) & ~(page_size - 1);

  int result = mprotect((void *) aligned_addr, aligned_len, prot);

  if (result < 0) {
    printf("mprotect failed: addr=%p, aligned=%p, len=0x%lx, errno=%d (%s)\n",
	   addr, (void *) aligned_addr, aligned_len, errno, strerror(errno));
  }

  return result;
}

/*
 * Validate pointer is in user space range
 */
static inline bool is_valid_user_ptr(uint64_t addr) {
  return (addr >= 0x10000 && addr < 0x7fffffffffff);
}

/*
 * Hook core function - receives pointer to saved registers
 * This is called from assembly: wechat_hook_core(&regs)
 */
extern "C" void wechat_hook_core(struct hook_regs *regs) {
  /*
   * Access register values - these are the EXACT values
   * that were in the CPU registers when WeChat hit the hook point
   */

  if (is_valid_user_ptr(regs->rdi)) {
    LOGGER_INFO << " rdi  " << LogFormat::addr << regs->rdi
      << "  " << (char *) regs->rdi;
  }

  /*
   * You can examine other registers too:
   */
#if 0
  if (is_valid_user_ptr(regs->rsi)) {
    LOGGER_INFO << " rsi  " << LogFormat::addr << regs->rsi
      << "  " << (char *) regs->rsi;
  }
  if (is_valid_user_ptr(regs->rdx)) {
    LOGGER_INFO << " rdx  " << LogFormat::addr << regs->rdx;
  }
  if (is_valid_user_ptr(regs->rcx)) {
    LOGGER_INFO << " rcx  " << LogFormat::addr << regs->rcx;
  }
  if (is_valid_user_ptr(regs->r8)) {
    LOGGER_INFO << " r8   " << LogFormat::addr << regs->r8;
  }
  if (is_valid_user_ptr(regs->r9)) {
    LOGGER_INFO << " r9   " << LogFormat::addr << regs->r9;
  }
#endif

  /*
   * You can also MODIFY registers!
   * Changes here will be restored to actual CPU registers
   * when returning to WeChat.
   * 
   * Example: Change return value
   *   regs->rax = 0;
   * 
   * Example: Modify first argument
   *   regs->rdi = (uint64_t)my_fake_string;
   */
}

/*
 * Library initialization - called when libX.so is loaded
 */
void __attribute__ ((constructor)) wechat_hook_init(void) {
  printf("\n==============================================\n");
  printf("libX.so loaded - Installing WeChat hook\n");
  printf("==============================================\n");

  lmc::Logger::setLevel(LogLevel::all);

  TargetMaps target(getpid());
  Elf64_Addr wechat_baseaddr = 0;

  /* Get addresses directly from exported assembly labels */
  Elf64_Addr first_nop_cmd_addr = (Elf64_Addr)wechat_hook;
  Elf64_Addr second_nop_cmd_addr = (Elf64_Addr)wechat_hook_resume;

  if (!target.readTargetAllMaps()) {
    LOGGER_ERROR << "Failed to read target maps";
    return;
  }

  /* Find WeChat base address */
  auto & maps = target.getMapInfo();
  for (auto & m:maps) {
    /* Check for wechat binary, but exclude .so files */
    if (m.first.find("wechat") != std::string::npos &&
        m.first.find(".so") == std::string::npos &&
        wechat_baseaddr == 0) {
      wechat_baseaddr = m.second;
      LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
    }
  }

  if (!wechat_baseaddr) {
    LOGGER_ERROR << "Failed to find WeChat base address";
    return;
  }

  LOGGER_INFO << "WeChat base: " << LogFormat::addr << wechat_baseaddr;
  LOGGER_INFO << "Hook target: " << LogFormat::addr << (wechat_baseaddr +
							WECHAT_OFFSET);
  LOGGER_INFO << "Entry sled (wechat_hook): " << LogFormat::addr << first_nop_cmd_addr;
  LOGGER_INFO << "Exit sled (wechat_hook_resume): " << LogFormat::addr << second_nop_cmd_addr;

  /*
   * Make memory writable for patching
   * Only request the minimum size needed (one page should be enough)
   */
  void *wechat_hook_addr = (void *) (wechat_baseaddr + WECHAT_OFFSET);
  void *libx_first_addr = (void *) first_nop_cmd_addr;
  void *libx_second_addr = (void *) second_nop_cmd_addr;

  // Only need to make writable the specific regions we're patching
  // 12 bytes at WeChat hook point
  // ~30 bytes at each NOP sled

  if (mprotect_page(wechat_hook_addr, 12, PROT_WRITE | PROT_READ | PROT_EXEC)
      < 0) {
    LOGGER_ERROR << "mprotect failed for WeChat hook point";
    return;
  }

  if (mprotect_page(libx_first_addr, 64, PROT_WRITE | PROT_READ | PROT_EXEC) <
      0) {
    LOGGER_ERROR << "mprotect failed for libX first NOP sled";
    return;
  }

  if (mprotect_page(libx_second_addr, 64, PROT_WRITE | PROT_READ | PROT_EXEC)
      < 0) {
    LOGGER_ERROR << "mprotect failed for libX second NOP sled";
    return;
  }

  /*
   * =================================================================
   * PATCH 1: Exit trampoline (second_nop_cmd_addr)
   * 
   * Layout (24 bytes total):
   *   [0-11]  Original 12 bytes from WeChat @ 0x9b0a7a
   *   [12-21] movabs rax, return_addr
   *   [22-23] jmp rax
   * =================================================================
   */
  unsigned char *exit_patch = (unsigned char *) second_nop_cmd_addr;

  /* Copy original 12 bytes that we're about to overwrite */
  memcpy(exit_patch, (unsigned char *) wechat_baseaddr + WECHAT_OFFSET, 12);

  /* movabs rax, imm64 (return address = hook point + 12) */
  Elf64_Addr return_addr = wechat_baseaddr + WECHAT_OFFSET + 12;

  exit_patch[12] = 0x48;	/* REX.W */
  exit_patch[13] = 0xB8;	/* MOV RAX, imm64 */
  memcpy(&exit_patch[14], &return_addr, 8);

  /* jmp rax */
  exit_patch[22] = 0xFF;
  exit_patch[23] = 0xE0;

  /*
   * =================================================================
   * PATCH 2: WeChat hook point (wechat_baseaddr + WECHAT_OFFSET)
   * 
   * Layout (12 bytes total):
   *   [0-9]   movabs rax, first_nop_cmd_addr
   *   [10-11] jmp rax
   * =================================================================
   */
  unsigned char *hook_patch =
    (unsigned char *) wechat_baseaddr + WECHAT_OFFSET;

  /* movabs rax, imm64 (our hook entry point) */
  hook_patch[0] = 0x48;		/* REX.W */
  hook_patch[1] = 0xB8;		/* MOV RAX, imm64 */
  memcpy(&hook_patch[2], &first_nop_cmd_addr, 8);

  /* jmp rax */
  hook_patch[10] = 0xFF;
  hook_patch[11] = 0xE0;

  /* Restore memory protection */
  mprotect_page(wechat_hook_addr, 12, PROT_READ | PROT_EXEC);
  mprotect_page(libx_first_addr, 64, PROT_READ | PROT_EXEC);
  mprotect_page(libx_second_addr, 64, PROT_READ | PROT_EXEC);

  LOGGER_INFO << "==============================================";
  LOGGER_INFO << "Hook installed successfully!";
  LOGGER_INFO << "  Hook point: " << LogFormat::addr << (wechat_baseaddr +
							 WECHAT_OFFSET);
  LOGGER_INFO << "  Entry sled: " << LogFormat::addr << first_nop_cmd_addr;
  LOGGER_INFO << "  Exit sled:  " << LogFormat::addr << second_nop_cmd_addr;
  LOGGER_INFO << "==============================================";
}
