#include <iostream>
#include <stdint.h>
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
   * UNCONDITIONAL DEBUG: Print to confirm we reached here
   */
  printf("[HOOK] wechat_hook_core called!\n");
  printf("[HOOK] rdi=0x%lx rsi=0x%lx rax=0x%lx\n",
         regs->rdi, regs->rsi, regs->rax);
  printf("[HOOK] rsp=0x%lx rbp=0x%lx rflags=0x%lx\n",
         regs->rsp, regs->rbp, regs->rflags);
  fflush(stdout);  // Force immediate output

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

  /* 
   * Find WeChat base address by scanning maps.
   * CRITICAL: Take the LAST matching entry (no early exit).
   * The WECHAT_OFFSET was calculated assuming this behavior.
   * Exclude .so files to avoid matching paths like /path/wechat-beta/libX.so
   */
  auto & maps = target.getMapInfo();
  for (auto & m : maps) {
    if (m.first.find("wechat") != std::string::npos &&
        m.first.find(".so") == std::string::npos) {
      wechat_baseaddr = m.second;  // OVERWRITES - always takes LAST match
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
  // ~64 bytes at exit sled

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
   * RUNTIME ASSERTION: Verify hook site bytes before patching
   * 
   * Expected bytes at 0x9b0a7a (12 bytes):
   *   [0-1]   74 05             je +5
   *   [2]     e8                call rel32 opcode
   *   [3-6]   XX XX XX XX       rel32 displacement
   *   [7-11]  80 7c 24 10 00    cmpb $0x0, 0x10(%rsp)
   * =================================================================
   */
  unsigned char *orig = (unsigned char *) wechat_baseaddr + WECHAT_OFFSET;
  
  /* Expected bytes for verification */
  const unsigned char expected_je[2] = { 0x74, 0x05 };
  const unsigned char expected_call_opcode = 0xE8;
  const unsigned char expected_cmpb[5] = { 0x80, 0x7C, 0x24, 0x10, 0x00 };
  
  bool mismatch = false;

  /* Check je +5 at orig[0..1] */
  if (memcmp(orig, expected_je, 2) != 0) {
    LOGGER_ERROR << "Assertion failed: je instruction mismatch at orig+0";
    LOGGER_ERROR << "  Expected: 74 05";
    LOGGER_ERROR << "  Got: " << LogFormat::addr << (unsigned int)orig[0] 
                 << " " << LogFormat::addr << (unsigned int)orig[1];
    mismatch = true;
  }

  /* Check call opcode at orig[2] */
  if (orig[2] != expected_call_opcode) {
    LOGGER_ERROR << "Assertion failed: call opcode mismatch at orig+2";
    LOGGER_ERROR << "  Expected: E8";
    LOGGER_ERROR << "  Got: " << LogFormat::addr << (unsigned int)orig[2];
    mismatch = true;
  }

  /* Check cmpb at orig[7..11] */
  if (memcmp(orig + 7, expected_cmpb, 5) != 0) {
    LOGGER_ERROR << "Assertion failed: cmpb instruction mismatch at orig+7";
    LOGGER_ERROR << "  Expected: 80 7C 24 10 00";
    LOGGER_ERROR << "  Got: " 
                 << LogFormat::addr << (unsigned int)orig[7] << " "
                 << LogFormat::addr << (unsigned int)orig[8] << " "
                 << LogFormat::addr << (unsigned int)orig[9] << " "
                 << LogFormat::addr << (unsigned int)orig[10] << " "
                 << LogFormat::addr << (unsigned int)orig[11];
    mismatch = true;
  }

  if (mismatch) {
    LOGGER_ERROR << "Hook site verification FAILED - aborting to prevent crash";
    LOGGER_ERROR << "Full 12 bytes at hook site:";
    LOGGER_ERROR << "  " 
                 << LogFormat::addr << (unsigned int)orig[0] << " "
                 << LogFormat::addr << (unsigned int)orig[1] << " "
                 << LogFormat::addr << (unsigned int)orig[2] << " "
                 << LogFormat::addr << (unsigned int)orig[3] << " "
                 << LogFormat::addr << (unsigned int)orig[4] << " "
                 << LogFormat::addr << (unsigned int)orig[5] << " "
                 << LogFormat::addr << (unsigned int)orig[6] << " "
                 << LogFormat::addr << (unsigned int)orig[7] << " "
                 << LogFormat::addr << (unsigned int)orig[8] << " "
                 << LogFormat::addr << (unsigned int)orig[9] << " "
                 << LogFormat::addr << (unsigned int)orig[10] << " "
                 << LogFormat::addr << (unsigned int)orig[11];
    
    /* Restore memory protection before aborting */
    mprotect_page(wechat_hook_addr, 12, PROT_READ | PROT_EXEC);
    mprotect_page(libx_first_addr, 64, PROT_READ | PROT_EXEC);
    mprotect_page(libx_second_addr, 64, PROT_READ | PROT_EXEC);
    return;
  }

  LOGGER_INFO << "Hook site verification PASSED";

  /*
   * =================================================================
   * PATCH 1: Exit trampoline (second_nop_cmd_addr)
   * 
   * Original code at 0x9b0a7a (12 bytes):
   *   74 05             je +5 (skip call if equal)
   *   e8 XX XX XX XX    call rel32 (relative call to _ZdlPv@plt)
   *   80 7c 24 10 00    cmpb $0x0, 0x10(%rsp)
   *
   * Problem: je and call use RIP-relative addressing, so we cannot
   * just memcpy them - they would jump/call to wrong addresses.
   *
   * Solution: Rebuild with absolute addressing (31 bytes total):
   *   74 0C             je +12 (skip movabs+call = 10+2 bytes)
   *   48 B8 [8 bytes]   movabs rax, <absolute call target>
   *   FF D0             call rax
   *   80 7C 24 10 00    cmpb $0x0, 0x10(%rsp) (safe, no relocation)
   *   48 B8 [8 bytes]   movabs rax, <return address>
   *   FF E0             jmp rax
   *
   * Why this works:
   *   - je remains short and only skips the call in the trampoline
   *   - The call is absolute and no longer depends on trampoline's RIP
   *   - mov/call don't alter flags; RFLAGS restored earlier preserves
   *     the cmp's flags for the je
   *   - rax is caller-saved, and the original call clobbers it anyway
   * =================================================================
   */
  unsigned char *exit_patch = (unsigned char *) second_nop_cmd_addr;

  /* Compute absolute target of original call at orig+2 (e8 rel32) */
  int32_t rel32 = 0;
  memcpy(&rel32, orig + 3, sizeof(rel32));                  /* imm32 right after 0xE8 */
  Elf64_Addr call_site_end = (Elf64_Addr)(orig + 2 + 5);    /* orig+7 */
  Elf64_Addr call_abs = (Elf64_Addr)((int64_t)call_site_end + (int64_t)rel32);

  /* movabs rax, imm64 (return address = hook point + N) */
  Elf64_Addr return_addr = wechat_baseaddr + WECHAT_OFFSET + 12; /* N = 12 here */

  LOGGER_INFO << "Original call target (absolute): " << LogFormat::addr << call_abs;
  LOGGER_INFO << "Return address: " << LogFormat::addr << return_addr;

  size_t off = 0;

  /* je +12 (skip movabs+call = 10+2 bytes) */
  exit_patch[off++] = 0x74;
  exit_patch[off++] = 0x0C;

  /* movabs rax, <abs target of original call> */
  exit_patch[off++] = 0x48;  /* REX.W */
  exit_patch[off++] = 0xB8;  /* MOV RAX, imm64 */
  memcpy(exit_patch + off, &call_abs, 8); off += 8;

  /* call rax */
  exit_patch[off++] = 0xFF;
  exit_patch[off++] = 0xD0;

  /* Normalize RAX so we don't resume with RAX == return address */
  exit_patch[off++] = 0x31;  /* xor eax, eax */
  exit_patch[off++] = 0xC0;

  /* cmpb 0x10(%rsp), $0x0 — copy original 5 bytes from orig+7 */
  memcpy(exit_patch + off, orig + 7, 5); off += 5;

  /* movabs r11, return_addr */
  exit_patch[off++] = 0x49;  /* REX.W + REX.B */
  exit_patch[off++] = 0xBB;  /* MOV R11, imm64 */
  memcpy(exit_patch + off, &return_addr, 8); off += 8;

  /* jmp r11 */
  exit_patch[off++] = 0x41;  /* REX.B */
  exit_patch[off++] = 0xFF;
  exit_patch[off++] = 0xE3;

  LOGGER_INFO << "Exit trampoline size: " << LogFormat::addr << off << " bytes";

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

  /* Debug: dump the patched bytes */
  printf("[PATCH] Exit trampoline bytes:\n  ");
  for (size_t i = 0; i < off; i++) {
    printf("%02X ", exit_patch[i]);
  }
  printf("\n");

  printf("[PATCH] Hook point bytes:\n  ");
  for (int i = 0; i < 12; i++) {
    printf("%02X ", hook_patch[i]);
  }
  printf("\n");
  fflush(stdout);

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
