#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#include <sys/mman.h>

#include "target/targetopt.h"
#include "log/log.h"

#define WECHAT_OFFSET 0x9b0a7a

void __attribute__((constructor)) wechat_hook_init(void) {
  /*

  Init Actions:
  
    Find the base address of the wechat binary and libX.so
    Find 2nd NOP sleds (32 consecutive 0x90 bytes) in libX.so to use as trampoline
    Hook the instruction at WECHAT_OFFSET (0x9b0a7a) by:
        Relocating the instructions to the second NOP sled (trampoline)
        Replacing the original instructions with a jump to the first NOP sled
        The first NOP sled fall-throuh to the hook function

  Hock Logic:

    At hook point in wechat, flags are set by cmp %r12,%rdi, then it
    Jump to first_nop_cmd_addr (the first NOP sled in wechat_hook())
    After the NOP sled, pushfq to save the flags from the cmp
    Then `mov %rbp,%r14; mov %rdi,%r15;` to save rbp & rdi to r14 r15
    Call wechat_hook_run(), which has its own prologue that modifies flags
    After return: popfq to restore the original flags before any compiler-generated code can mess with stack
    Then is the second NOP sled, which now contains the trampoline code
    The trampoline code finish the relocated instructions then
    jumps back to wechat to continue its normal operations

   */
  
  printf("Dynamic library loaded: Running initialization.\n");
  lmc::Logger::setLevel(LogLevel::all);
  TargetMaps target(getpid());
  Elf64_Addr wechat_baseaddr = 0;
  Elf64_Addr libx_baseaddr = 0;
  Elf64_Addr first_nop_cmd_addr = 0;
  Elf64_Addr second_nop_cmd_addr = 0;
  if (target.readTargetAllMaps())
  {
    auto &maps = target.getMapInfo();
    for (auto &m : maps)
    {
      if (m.first.find("wechat") != std::string::npos)
      {
        wechat_baseaddr = m.second;
        LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
      }

      if (m.first.find("libX.so") != std::string::npos)
      {
        libx_baseaddr = m.second;
        LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
      } 
    }

    unsigned char buffer[16] = {0x90};
    memset(buffer, 0x90, sizeof(buffer));

    unsigned char *nop_cmd_byte = (unsigned char *)libx_baseaddr;
    for (int i = 0; i < 0x1000000; i++)
    {
      if (!memcmp(&nop_cmd_byte[i], buffer, sizeof(buffer)))
      {
        if (first_nop_cmd_addr)
        {
          second_nop_cmd_addr = (Elf64_Addr)&nop_cmd_byte[i];
          LOGGER_INFO << "second search successful   " << LogFormat::addr << second_nop_cmd_addr;
          break;
        } else {
          first_nop_cmd_addr = (Elf64_Addr)&nop_cmd_byte[i];
          LOGGER_INFO << "first search successful   " << LogFormat::addr << first_nop_cmd_addr;
          i += 16;
          continue;
        }
      }
    }

    if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect wechat (RWX) failed";
    }

    if (mprotect((void *)(libx_baseaddr), 0x10000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect libx (RWX) failed";
    }
        
    // --- FIXED TRAMPOLINE: relocate je/call/cmpb correctly ---
    //
    // Original at WECHAT_OFFSET:
    //   9b0a7a: 74 05                   je     9b0a81
    //   9b0a7c: e8 3f e1 a4 ff          call   3febc0 <_ZdlPv@plt>
    //   9b0a81: 80 7c 24 10 00          cmpb   $0x0,0x10(%rsp)
    //
    // We build at second_nop_cmd_addr:
    //   jz  +0x0c                      ; skip movabs+call if ZF=1
    //   movabs rax, call_target
    //   call  rax
    //   cmpb  $0x0,0x10(%rsp)
    //   movabs rax, resume
    //   jmp   rax
    //
    // NOTE: call is absolute (mov rax; call rax) to avoid rel32 range issues
    // when calling from libX.so to wechat.

    unsigned char *orig = (unsigned char *)wechat_baseaddr + WECHAT_OFFSET;
    unsigned char *tramp = (unsigned char *)second_nop_cmd_addr;

    unsigned char tramp_inst[32];
    memset(tramp_inst, 0x90, sizeof(tramp_inst));
    int t_idx = 0;

    // 1) JZ +0x0c  (skip over movabs+call)
    tramp_inst[t_idx++] = 0x74;  // JZ rel8
    tramp_inst[t_idx++] = 0x0c;  // +12 bytes

    // 2) Compute absolute call_target from original rel32
    int orig_disp = 0;
    memcpy(&orig_disp, orig + 3, 4);  // original disp32 at orig+3
    Elf64_Addr orig_call_after = (Elf64_Addr)(orig + 2 + 5);
    Elf64_Addr call_target = orig_call_after + (int64_t)orig_disp;

    // 3) movabs rax, call_target
    tramp_inst[t_idx++] = 0x48;
    tramp_inst[t_idx++] = 0xb8;
    memcpy(&tramp_inst[t_idx], &call_target, 8);
    t_idx += 8;

    // 4) call rax
    tramp_inst[t_idx++] = 0xff;
    tramp_inst[t_idx++] = 0xd0;

    // 5) cmpb $0x0,0x10(%rsp)  (copy from orig+7, position-independent)
    memcpy(&tramp_inst[t_idx], orig + 7, 5);
    t_idx += 5;

    // Write relocated instructions to second_nop_cmd_addr
    memcpy(tramp, tramp_inst, t_idx);

    // After these t_idx bytes, keep your original movabs/jmp back.

    unsigned char movabs_wechat_buffer[10];
    memset(movabs_wechat_buffer, 0, sizeof(movabs_wechat_buffer));
    Elf64_Addr wechat_hook_point_addr = (Elf64_Addr)wechat_baseaddr + WECHAT_OFFSET + 12;
    movabs_wechat_buffer[0] = 0x48;
    movabs_wechat_buffer[1] = 0xb8;
    memcpy(&movabs_wechat_buffer[2], &wechat_hook_point_addr, 8);

    memcpy((unsigned char *)second_nop_cmd_addr + t_idx, movabs_wechat_buffer, 10);

    unsigned char jmp_wechat_buffer[2];
    jmp_wechat_buffer[0] = 0xff;
    jmp_wechat_buffer[1] = 0xe0;
    memcpy((unsigned char *)second_nop_cmd_addr + t_idx + 10, jmp_wechat_buffer, 2);

    // --- HOOK INSTALLATION ---
    unsigned char movabs_buffer[10];
    memset(movabs_buffer, 0, sizeof(movabs_buffer));
    movabs_buffer[0] = 0x48;
    movabs_buffer[1] = 0xb8;
    memcpy(&movabs_buffer[2], &first_nop_cmd_addr, 8);
    memcpy((unsigned char *)wechat_baseaddr + WECHAT_OFFSET, movabs_buffer, 10);
  
    unsigned char jmp_buffer[2];
    jmp_buffer[0] = 0xff;
    jmp_buffer[1] = 0xe0;
    memcpy((unsigned char *)wechat_baseaddr + WECHAT_OFFSET + 10, jmp_buffer, 2);

    if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect wechat (RX) failed";
    }

    if (mprotect((void *)(libx_baseaddr), 0x10000, PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect libx (RX) failed";
    }
  }
}

static void wechat_hook_core(struct user_regs_struct *regs)
{
  // if (regs->r8 > 0x5016f3e7d290 && regs->r8 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r8  " << LogFormat::addr << regs->r8 << "  " << (char *)regs->r8;
  // }
  // if (regs->r9 > 0x5016f3e7d290 && regs->r9 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r9  " << LogFormat::addr << regs->r9 << "  " << (char *)regs->r9;
  // }
  // if (regs->r10 > 0x5016f3e7d290 && regs->r10 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r10  " << LogFormat::addr << regs->r10 << "  " << (char *)regs->r10;
  // }
  // if (regs->r11 > 0x5016f3e7d290 && regs->r11 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r11  " << LogFormat::addr << regs->r11 << "  " << (char *)regs->r11;
  // }
  // if (regs->r12 > 0x5016f3e7d290 && regs->r12 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r12  " << LogFormat::addr << regs->r12 << "  " << (char *)regs->r12;
  // }
  // if (regs->r13 > 0x5016f3e7d290 && regs->r13 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r13  " << LogFormat::addr << regs->r13 << "  " << (char *)regs->r13;
  // }
  // if (regs->rsi > 0x5016f3e7d290 && regs->rsi < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " rsi  " << LogFormat::addr << regs->rsi << "  " << (char *)regs->rsi;
  // }
  if (regs->rdi > 0x5016f3e7d290 && regs->rdi < 0x7fffffffffff)
  {
    LOGGER_INFO << " rdi  " << LogFormat::addr << regs->rdi << "  " << (char *)regs->rdi;
  }
  // if (regs->rsp > 0x5016f3e7d290 && regs->rsp < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " rsp  " << LogFormat::addr << regs->rsp << "  " << (char *)regs->rsp;
  // }
  // if (regs->rbp > 0x5016f3e7d290 && regs->rbp < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " rbp  " << LogFormat::addr << regs->rbp << "  " << (char *)regs->rbp;
  // }
}

static void wechat_hook_run()
{
  struct user_regs_struct regs = {0};

  asm volatile (
    "mov %%rbx, %0\n"
    "mov %%rcx, %1\n"
    "mov %%rdx, %2\n"
    "mov %%rsi, %3\n"
    "mov %%r15, %4\n"
    "mov %%r14, %5\n"
    "mov %%rsp, %6\n"
    "mov %%r8, %7\n"
    "mov %%r9, %8\n"
    "mov %%r10, %9\n"
    "mov %%r11, %10\n"
    "mov %%r12, %11\n"
    "mov %%r13, %12\n"
    "mov %%r14, %13\n"
    "mov %%r15, %14\n"
    : "=m"(regs.rbx), "=m"(regs.rcx), "=m"(regs.rdx),
      "=m"(regs.rsi), "=m"(regs.rdi), "=m"(regs.rbp), "=m"(regs.rsp),
      "=m"(regs.r8), "=m"(regs.r9), "=m"(regs.r10), "=m"(regs.r11),
      "=m"(regs.r12), "=m"(regs.r13), "=m"(regs.r14), "=m"(regs.r15)
    :
    : "memory"
    );

  wechat_hook_core(&regs);

  asm volatile (
    "mov %0, %%rbx\n"
    "mov %1, %%rcx\n"
    "mov %2, %%rdx\n"
    "mov %3, %%rsi\n"
    "mov %4, %%rdi\n"
    "mov %5, %%r8\n"
    "mov %6, %%r9\n"
    "mov %7, %%r10\n"
    "mov %8, %%r11\n"
    "mov %9, %%r12\n"
    "mov %10, %%r13\n"
    "mov %11, %%r14\n"
    "mov %12, %%r15\n"
    :
    : "m"(regs.rbx), "m"(regs.rcx), "m"(regs.rdx),
      "m"(regs.rsi), "m"(regs.rdi), "m"(regs.r8), 
      "m"(regs.r9), "m"(regs.r10), "m"(regs.r11),
      "m"(regs.r12), "m"(regs.r13), "m"(regs.r14), "m"(regs.r15)
    : "memory", "cc",
      "rax","rbx","rcx","rdx","rsi","rdi",
      "r8","r9","r10","r11","r12","r13","r14","r15"
    );
}

void wechat_hook()
{
  // first_nop_cmd_addr
  asm("nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "mov %rbp,%r14;\n"
      "mov %rdi,%r15;\n"
      "pushfq;\n"        // save flags from cmp %r12,%rdi
      "sub $8, %rsp;\n"  // keep stack 16-byte aligned for call (if desired)
    );
   
  wechat_hook_run();

  asm("add $8, %rsp;\n"  // undo alignment adjustment (if used)
      // second_nop_cmd_addr
      "popfq;\n"         // restore flags before executing relocated je/call/cmpb
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
    );
}
