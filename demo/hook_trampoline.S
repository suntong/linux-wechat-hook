.intel_syntax noprefix
.text

#============================================================================
# Register struct layout (must match C struct exactly)
#============================================================================
.set REG_RAX,    0
.set REG_RBX,    8
.set REG_RCX,    16
.set REG_RDX,    24
.set REG_RSI,    32
.set REG_RDI,    40
.set REG_RBP,    48
.set REG_RSP,    56
.set REG_R8,     64
.set REG_R9,     72
.set REG_R10,    80
.set REG_R11,    88
.set REG_R12,    96
.set REG_R13,    104
.set REG_R14,    112
.set REG_R15,    120
.set REG_RFLAGS, 128
.set REG_STRUCT_SIZE, 136

#============================================================================
# wechat_hook - Main hook entry point
#============================================================================
.global wechat_hook          # Entry point (16 NOPs)
.global wechat_hook_resume   # Exit point (64 NOPs)
.type wechat_hook, @function

wechat_hook:
    #========================================================================
    # ENTRY NOP SLED (16 bytes)
    # This is first_nop_cmd_addr - init code patches WeChat to jump here
    # DO NOT MODIFY - init code searches for this pattern
    #========================================================================
    .rept 16
    nop
    .endr

    #========================================================================
    # ALLOCATE STACK SPACE FIRST
    # 
    # CRITICAL: Use lea instead of sub!
    # sub modifies flags (ZF, SF, CF, OF, etc.), but we need to preserve
    # the original flags from WeChat for the exit trampoline's je instruction.
    # lea does NOT modify flags.
    #
    # HANDLE RED ZONE + ALLOCATE REGISTER STRUCT
    # x86-64 SysV ABI: 128 bytes below RSP may contain WeChat's data
    # We must not corrupt this area
    #
    # We allocate space for:
    #   - 128 bytes red zone (x86-64 SysV ABI)
    #   - REG_STRUCT_SIZE bytes for our register struct
    #========================================================================
    lea rsp, [rsp - 128 - REG_STRUCT_SIZE]

    #========================================================================
    # SAVE ALL OTHER REGISTERS TO STRUCT
    # 
    # Stack layout after this:
    #   [rsp + 0]   = rax
    #   [rsp + 8]   = rbx
    #   ...
    #   [rsp + 128] = rflags
    #========================================================================
    mov [rsp + REG_RAX], rax
    mov [rsp + REG_RBX], rbx
    mov [rsp + REG_RCX], rcx
    mov [rsp + REG_RDX], rdx
    mov [rsp + REG_RSI], rsi
    mov [rsp + REG_RDI], rdi
    mov [rsp + REG_RBP], rbp
    # skip REG_RSP for now
    mov [rsp + REG_R8],  r8
    mov [rsp + REG_R9],  r9
    mov [rsp + REG_R10], r10
    mov [rsp + REG_R11], r11
    mov [rsp + REG_R12], r12
    mov [rsp + REG_R13], r13
    mov [rsp + REG_R14], r14
    mov [rsp + REG_R15], r15

    # Save original RSP (value before our allocation)
    lea rax, [rsp + 128 + REG_STRUCT_SIZE]
    mov [rsp + REG_RSP], rax

    #========================================================================
    # SAVE RFLAGS
    # Now we save the ORIGINAL flags from WeChat, since we used lea
    # (which doesn't modify flags) instead of sub.
    #========================================================================
    pushfq
    pop rax
    mov [rsp + REG_RFLAGS], rax

    #========================================================================
    # CALL wechat_hook_core(&regs)
    #
    # SysV ABI: First argument passed in RDI
    # rsp currently points to our struct, so:
    #   mov rdi, rsp  -->  rdi = &regs
    #
    # This is EXACTLY equivalent to the C code:
    #   wechat_hook_core(&regs);
    #========================================================================
    
    mov rdi, rsp                    # RDI = &regs (first argument to function)
    
    # Save struct pointer in callee-saved register (survives function call)
    mov rbx, rsp
    
    # Align stack to 16 bytes (required by SysV ABI before CALL)
    and rsp, -16
    sub rsp, 8
    
    # Call the C hook function
    # wechat_hook_core receives pointer to saved registers
    call wechat_hook_core
    
    # Restore stack pointer to our struct
    mov rsp, rbx

    #========================================================================
    # RESTORE RFLAGS
    #========================================================================
    mov rax, [rsp + REG_RFLAGS]
    push rax
    popfq

    #========================================================================
    # RESTORE ALL REGISTERS FROM STRUCT
    # If wechat_hook_core() modified any regs->xxx values,
    # those changes will take effect here!
    #========================================================================
    mov rax, [rsp + REG_RAX]
    mov rbx, [rsp + REG_RBX]
    mov rcx, [rsp + REG_RCX]
    mov rdx, [rsp + REG_RDX]
    mov rsi, [rsp + REG_RSI]
    mov rdi, [rsp + REG_RDI]
    mov rbp, [rsp + REG_RBP]
    mov r8,  [rsp + REG_R8]
    mov r9,  [rsp + REG_R9]
    mov r10, [rsp + REG_R10]
    # r11 restored below after we're done using rsp-relative addressing
    mov r12, [rsp + REG_R12]
    mov r13, [rsp + REG_R13]
    mov r14, [rsp + REG_R14]
    mov r15, [rsp + REG_R15]

    #========================================================================
    # RESTORE R11 AND RSP
    # 
    # Order matters! Load r11 while we can still access the struct,
    # then restore rsp (after which we can't access the struct anymore).
    #========================================================================
    mov r11, [rsp + REG_R11]        # restore original r11 value
    mov rsp, [rsp + REG_RSP]        # restore original RSP

wechat_hook_resume:
    #========================================================================
    # EXIT NOP SLED (64 bytes)
    # This is second_nop_cmd_addr - init code patches this with relocated
    # instructions that handle RIP-relative addressing:
    #
    # Original code at 0x9b0a7a:
    #   74 05             je +5 (skip call if equal)
    #   e8 XX XX XX XX    call rel32
    #   80 7c 24 10 00    cmpb $0x0, 0x10(%rsp)
    #
    # Patched trampoline (31 bytes):
    #   74 0C             je +12 (skip movabs+call)
    #   48 B8 [8 bytes]   movabs rax, <absolute call target>
    #   FF D0             call rax
    #   80 7C 24 10 00    cmpb $0x0, 0x10(%rsp)
    #   48 B8 [8 bytes]   movabs rax, <return address>
    #   FF E0             jmp rax
    #========================================================================
    .rept 64
    nop
    .endr

    # Should never reach here if patching worked correctly
    ret

.size wechat_hook, .-wechat_hook

#============================================================================
# Mark stack as non-executable (security + silences linker warning)
#============================================================================
#if defined(__ELF__)
  .section .note.GNU-stack, "", @progbits
#endif
