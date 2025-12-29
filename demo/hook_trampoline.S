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
.global wechat_hook_resume   # Exit point (30 NOPs)
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
    # SAVE ORIGINAL RSP IMMEDIATELY
    # Must do this FIRST before any stack operations
    # Use r11 temporarily (caller-saved, will be saved to struct later)
    #========================================================================
    mov r11, rsp

    #========================================================================
    # HANDLE RED ZONE
    # x86-64 SysV ABI: 128 bytes below RSP may contain WeChat's data
    # We must not corrupt this area
    #========================================================================
    sub rsp, 128

    #========================================================================
    # ALLOCATE REGISTER STRUCT ON STACK
    # Equivalent to: struct hook_regs regs;
    #========================================================================
    sub rsp, REG_STRUCT_SIZE

    #========================================================================
    # SAVE ALL REGISTERS TO STRUCT
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
    mov [rsp + REG_RSP], r11        # Original RSP (saved in r11 earlier)
    mov [rsp + REG_R8],  r8
    mov [rsp + REG_R9],  r9
    mov [rsp + REG_R10], r10
    mov [rsp + REG_R11], r11        # r11 held original RSP, save it too
    mov [rsp + REG_R12], r12
    mov [rsp + REG_R13], r13
    mov [rsp + REG_R14], r14
    mov [rsp + REG_R15], r15

    # Save RFLAGS (condition flags)
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
    # Skip r11 for now - we need it to restore RSP
    mov r12, [rsp + REG_R12]
    mov r13, [rsp + REG_R13]
    mov r14, [rsp + REG_R14]
    mov r15, [rsp + REG_R15]

    #========================================================================
    # RESTORE ORIGINAL RSP
    # This also deallocates our struct and red zone padding
    # 
    # Note: We use r11 as temporary, then restore it
    #========================================================================
    mov r11, [rsp + REG_R11]        # Load saved r11 value to r11
    mov rsp, [rsp + REG_RSP]        # Restore original RSP
    # r11 is caller-saved, so WeChat doesn't rely on its value
    # If needed, we could use a different strategy to preserve it exactly

wechat_hook_resume:
    #========================================================================
    # EXIT NOP SLED (30 bytes)
    # This is second_nop_cmd_addr - init code patches this with:
    #   [Original 12 bytes from WeChat @ 0x9b0a7a] (12 bytes)
    #   [movabs rax, wechat_baseaddr + 0x9b0a7a + 12] (10 bytes)
    #   [jmp rax] (2 bytes)
    # Total: 24 bytes, with 6 bytes spare
    #========================================================================
    .rept 30
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
