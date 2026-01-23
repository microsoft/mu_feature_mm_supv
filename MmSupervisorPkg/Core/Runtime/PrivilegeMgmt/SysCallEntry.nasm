;------------------------------------------------------------------------------ ;
; Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
; Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
; Copyright (c) Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   WriteTr.nasm
;
; Abstract:
;
;   Write TR register
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

; Segments defined in SmiException.nasm
%define LONG_DS_R0                      0x40
%define LONG_DS_R3                      0x53

; This should be OFFSET_OF (MM_SUPV_SYSCALL_CACHE, MmSupvRsp)
%define MM_SUPV_RSP                     0x00
; This should be OFFSET_OF (MM_SUPV_SYSCALL_CACHE, SavedUserRsp)
%define SAVED_USER_RSP                  0x08

extern ASM_PFX(SyscallDispatcher)
;------------------------------------------------------------------------------
; Caller Interface:
; UINT64
; EFIAPI <SysV calling convention>
; SysCall (
;   UINTN CallIndex,
;   UINTN Arg1,
;   UINTN Arg2,
;   UINTN Arg3
;   );
;
; Backend Interface:
; UINT64
; EFIAPI
; SyscallDispatcher (
;   UINTN         CallIndex,
;   UINTN         Arg1,
;   UINTN         Arg2,
;   UINTN         Arg3,
;   UINTN         CallerAddr
;   );
;------------------------------------------------------------------------------
global ASM_PFX(SyscallCenter)
ASM_PFX(SyscallCenter):
; Calling convention: CallIndex in RAX, Arg1 in RDX, Arg2 in R8, Arg3 in R9 from SysCallLib
; Architectural definition: CallerAddr in RCX, rFLAGs in R11 from x64 syscall instruction
; push CallIndex stored at top of stack

    swapgs  ; get kernel pointer, save user GSbase
    mov gs:[SAVED_USER_RSP], rsp ; save user's stack pointer
    mov rsp, gs:[MM_SUPV_RSP] ; set up kernel stack

    ;Preserve all registers in CPL3
    push    rax
    push    rcx
    push    rbp
    push    rdx
    push    r8
    push    r9
    push    rsi
    push    r12
    push    rdi
    push    rbx
    push    r11
    push    r10
    push    r13
    push    r14
    push    r15

    mov     rbp, rsp
    and     rsp, -16

    ;; FX_SAVE_STATE_X64 FxSaveState;
    sub rsp, 512
    mov rdi, rsp
    db 0xf, 0xae, 0x7 ;fxsave [rdi]

    ;Prepare for ds, es, fs, gs
    xor     rbx, rbx
    mov     bx, LONG_DS_R0
    mov     ds, bx
    mov     es, bx
    mov     fs, bx

    mov     rsi, gs:[SAVED_USER_RSP]     ; Save Ring 3 stack to RSI
    push    rsi                          ; Push Ring 3 stack as Ring3Stack for SyscallDispatcher
    push    rcx                          ; Push return address on stack as CallerAddr for SyscallDispatcher
    mov     rcx, rax
    sub     rsp, 0x20

    call    ASM_PFX(SyscallDispatcher)

    add     rsp, 0x20
    pop     rcx                          ; Restore SP to avoid stack overflow
    pop     rsi                          ; Restore SI to avoid stack overflow

    ;Prepare for ds, es, fs, gs
    xor     rbx, rbx
    mov     bx, LONG_DS_R3
    mov     ds, bx
    mov     es, bx
    mov     fs, bx

    mov rsi, rsp
    db 0xf, 0xae, 0xE ; fxrstor [rsi]
    add rsp, 512

    mov     rsp, rbp

    ;restore registers from CPL3 stack
    pop     r15
    pop     r14
    pop     r13
    pop     r10
    pop     r11
    pop     rbx
    pop     rdi
    pop     r12
    pop     rsi
    pop     r9
    pop     r8
    pop     rdx
    pop     rbp
    cmp     [rsp], rcx
    je      NormalReturn  ; if syscall dispatcher changed return address, need to go through error report
    push    rcx           ; Make caller ID on the top of stack
    mov     rcx, [rsp+8]  ; Put real jump point in rcx
    mov     [rsp+8], rax  ; Make jump buffer second from the top of stack
    ; The next will be call index pushed from rax
    ; Note that in this path, the stack is 3 segments taller than input
    jmp     Sysret

NormalReturn:
    pop     rcx           ; return rcx from stack
    add     rsp, 8        ; return rsp to original position
Sysret:
    mov     rsp, gs:[SAVED_USER_RSP]  ; restore user RSP
    swapgs  ; restore user GS, save kernel pointer
    db      48h           ; return to the long mode
    sysret                ; RAX contains return value
