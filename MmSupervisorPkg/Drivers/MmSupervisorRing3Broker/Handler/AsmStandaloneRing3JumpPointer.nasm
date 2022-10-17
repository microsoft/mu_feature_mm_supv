;
; Jump point to a Standalone MM handler.
;
; Copyright (c), Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; CentralRing3JumpPointer (
;   IN EFI_HANDLE  *DispatchHandle,
;   IN CONST VOID  *Context         OPTIONAL,
;   IN OUT VOID    *CommBuffer      OPTIONAL,
;   IN OUT UINTN   *CommBufferSize  OPTIONAL
;   )
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(CentralRing3JumpPointer)
ASM_PFX(CentralRing3JumpPointer):
    ;By the time we are here, it should be everything CPL3 already

    ;Note that top of stack at this moment is real jmp point
    pop     rax

    sub     rsp, 0x28

    ;To boot strap this driver, we directly call the entry point worker
    call    rax

    ;Restore the stack pointer
    add     rsp, 0x28

    ;Just to restore the stack to be a law-abiding citizen
    push    rax

    ;Once returned, we will get returned status in rax, don't touch it, if you can help
    ;r15 contains call gate selector that was planned ahead
    push    r15                         ; New selector to be used, which is set to call gate by the supervisor
    DB      0xff, 0x1c, 0x24            ; call    far qword [rsp]; return to ring 0 via call gate m16:32
    call    far qword [rsp]             ; return to ring 0 via call gate
    jmp     $                           ; Code should not reach here

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; ApRing3JumpPointer (
;   IN EFI_AP_PROCEDURE2        Procedure,
;   IN VOID                     *ProcedureArgument,
;   )
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(ApRing3JumpPointer)
ASM_PFX(ApRing3JumpPointer):
    ;By the time we are here, it should be everything CPL3 already
    sub     rsp, 0x18

    mov     rax, rcx
    mov     rcx, rdx

    ;To boot strap this procedure, we directly call the registered procedure worker
    call    rax

    ;Restore the stack pointer
    add     rsp, 0x18

    ;Once returned, we will get returned status in rax, don't touch it, if you can help
    ;r15 contains call gate selector that was planned ahead
    push    r15                         ; New selector to be used, which is set to call gate by the supervisor
    DB      0xff, 0x1c, 0x24;call    far qword [rsp]             ; return to ring 0 via call gate
    jmp     $                           ; Code should not reach here
