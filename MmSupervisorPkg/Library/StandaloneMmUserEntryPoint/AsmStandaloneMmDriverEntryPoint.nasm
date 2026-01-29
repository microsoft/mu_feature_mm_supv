;
; Entry point to a Standalone MM driver.
;
; Copyright (c), Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;

    DEFAULT REL
    SECTION .text

extern ASM_PFX(_ModuleEntryPointWorker)

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; _ModuleEntryPoint (
;   IN EFI_HANDLE               ImageHandle,
;   IN IN EFI_MM_SYSTEM_TABLE   *MmSystemTable
;   )
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(_ModuleEntryPoint)
ASM_PFX(_ModuleEntryPoint):
    ;By the time we are here, it should be everything CPL3 already
    sub     rsp, 0x28

    ;To boot strap this driver, we directly call the entry point worker
    call    _ModuleEntryPointWorker

    ;Restore the stack pointer
    add     rsp, 0x28

    ;Once returned, we will get returned status in rax, don't touch it, if you can help
    ;r15 contains call gate selector that was planned ahead
    push    r15                         ; New selector to be used, which is set to call gate by the supervisor
    DB      0xff, 0x1c, 0x24            ; call    far qword [rsp]; return to ring 0 via call gate m16:32
    jmp     $                           ; Code should not reach here
