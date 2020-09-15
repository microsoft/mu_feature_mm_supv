;
; Jump point to a Standalone MM handler.
;
; Copyright (c), Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;

    DEFAULT REL
    SECTION .text

extern ASM_PFX(MmSupvErrorReportWorker)

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; RegErrorReportJumpPointer (
;   IN UINTN                    CpuIndex,
;   IN VOID                     *ErrorInfoBuffer,
;   IN UINTN                    ErrorInfoSize
;   )
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(RegErrorReportJumpPointer)
ASM_PFX(RegErrorReportJumpPointer):
    ;By the time we are here, it should be everything CPL3 already
    sub     rsp, 0x18

    ;To boot strap this procedure, we directly call the registered procedure worker
    call    MmSupvErrorReportWorker

    ;Restore the stack pointer
    add     rsp, 0x18

    ;Once returned, we will get returned status in rax, don't touch it, if you can help
    ;r15 contains call gate selector that was planned ahead
    push    r15                         ; New selector to be used, which is set to call gate by the supervisor
    DB      0xff, 0x1c, 0x24;call    far qword [rsp]             ; return to ring 0 via call gate
    jmp     $                           ; Code should not reach here
