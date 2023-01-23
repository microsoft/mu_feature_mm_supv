;------------------------------------------------------------------------------ ;
; Copyright 2008 - 2020 ADVANCED MICRO DEVICES, INC.  All Rights Reserved.
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
%define PROTECTED_DS                    0x20
%define LONG_CS_R0                      0x38
%define LONG_DS_R0                      0x40
%define LONG_CS_R3_PH                   0x4B
%define LONG_DS_R3                      0x53
%define LONG_CS_R3                      0x5B
%define CALL_GATE_OFFSET                0x63

extern ASM_PFX(SetupCallGate)
extern ASM_PFX(SetupTssDescriptor)

extern ASM_PFX(SetupBspCpl0MsrStar)
extern ASM_PFX(RestoreBspCpl0MsrStar)

extern ASM_PFX(SetupCpl0MsrStar)
extern ASM_PFX(RestoreCpl0MsrStar)

extern ASM_PFX(GetBspCpl3Stack)
extern ASM_PFX(GetThisCpl3Stack)

extern ASM_PFX(RegErrorReportJumpPointer)

%macro CHECK_RAX    0
    cmp     rax, 0
    jz      .4
%endmacro

;------------------------------------------------------------------------------
; /**
;   Invoke specified routine on specified core in CPL 3.
;
;   @param[in]      CpuIndex            CpuIndex value of intended core, cannot be
;                                       greater than mNumberOfCpus.
;   @param[in]      Cpl3Routine         Function pointer to demoted routine.
;   @param[in]      ArgCount            Number of arguments needed by Cpl3Routine.
;   @param          ...                 The variable argument list whose count is defined by
;                                       ArgCount. Its contented will be accessed and populated
;                                       to the registers and/or CPL3 stack areas per EFIAPI
;                                       calling convention.
;
;   @retval EFI_SUCCESS                 The demoted routine returns successfully.
;   @retval Others                      Errors caught by subroutines during ring transitioning
;                                       or error code returned from demoted routine.
; **/
; EFI_STATUS
; EFIAPI
; InvokeDemotedRoutine (
;   IN UINTN                 CpuIndex,
;   IN EFI_PHYSICAL_ADDRESS  Cpl3Routine,
;   IN UINTN                 ArgCount,
;   ...
;   );
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(InvokeDemotedRoutine)
ASM_PFX(InvokeDemotedRoutine):
    ;Preserve input parameters onto reg parameter stack area for later usage
    mov     [rsp + 0x20], r9
    mov     [rsp + 0x18], r8
    mov     [rsp + 0x10], rdx
    mov     [rsp + 0x08], rcx

    ;Preserve nonvolatile registers, in case demoted routines mess with them
    push    rbp
    mov     rbp, rsp
    ;Clear the lowest 16 bit after saving rsp, to make sure the stack pointer 16byte aligned
    and     rsp, -16

    push    rbx
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ;Preserve the updated rbp as we need them on return
    push    rbp

    push    rcx
    sub     rsp, 0x28
    call    GetThisCpl3Stack
    add     rsp, 0x28
    mov     r15, rax
    and     r15, -16
    pop     rcx

    ;rcx is CpuIndex, so no worries for this call
    sub     rsp, 0x20
    call    SetupCpl0MsrStar
    add     rsp, 0x20

    ;Setup call gate for return
    lea     rcx, [.5]
    mov     rdx, 1
    sub     rsp, 0x20
    call    SetupCallGate
    add     rsp, 0x20

    ;Setup SetupTssDescriptor for return
    mov     rcx, rsp
    mov     rdx, 1
    sub     rsp, 0x20
    call    SetupTssDescriptor
    add     rsp, 0x20

    ;Same level far return to apply GDT change
    xor     rcx, rcx
    mov     rcx, cs
    push    rcx                 ;prepare cs on the stack
    lea     rax, [.2]
    push    rax                 ;prepare return rip on the stack
    retfq

.2:
    ;Prepare for ds, es, fs, gs
    xor     rax, rax
    mov     ax, LONG_DS_R3
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ;Prepare input arguments
    mov     rax, [rbp + 0x20]           ;Get ArgCount from stack
    CHECK_RAX
    mov     rcx, [rbp + 0x28]           ;First input argument for demoted routine
    dec     rax
    CHECK_RAX
    mov     rdx, [rbp + 0x30]           ;Second input argument for demoted routine
    dec     rax
    CHECK_RAX
    mov     r8, [rbp + 0x38]            ;Third input argument for demoted routine
    dec     rax
    CHECK_RAX
    mov     r9, [rbp + 0x40]            ;Forth input argument for demoted routine
    dec     rax
    CHECK_RAX
    ;For further input arguments, they will be put on the stack
    xor     rbx, rbx                    ;rbx=0
    mov     r14, rax
    shl     r14, 3                      ;r14=8*rax
    sub     r15, r14                    ;r15-=r14, offset the stack for remainder of input arguments
    sub     r15, 0x20                   ;r15-=0x20, 4 stack parameters
    and     r15, -16                    ;finally we worry about the stack alignment in CPL3
.3:
    mov     r14, [rbp + 0x48 + rbx]     ;r14=*(rbp+0x48+rbx)
    mov     [r15 + 0x20 + rbx], r14     ;*(r15+0x20+rbx)=r14
    add     rbx, 0x08                   ;rbx+=0x08
    dec     rax
    CHECK_RAX
    jmp     .3

.4:
    ;Demote to CPL3 by far return, it will take care of cs and ss
    ;Note: we did more pushes on the way, so need to compensate the calculation when grabbing earlier pushed values
    sub     r15, 0x08                   ;dummy r15 displacement, to mimic the return pointer on the stack
    push    LONG_DS_R3                  ;prepare ss on the stack
    mov     rax, r15                    ;grab Cpl3StackPtr from r15
    push    rax                         ;prepare CPL3 stack pointer on the stack
    push    LONG_CS_R3                  ;prepare cs on the stack
    mov     rax, [rbp + 0x18]           ;grab routine pointer from stack
    push    rax                         ;prepare routine pointer on the stack

    mov     r15, CALL_GATE_OFFSET       ;This is our way to come back, do not mess it up
    shl     r15, 32                     ;Call gate on call far stack should be CS:rIP
    retfq

    ;2000 years later...

.5:
    ;First offset the return far related 4 pushes (we have 0 count of arguments):
    ;PUSH.v old_SS // #SS on this or next pushes use SS.sel as error code
    ;PUSH.v old_RSP
    ;PUSH.v old_CS
    ;PUSH.v next_RIP
    add     rsp, 0x20

    ;Demoted routine is responsible for returning to this point by invoking call gate
    ;rbp should be at the top of this stack we set up in the TS
    mov     rbp, [rsp]

    ;Populate the rcx for usage below
    mov     rcx, [rbp + 0x10]

    ;Return status should still be in rax, save it before calling other functions
    push    rax
    sub     rsp, 0x28
    call    RestoreCpl0MsrStar
    add     rsp, 0x28
    pop     rax

    xor     rcx, rcx
    mov     cx, LONG_DS_R0
    mov     ds, cx
    mov     es, cx
    mov     fs, cx
    mov     gs, cx

    add     rsp, 0x08       ;Unwind the rbp from the last net-push
    ;Unwind the rest of the pushes
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    mov     rsp, rbp
    pop     rbp

    ret
