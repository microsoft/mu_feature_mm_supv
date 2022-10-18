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

extern ASM_PFX(RegisteredRing3JumpPointer)
extern ASM_PFX(RegApRing3JumpPointer)
extern ASM_PFX(RegErrorReportJumpPointer)

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; InvokeDemotedDriverEntryPoint (
;   IN MM_IMAGE_ENTRY_POINT     *EntryPoint,
;   IN EFI_HANDLE               ImageHandle,
;   IN EFI_MM_SYSTEM_TABLE      *MmSystemTable
;   );
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(InvokeDemotedDriverEntryPoint)
ASM_PFX(InvokeDemotedDriverEntryPoint):
    ;Preserve all input parameters onto stack
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r15

    ;Place holder on stack
    sub     rsp, 0x20

    call    GetBspCpl3Stack
    mov     r15, rax

    call    SetupBspCpl0MsrStar

    ;Double-check call gate for return, failed to match call gate will cause GP#
    lea     rcx, [EntryReturnPointer]
    mov     rdx, 1
    call    SetupCallGate

    ;Double-check SetupTssDescriptor for return, failed to match Tss will cause GP#
    mov     rcx, rsp
    mov     rdx, 1
    call    SetupTssDescriptor

    ;Same level far return to apply GDT change
    xor     rcx, rcx
    mov     rcx, cs
    push    rcx                 ;prepare cs on the stack
    lea     rax, [.0]
    push    rax                 ;prepare return rip on the stack
    retfq

.0:
    ;Prepare for ds, es, fs, gs
    xor     rax, rax
    mov     ax, LONG_DS_R3
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ;Prepare input arguments
    mov     rcx, [rsp + 0x20 + 0x18]    ;ImageHandle from input argument
    mov     rdx, [rsp + 0x20 + 0x10]    ;MmSystemTable from input argument

    ;Demote to CPL3 by far return, it will take care of cs and ss
    ;Note: we did more pushes on the way, so need to compensate the calculation when grabbing earlier pushed values
    push    LONG_DS_R3                  ;prepare ss on the stack
    mov     rax, r15                    ;grab Cpl3StackPtr from r15
    push    rax                         ;prepare CPL3 stack pointer on the stack
    push    LONG_CS_R3                  ;prepare cs on the stack
    mov     rax, [rsp + 0x20 + 0x38]    ;grab EntryPoint from stack
    push    rax                         ;prepare EntryPoint on the stack

    mov     r15, CALL_GATE_OFFSET       ;This is our way to come back, do not mess it up
    shl     r15, 32                     ;Call gate on call far stack should be CS:rIP
    retfq

    ;2000 years later...

EntryReturnPointer:
    ;Driver entry point is responsible for returning to this point by invoking call gate

    ;First offset the return far related 4 pushes
    ;PUSH.v old_SS // #SS on this or next pushes use SS.sel as error code
    ;PUSH.v old_RSP
    ;PUSH.v old_CS
    ;PUSH.v next_RIP
    add     rsp, 0x20

    ;Return status should still be in rax, save it before calling other functions
    push    rax
    call    RestoreBspCpl0MsrStar
    pop     rax

    ;Then offset the stack place holder for function entry
    add     rsp, 0x20

    xor     rcx, rcx
    mov     cx, LONG_DS_R0
    mov     ds, cx
    mov     es, cx
    mov     fs, cx
    mov     gs, cx

    pop     r15
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; InvokeDemotedMmHandler (
;   IN MMI_HANDLER *DispatchHandle,
;   IN CONST VOID  *Context         OPTIONAL,
;   IN OUT VOID    *CommBuffer      OPTIONAL,
;   IN OUT UINTN   *CommBufferSize  OPTIONAL
;   );
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(InvokeDemotedMmHandler)
ASM_PFX(InvokeDemotedMmHandler):
    ;Preserve all input parameters onto stack
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r15

    ;Place holder on stack
    sub     rsp, 0x30

    call    GetBspCpl3Stack
    mov     r15, rax

    call    SetupBspCpl0MsrStar

    ;Setup call gate for return
    lea     rcx, [MmHandlerReturnPointer]
    mov     rdx, 1
    call    SetupCallGate

    ;Setup SetupTssDescriptor for return
    mov     rcx, rsp
    mov     rdx, 1
    call    SetupTssDescriptor

    ;Same level far return to apply GDT change
    xor     rcx, rcx
    mov     rcx, cs
    push    rcx                 ;prepare cs on the stack
    lea     rax, [.0]
    push    rax                 ;prepare return rip on the stack
    retfq

.0:
    ;Prepare for ds, es, fs, gs
    xor     rax, rax
    mov     ax, LONG_DS_R3
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ;Prepare input arguments
    mov     rcx, [rsp + 0x30 + 0x20]    ;DispatchHandle from input argument
    mov     rdx, [rsp + 0x30 + 0x18]    ;Context from input argument
    mov     r8, [rsp + 0x30 + 0x10]     ;CommBuffer from input argument
    mov     r9, [rsp + 0x30 + 0x08]     ;CommBufferSize from input argument

    ;Demote to CPL3 by far return, it will take care of cs and ss
    ;Note: we did more pushes on the way, so need to compensate the calculation when grabbing earlier pushed values
    push    LONG_DS_R3                  ;prepare ss on the stack
    mov     rax, r15                    ;grab Cpl3StackPtr from r15
    sub     rax, 0x08                   ;mimic a push
    mov     r15, [rcx + 0x18]           ;TODO: This is DispatchHandle->Handler operation
    mov     [rax], r15                  ;store real handler to stack
    push    rax                         ;prepare CPL3 stack pointer on the stack
    push    LONG_CS_R3                  ;prepare cs on the stack
    mov     rax, strict qword 0         ;mov     rax, ASM_PFX(RegisteredRing3JumpPointer); from ring 3 shim driver
RegisteredRing3JumpPointerAddr:
    mov     rax, [rax]                  ;dereference the content of RegisteredRing3JumpPointer
    push    rax                         ;prepare EntryPoint on the stack

    mov     r15, CALL_GATE_OFFSET       ;This is our way to come back, do not mess it up
    shl     r15, 32                     ;Call gate on call far stack should be CS:rIP
    retfq

    ;2000 years later...

MmHandlerReturnPointer:
    ;Driver entry point is responsible for returning to this point by invoking call gate

    ;First offset the return far related 4 pushes
    ;PUSH.v old_SS // #SS on this or next pushes use SS.sel as error code
    ;PUSH.v old_RSP
    ;PUSH.v old_CS
    ;PUSH.v next_RIP
    add     rsp, 0x20

    ;Return status should still be in rax, save it before calling other functions
    push    rax
    call    RestoreBspCpl0MsrStar
    pop     rax

    ;Then offset the stack place holder for function entry
    add     rsp, 0x30

    xor     rcx, rcx
    mov     cx, LONG_DS_R0
    mov     ds, cx
    mov     es, cx
    mov     fs, cx
    mov     gs, cx

    pop     r15
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; InvokeDemotedApProcedure (
;   IN UINTN                    CpuIndex,
;   IN EFI_AP_PROCEDURE2        *Procedure,
;   IN VOID                     *ProcedureArgument
;   );
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(InvokeDemotedApProcedure)
global ASM_PFX(ApHandlerReturnPointer)

ASM_PFX(InvokeDemotedApProcedure):
    ;Preserve all input parameters onto stack
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r15

    ;Place holder on stack
    sub     rsp, 0x20

    push    rcx
    call    GetThisCpl3Stack
    mov     r15, rax
    pop     rcx

    ;rcx is CpuIndex, so no worries for this call
    call    SetupCpl0MsrStar

    ;Setup call gate for return
    lea     rcx, [ApHandlerReturnPointer]
    mov     rdx, 1
    call    SetupCallGate

    ;Setup SetupTssDescriptor for return
    mov     rcx, rsp
    mov     rdx, 1
    call    SetupTssDescriptor

    ;Same level far return to apply GDT change
    xor     rcx, rcx
    mov     rcx, cs
    push    rcx                 ;prepare cs on the stack
    lea     rax, [.0]
    push    rax                 ;prepare return rip on the stack
    retfq

.0:
    ;Prepare for ds, es, fs, gs
    xor     rax, rax
    mov     ax, LONG_DS_R3
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ;Prepare input arguments
    mov     rcx, [rsp + 0x20 + 0x18]    ;Procedure from input argument
    mov     rdx, [rsp + 0x20 + 0x10]    ;ProcedureArgument from input argument

    ;Demote to CPL3 by far return, it will take care of cs and ss
    ;Note: we did more pushes on the way, so need to compensate the calculation when grabbing earlier pushed values
    push    LONG_DS_R3                  ;prepare ss on the stack
    mov     rax, r15                    ;grab Cpl3StackPtr from r15
    push    rax                         ;prepare CPL3 stack pointer on the stack
    push    LONG_CS_R3                  ;prepare cs on the stack
    mov     rax, strict qword 0         ;mov     rax, ASM_PFX(RegApRing3JumpPointer); from ring 3 shim driver
RegApRing3JumpPointerAddr:
    mov     rax, [rax]                  ;dereference the content of RegApRing3JumpPointer
    push    rax                         ;prepare EntryPoint on the stack

    mov     r15, CALL_GATE_OFFSET       ;This is our way to come back, do not mess it up
    shl     r15, 32                     ;Call gate on call far stack should be CS:rIP
    retfq

    ;2000 years later...

ASM_PFX(ApHandlerReturnPointer):
    ;First offset the return far related 4 pushes (we have 0 count of arguments):
    ;PUSH.v old_SS // #SS on this or next pushes use SS.sel as error code
    ;PUSH.v old_RSP
    ;PUSH.v old_CS
    ;PUSH.v next_RIP
    add     rsp, 0x20

    ;Driver entry point is responsible for returning to this point by invoking call gate
    mov     rcx, [rsp + 0x20 + 0x20]

    ;Return status should still be in rax, save it before calling other functions
    push    rax
    call    RestoreCpl0MsrStar
    pop     rax

    ;Then offset the stack place holder for function entry
    add     rsp, 0x20

    xor     rcx, rcx
    mov     cx, LONG_DS_R0
    mov     ds, cx
    mov     es, cx
    mov     fs, cx
    mov     gs, cx

    pop     r15
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; InvokeDemotedErrorReport (
;   IN UINTN                    CpuIndex,
;   IN VOID                     *ErrorInfoBuffer
;   );
; Calling convention: Arg0 in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9, more on the stack
;------------------------------------------------------------------------------
global ASM_PFX(InvokeDemotedErrorReport)
ASM_PFX(InvokeDemotedErrorReport):
    ;Preserve all input parameters onto stack
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r15

    ;Place holder on stack
    sub     rsp, 0x30

    push    rcx
    call    GetThisCpl3Stack
    mov     r15, rax
    pop     rcx

    ;rcx is CpuIndex, so no worries for this call
    call    SetupCpl0MsrStar

    ;Setup call gate for return
    lea     rcx, [ErrorReportReturnPointer]
    mov     rdx, 1
    call    SetupCallGate

    ;Setup SetupTssDescriptor for return
    mov     rcx, rsp
    mov     rdx, 1
    call    SetupTssDescriptor

    ;Same level far return to apply GDT change
    xor     rcx, rcx
    mov     rcx, cs
    push    rcx                 ;prepare cs on the stack
    lea     rax, [.0]
    push    rax                 ;prepare return rip on the stack
    retfq

.0:
    ;Prepare for ds, es, fs, gs
    xor     rax, rax
    mov     ax, LONG_DS_R3
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ;Prepare input arguments
    mov     rcx, [rsp + 0x30 + 0x20]    ;CpuIndex from input argument
    mov     rdx, [rsp + 0x30 + 0x18]    ;ErrorInfoBuffer from input argument

    ;Demote to CPL3 by far return, it will take care of cs and ss
    ;Note: we did more pushes on the way, so need to compensate the calculation when grabbing earlier pushed values
    push    LONG_DS_R3                  ;prepare ss on the stack
    mov     rax, r15                    ;grab Cpl3StackPtr from r15
    push    rax                         ;prepare CPL3 stack pointer on the stack
    push    LONG_CS_R3                  ;prepare cs on the stack
    mov     rax, strict qword 0         ;mov     rax, ASM_PFX(RegErrorReportJumpPointer); from ring 3 shim driver
RegErrorReportJumpPointerAddr:
    mov     rax, [rax]                  ;dereference the content of RegErrorReportJumpPointer
    push    rax                         ;prepare EntryPoint on the stack

    mov     r15, CALL_GATE_OFFSET       ;This is our way to come back, do not mess it up
    shl     r15, 32                     ;Call gate on call far stack should be CS:rIP
    retfq

    ;2000 years later...

ErrorReportReturnPointer:
    ;First offset the return far related 4 pushes (we have 0 count of arguments):
    ;PUSH.v old_SS // #SS on this or next pushes use SS.sel as error code
    ;PUSH.v old_RSP
    ;PUSH.v old_CS
    ;PUSH.v next_RIP
    add     rsp, 0x20

    ;Error report function is responsible for returning to this point by invoking call gate
    mov     rcx, [rsp + 0x30 + 0x20]

    ;Return status should still be in rax, save it before calling other functions
    push    rax
    call    RestoreCpl0MsrStar
    pop     rax

    ;Then offset the stack place holder for function entry
    add     rsp, 0x30

    xor     rcx, rcx
    mov     cx, LONG_DS_R0
    mov     ds, cx
    mov     es, cx
    mov     fs, cx
    mov     gs, cx

    pop     r15
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret

global ASM_PFX(PrivilegeMgmtFixupAddress)
ASM_PFX(PrivilegeMgmtFixupAddress):
    lea    rax, [ASM_PFX(RegisteredRing3JumpPointer)]
    lea    rcx, [RegisteredRing3JumpPointerAddr]
    mov    qword [rcx - 8], rax

    lea    rax, [ASM_PFX(RegApRing3JumpPointer)]
    lea    rcx, [RegApRing3JumpPointerAddr]
    mov    qword [rcx - 8], rax

    lea    rax, [ASM_PFX(RegErrorReportJumpPointer)]
    lea    rcx, [RegErrorReportJumpPointerAddr]
    mov    qword [rcx - 8], rax

    ret

