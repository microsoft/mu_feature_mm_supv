;------------------------------------------------------------------------------ ;
; Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
; Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
; Copyright (C) Microsoft Corporation.
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

;------------------------------------------------------------------------------
; UINT64
; EFIAPI <- This will guarantee __cdecl call convention for both GNUC & MSVC
; SysCall (
;   UINTN CallIndex,
;   UINTN Arg1,
;   UINTN Arg2,
;   UINTN Arg3
;   );
;------------------------------------------------------------------------------
global ASM_PFX(SysCall)
ASM_PFX(SysCall):
; CallIndex in RCX, Arg1 in RDX, Arg2 in R8, Arg3 in R9
; push CallIndex to the stack then invoke syscall

    push    r11
; x64 calling convention Integer First 4 parameters - RCX, RDX, R8, R9. Others passed on stack.
; syscall will put the command below to rcx, rFLAGs to r11
; Use RAX, RDX, R8, R9 to pass parameters
; All registers will be reserved
    mov     rax, rcx
    syscall
    pop     r11
    ret
