;------------------------------------------------------------------------------
;
; Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   EnableInterrupts.Asm
;
; Abstract:
;
;   EnableInterrupts function
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

; MS_CHANGE - START
; Note: EnableInterrupts and EnableInterruptsAndSleep functions are now implemented
; in EnableInterrupts.c using syscalls (SMM_SC_STI and SMM_SC_HLT) to properly
; handle privilege separation in the MM Supervisor environment.
; The direct 'sti' and 'hlt' instructions have been replaced with syscall-based
; implementations to ensure proper security policy enforcement.
; MS_CHANGE - END