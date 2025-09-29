;------------------------------------------------------------------------------
;
; Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   Invd.Asm
;
; Abstract:
;
;   AsmInvd function
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

; MS_CHANGE - START
; Note: AsmInvd function is now implemented in Invd.c using syscalls (SMM_SC_INVD)
; to properly handle privilege separation in the MM Supervisor environment.
; The direct 'invd' instruction has been replaced with syscall-based
; implementation to ensure proper security policy enforcement.
; MS_CHANGE - END

