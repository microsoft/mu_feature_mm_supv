;------------------------------------------------------------------------------ ;
; Copyright (c) 2016 - 2018, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   SmiException.nasm
;
; Abstract:
;
;   Exception handlers used in SM mode
;
;-------------------------------------------------------------------------------

extern  ASM_PFX(SmiPFHandler)

global  ASM_PFX(gcSmiIdtr)
global  ASM_PFX(gcSmiGdtr)
global  ASM_PFX(gcPsd)

    SECTION .rdata

NullSeg: DQ 0                   ; reserved by architecture
CodeSeg32:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x9b
            DB      0xcf                ; LimitHigh
            DB      0                   ; BaseHigh
ProtModeCodeSeg32:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x9b
            DB      0xcf                ; LimitHigh
            DB      0                   ; BaseHigh
ProtModeSsSeg32:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x93
            DB      0xcf                ; LimitHigh
            DB      0                   ; BaseHigh
DataSeg32:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x93
            DB      0xcf                ; LimitHigh
            DB      0                   ; BaseHigh
CodeSeg16:
            DW      -1
            DW      0
            DB      0
            DB      0x9b
            DB      0x8f
            DB      0
DataSeg16:
            DW      -1
            DW      0
            DB      0
            DB      0x93
            DB      0x8f
            DB      0
CodeSeg64R0:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x9b
            DB      0xaf                ; LimitHigh
            DB      0                   ; BaseHigh
DataSeg64R0:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x93
            DB      0xcf                ; LimitHigh
            DB      0                   ; BaseHigh
CodeSeg64ComR3:                         ; Placeholder, not used
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x7b                ; Not present
            DB      0xaf                ; LimitHigh
            DB      0                   ; BaseHigh
DataSeg64R3:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0xf3
            DB      0xcf                ; LimitHigh
            DB      0                   ; BaseHigh
CodeSeg64R3:
            DW      -1                  ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0xfb                ; P = 1, DPL = 3
            DB      0xaf                ; LimitHigh
            DB      0                   ; BaseHigh
CallGate64:
            DW      0                   ; OffsetLow
            DW      0x38                ; Selector, CodeSeg64R0
            DB      0                   ; Reserved
            DB      0xec                ; P = 1, DPL = 3, Long mode type
            DW      0                   ; OffsetMid
            DD      0                   ; OffsetHigh
            DD      0                   ; Reserved
; TSS Segment for X64 specially
TssSeg:
            DW      TSS_DESC_SIZE       ; LimitLow
            DW      0                   ; BaseLow
            DB      0                   ; BaseMid
            DB      0x89
            DB      0x80                ; LimitHigh
            DB      0                   ; BaseHigh
            DD      0                   ; BaseUpper
            DD      0                   ; Reserved
GDT_SIZE equ $ -   NullSeg

ASM_PFX(gcSmiGdtr):
    DW      GDT_SIZE - 1
    DQ        NullSeg

;
; CODE & DATA segments for SMM runtime
;
CODE_SEL    equ   CodeSeg64R0 -   NullSeg
DATA_SEL    equ   DataSeg64R0 -   NullSeg
CODE32_SEL  equ   CodeSeg32 -   NullSeg

; Create TSS Descriptor just after GDT
TssDescriptor:
            DD      0                   ; Reserved
            DQ      0                   ; RSP0
            DQ      0                   ; RSP1
            DQ      0                   ; RSP2
            DD      0                   ; Reserved
            DD      0                   ; Reserved
            DQ      0                   ; IST1
            DQ      0                   ; IST2
            DQ      0                   ; IST3
            DQ      0                   ; IST4
            DQ      0                   ; IST5
            DQ      0                   ; IST6
            DQ      0                   ; IST7
            DD      0                   ; Reserved
            DD      0                   ; Reserved
            DW      0                   ; Reserved
            DW      0                   ; I/O Map Base Address
TSS_DESC_SIZE equ $ -   TssDescriptor

;
; This structure serves as a template for all processors.
;
ASM_PFX(gcPsd):
            DB      'PSDSIG  '
            DW      PSD_SIZE
            DW      2
            DW      1 << 2
            DW      CODE_SEL
            DW      DATA_SEL
            DW      DATA_SEL
            DW      DATA_SEL
            DW      0
            DQ      0
            DQ      0
            DQ      0                   ; fixed in InitializeMpServiceData()
            DQ        NullSeg
            DD      GDT_SIZE
            DD      0
            times   24 DB 0
            DQ      0
PSD_SIZE  equ $ -   ASM_PFX(gcPsd)

    SECTION .data

ASM_PFX(gcSmiIdtr):
    DW      0
    DQ      0
