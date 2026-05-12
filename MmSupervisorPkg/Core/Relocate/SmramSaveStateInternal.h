/** @file
  Internal declarations shared between the SMRAM Save State Map services pair:
    * SmramSaveState_core.c -- Core build (MmSupervisorCore.inf)
    * SmramSaveState_init.c -- Init build (MmSupervisorInit.inf)

  PROCESSOR_SMM_DESCRIPTOR / CPU_SMM_SAVE_STATE_IO_WIDTH and the gcPsd
  declaration are private to this pair of source files (gcPsd itself is
  defined in SmiException.nasm).

  Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_SMRAM_SAVE_STATE_INTERNAL_H_
#define _MM_SUPV_SMRAM_SAVE_STATE_INTERNAL_H_

#include <Protocol/SmmCpu.h>

typedef struct {
  UINT64    Signature;                                      // Offset 0x00
  UINT16    Reserved1;                                      // Offset 0x08
  UINT16    Reserved2;                                      // Offset 0x0A
  UINT16    Reserved3;                                      // Offset 0x0C
  UINT16    SmmCs;                                          // Offset 0x0E
  UINT16    SmmDs;                                          // Offset 0x10
  UINT16    SmmSs;                                          // Offset 0x12
  UINT16    SmmOtherSegment;                                // Offset 0x14
  UINT16    Reserved4;                                      // Offset 0x16
  UINT64    Reserved5;                                      // Offset 0x18
  UINT64    Reserved6;                                      // Offset 0x20
  UINT64    Reserved7;                                      // Offset 0x28
  UINT64    SmmGdtPtr;                                      // Offset 0x30
  UINT32    SmmGdtSize;                                     // Offset 0x38
  UINT32    Reserved8;                                      // Offset 0x3C
  UINT64    Reserved9;                                      // Offset 0x40
  UINT64    Reserved10;                                     // Offset 0x48
  UINT16    Reserved11;                                     // Offset 0x50
  UINT16    Reserved12;                                     // Offset 0x52
  UINT32    Reserved13;                                     // Offset 0x54
  UINT64    Reserved14;                                     // Offset 0x58
} PROCESSOR_SMM_DESCRIPTOR;

extern CONST PROCESSOR_SMM_DESCRIPTOR  gcPsd;

///
/// Structure used to build a lookup table for the IOMisc width information
///
typedef struct {
  UINT8                          Width;
  EFI_SMM_SAVE_STATE_IO_WIDTH    IoWidth;
} CPU_SMM_SAVE_STATE_IO_WIDTH;

#endif // _MM_SUPV_SMRAM_SAVE_STATE_INTERNAL_H_
