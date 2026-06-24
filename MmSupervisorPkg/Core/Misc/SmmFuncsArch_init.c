/** @file
  Init (MmSupervisorInit) stub for shadow-stack initialization.

  Linked only into MmSupervisorInit.  CET shadow-stack support is unsupported
  in the Init phase: the Init build does not link the NASM patch labels that
  the runtime supervisor uses, and Init never enters CFE-protected SMM.  So
  this stub PANICs if a caller ever reaches it with CET enabled, leaving the
  three mCet* globals (defined in shared SmmFuncsArch.c) at their zero-init
  values.  See SmmFuncsArch_core.c for the runtime implementation.

  Copyright (c) 2015 - 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/DebugLib.h>
#include <Library/PanicLib.h>

extern BOOLEAN  mCetSupported;

/**
  Initialize the shadow stack related data structure.

  @param CpuIndex     The index of CPU.
  @param ShadowStack  The bottom of the shadow stack for this CPU.
**/
VOID
InitShadowStack (
  IN UINTN  CpuIndex,
  IN VOID   *ShadowStack
  )
{
  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    PANIC ("Shadow Stack is not supported in SMM currently!!!\n");
  }
}
