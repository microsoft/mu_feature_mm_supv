/** @file
  EnableInterrupts function.

  Copyright (c) 2006 - 2010, Intel Corporation. All rights reserved.<BR>
  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/**
  Microsoft Visual Studio 7.1 Function Prototypes for I/O Intrinsics.
**/

#include    <Uefi.h>
#include    <Library/BaseLib.h>
#include    <Library/SysCallLib.h>

/**
  Enable CPU interrupts.

**/
VOID
EFIAPI
EnableInterrupts (
  VOID
  )
{
  SysCall (SMM_SC_STI, 0, 0, 0);
}

/**
  Enable CPU interrupts and enter sleep state.

**/
VOID
EFIAPI
EnableInterruptsAndSleep (
  VOID
  )
{
  SysCall (SMM_SC_STI, 0, 0, 0);
  SysCall (SMM_SC_HLT, 0, 0, 0);
}
