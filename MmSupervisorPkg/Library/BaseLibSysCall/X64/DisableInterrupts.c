/** @file
  CpuBreakpoint function.

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
  Disable CPU interrupts.

**/
VOID
EFIAPI
DisableInterrupts (
  VOID
  )
{
  SysCall (SMM_SC_CLI, 0, 0, 0);
}
