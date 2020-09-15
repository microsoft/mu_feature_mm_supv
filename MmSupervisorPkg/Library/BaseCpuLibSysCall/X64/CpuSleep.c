/** @file
  Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
  Copyright (C), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  Module Name:

    CpuSleep.c

  Abstract:

    CpuSleep function

  Notes:

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/SysCallLib.h>

/**
  Executes a WBINVD instruction.

  Executes a WBINVD instruction. This function is only available on IA-32 and
  x64.

**/
VOID
EFIAPI
CpuSleep (
  VOID
  )
{
  SysCall (SMM_SC_HLT, 0, 0, 0);
}
