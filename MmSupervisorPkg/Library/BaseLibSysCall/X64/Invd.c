/** @file
  CpuBreakpoint function.

  Copyright (c) 2006 - 2010, Intel Corporation. All rights reserved.<BR>
  Copyright (C), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include    <Uefi.h>
#include    <Library/BaseLib.h>

/**
  Executes a INVD instruction.

  Executes a INVD instruction. This function is only available on IA-32 and
  x64.

**/
VOID
EFIAPI
AsmInvd (
  VOID
  )
{
  // We should not even invoke this function for supervised environment.
  ASSERT (FALSE);
}
