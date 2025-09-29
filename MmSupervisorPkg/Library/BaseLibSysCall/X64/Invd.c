/** @file
  AsmInvd function.

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
  Executes an INVD instruction.

  Executes an INVD instruction. This function is only available on IA-32 and
  x64.

**/
VOID
EFIAPI
AsmInvd (
  VOID
  )
{
  SysCall (SMM_SC_INVD, 0, 0, 0);
}