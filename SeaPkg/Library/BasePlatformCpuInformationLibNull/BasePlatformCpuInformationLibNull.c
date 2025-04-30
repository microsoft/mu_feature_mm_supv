/**
  This is a NULL instance that returns 0 for all functions.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

*/

#include <Uefi.h>
#include <Library/PlatformCpuInformationLib.h>

/**
  Publish the SEA Manifest so it can be located by an operating system.

  @retval The number of CPU cores on the system

**/
UINTN
EFIAPI
GetPlatormCoreCount (
  VOID
  )
{
  return 0;
}
