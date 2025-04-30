/**
  This is a NULL instance that returns 0 for all functions.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

*/

#include <Uefi.h>
#include <Library/PlatformCpuInformationLib.h>

/**
  Return the Platform CPU core count.  This is the NULL implementation which will
  always return 0.

  @retval The number of CPU cores on the system

**/
UINTN
EFIAPI
GetPlatformCoreCount (
  VOID
  )
{
  return 0;
}
