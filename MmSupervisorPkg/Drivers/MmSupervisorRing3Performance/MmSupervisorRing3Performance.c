/** @file
  Driver to initialize and provide user mode performance data in an MM Supervisor environment.

  This driver is expected to be linked against a PerformanceLib instance that implements the
  code typically in a MM Core for user mode performance data. This includes installing the
  performance protocol and registering a MMI to return performance data to the MMI caller.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Pi/PiMmCis.h>

#include <Library/DebugLib.h>

/**
  The MM Supervisor Ring 3 Performance Entry Point.

  @param[in]  ImageHandle    The firmware allocated handle for the EFI image.
  @param[in]  SystemTable    A pointer to the MM System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.

**/
EFI_STATUS
EFIAPI
MmSupervisorRing3PerformanceEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  return EFI_SUCCESS;
}
