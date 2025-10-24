/** @file

  Copyright (c) 2020-2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Register/Intel/Cpuid.h>

/**
  Probe if TD is enabled.

  @return TRUE    TD is enabled.
  @return FALSE   TD is not enabled.
**/
BOOLEAN
EFIAPI
TdIsEnabled (
  )
{
  // We should not even invoke this function for supervised environment.
  ASSERT (FALSE);
  return FALSE;
}
