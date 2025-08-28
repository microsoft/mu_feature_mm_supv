/** @file

  A null library instance that performs no actions.

  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/MmSupervisorCoreInitLib.h>

/**
  Perform any custom initialization needed by the MM Supervisor Core.

  This function is called at the beginning of the MM Supervisor Core entry point,
  before any other MM Supervisor Core initialization is performed.

  This function allows any critical initialization specific to a given platform to be
  hooked at the beginning of the MM Supervisor Core initialization. This function must
  only contain code that is completely independent of any other MM Core initialization
  or services outside of the function implementation itself.

**/
VOID
EFIAPI
MmSupervisorCoreEntryInit (
  VOID
  )
{
  return;
}
