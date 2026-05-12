/** @file
  Init (MmSupervisorInit) implementation of FwVol phase-specific helpers.

  See FwVol.h for the contract.  During foundation init the FFS source already
  resides inside MMRAM and MmCopyMemToMmram() would reject it as a security
  violation, so a plain CopyMem() is used.

  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseMemoryLib.h>

#include "FwVol.h"

EFI_STATUS
EFIAPI
FwVolCopyToInternalBuffer (
  OUT VOID   *Destination,
  IN  VOID   *Source,
  IN  UINTN  Length
  )
{
  CopyMem (Destination, Source, Length);
  return EFI_SUCCESS;
}
