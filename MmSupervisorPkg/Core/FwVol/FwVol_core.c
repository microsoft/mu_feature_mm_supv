/** @file
  Runtime (MmSupervisorCore) implementation of FwVol phase-specific helpers.

  See FwVol.h for the contract.  At runtime the FFS source is expected to
  reside outside MMRAM, so MmCopyMemToMmram() is used to enforce that and
  perform the copy.

  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/MemLib.h>

#include "FwVol.h"

EFI_STATUS
EFIAPI
FwVolCopyToInternalBuffer (
  OUT VOID   *Destination,
  IN  VOID   *Source,
  IN  UINTN  Length
  )
{
  return MmCopyMemToMmram (Destination, Source, Length);
}
