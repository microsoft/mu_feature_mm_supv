/** @file
  Phase-specific helpers for FwVol.c.

  FwVol.c is shared between MmSupervisorCore (runtime) and MmSupervisorInit
  (foundation init).  A small number of operations have to behave differently
  in each phase; those operations are declared here and implemented in
  FwVol_core.c (runtime) and FwVol_init.c (init) respectively.

  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef FW_VOL_H_
#define FW_VOL_H_

#include <Uefi/UefiBaseType.h>

/**
  Copy a FFS file from a source buffer into a buffer that has been allocated
  inside MMRAM for use by the MM driver dispatcher.

  In the runtime MmSupervisorCore phase, this must go through
  MmCopyMemToMmram() so the source buffer is validated to live outside MMRAM.

  In the MmSupervisorInit phase, the source buffer is already inside MMRAM and
  MmCopyMemToMmram() would (correctly) reject it as a security violation, so
  a plain CopyMem() is used instead.

  @param[in]  Destination  Destination buffer (always inside MMRAM).
  @param[in]  Source       Source buffer.
  @param[in]  Length       Number of bytes to copy.

  @retval EFI_SUCCESS            The copy completed successfully.
  @retval EFI_SECURITY_VIOLATION (Runtime only) The source overlaps MMRAM.
**/
EFI_STATUS
EFIAPI
FwVolCopyToInternalBuffer (
  OUT VOID   *Destination,
  IN  VOID   *Source,
  IN  UINTN  Length
  );

#endif // FW_VOL_H_
