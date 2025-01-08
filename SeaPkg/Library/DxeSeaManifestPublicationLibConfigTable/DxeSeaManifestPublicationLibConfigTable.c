/**
  Publishes the SEA Manifest to the system config table so an OS can locate it.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

*/

#include <Uefi.h>
#include <PiDxe.h>

#include <Library/DebugLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Guid/SeaManifest.h>

/**
  Publish the SEA Manifest so it can be located by an operating system.

  @param[in]      SeaManifest       A pointer to the SEA manifest to publish. If this pointer is NULL, the
                                    function wil attempt to locate the SEA manifest by GUID in currently installed
                                    firmware volumes.
  @param[in,out]  SeaManifestSize   A pointer to a buffer for the SEA manifest size. If SeaManifest is non-NULL, this
                                    pointer must be non-NULL with a non-zero size. If this pointer is otherwise
                                    non-NULL, it will contain the size of the SEA manifest that was published if the
                                    manifest was published successfully.

  @retval EFI_SUCCESS     The SEA manifest was published successfully.
  @retval EFI_NOT_FOUND   Failed to find the SEA manifest in an installed firmware volume.
  @retval Others          An error occurred in a function called during SEA manifest publication.

**/
EFI_STATUS
EFIAPI
PublishSeaManifest (
  IN  VOID   *SeaManifest        OPTIONAL,
  IN  UINTN  *SeaManifestSize    OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINTN       PublishedSeaManifestSize;

  if (SeaManifest == NULL) {
    Status = GetSectionFromAnyFv (
               &gSeaRimFileGuid,
               EFI_SECTION_RAW,
               0,
               &SeaManifest,
               &PublishedSeaManifestSize
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] - Failed to find the SEA manifest - %r\n", __func__, Status));
      return EFI_NOT_FOUND;
    }

    ASSERT (PublishedSeaManifestSize > 0);
  } else if ((SeaManifestSize == NULL) || (*SeaManifestSize == 0)) {
    return EFI_INVALID_PARAMETER;
  } else {
    PublishedSeaManifestSize = *SeaManifestSize;
  }

  DEBUG ((DEBUG_INFO, "[%a] - SEA manifest located of size 0x%lx.\n", __func__, (UINT64)PublishedSeaManifestSize));

  Status = gBS->InstallConfigurationTable (&gSeaManifestConfigurationTableGuid, SeaManifest);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - Failed to publish the SEA manifest - %r\n", __func__, Status));
    return Status;
  }

  if (SeaManifestSize != NULL) {
    *SeaManifestSize = PublishedSeaManifestSize;
  }

  DEBUG ((DEBUG_INFO, "[%a] - SEA manifest published to config table successfully.\n", __func__));

  return Status;
}
