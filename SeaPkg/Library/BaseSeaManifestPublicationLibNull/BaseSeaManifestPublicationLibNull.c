/**
  This is a NULL instance that simply returns instead of publishing the manifest.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

*/

#include <Uefi.h>

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
  return EFI_SUCCESS;
}
