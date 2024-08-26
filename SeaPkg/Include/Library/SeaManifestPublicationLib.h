/** @file
  Library instance to publish the SMM Enhanced Attestation (SEA) Manifest.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SEA_MANIFEST_PUBLICATION_LIB_H_
#define SEA_MANIFEST_PUBLICATION_LIB_H_

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
  );

#endif // SEA_MANIFEST_PUBLICATION_LIB_H_
