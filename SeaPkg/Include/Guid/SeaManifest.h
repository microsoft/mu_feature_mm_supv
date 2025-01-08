/** @file
  SMM Enhanced Attestation (SEA) Manifest Definitions.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SEA_MANIFEST_H_
#define SEA_MANIFEST_H_

#define SEA_RIM_FILE_GUID \
  { 0x442adad1, 0x5d9c, 0x46ea, { 0xb5, 0x38, 0xc7, 0xb1, 0x74, 0x0f, 0x83, 0x92 } }

#define SEA_MANIFEST_CONFIGURATION_TABLE_GUID \
  { 0x658f2b96, 0xc6d3, 0x4c5f, { 0xa9, 0x2b, 0x9a, 0xe1, 0x4a, 0x57, 0x3f, 0x1b } }

extern EFI_GUID  gSeaManifestConfigurationTableGuid;
extern EFI_GUID  gSeaRimFileGuid;

#endif
