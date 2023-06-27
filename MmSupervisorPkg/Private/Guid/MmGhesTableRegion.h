/** @file
  Hob data structure definition for regions that needs to be unblocked by MM core
  from its entry point.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_GHES_TABLE_REGION_GUID_H_
#define MM_GHES_TABLE_REGION_GUID_H_

#define MM_GHES_TABLE_REGION_GUID \
  { 0xb0fecab4, 0x9b8c, 0x4d71, { 0x89, 0x72, 0xf7, 0xc1, 0xa7, 0x4, 0x6a, 0x2e } }

extern EFI_GUID  gMmGhesTableRegionGuid;

typedef struct _MM_GHES_TABLE_REGION {
  EFI_MEMORY_DESCRIPTOR  MmGhesTableRegion;
  UINT64                 ReturnStatus;
} MM_GHES_TABLE_REGION;

#endif // MM_GHES_TABLE_REGION_GUID_H_
