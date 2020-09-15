/** @file
  Hob data structure definition for intended protected regions.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __MM_PROT_REGION_HOB_H__
#define __MM_PROT_REGION_HOB_H__

#define MM_PROT_REGION_HOB_GUID \
  { 0x6c0792ac, 0x13d7, 0x431b, { 0xa4, 0x89, 0x3, 0x2f, 0x4a, 0xf9, 0x73, 0x80 } }

extern EFI_GUID  gMmProtectedRegionHobGuid;

typedef enum {
  MM_PROT_MMIO_IOMMU_T,
  MM_PROT_MMIO_SEC_BIO_T,
  MM_PROT_REGION_TYPE_CNT        // Do NOT append after this entry
} MM_PROTECTED_REGION_TYPE;

typedef struct {
  UINT64                  MmProtectedRegionType;     // Should be one of the MM_PROTECTED_REGION_TYPE
  EFI_PHYSICAL_ADDRESS    MmProtectedRegionAddr;
  UINT64                  MmProtectedRegionPages;
} MM_PROT_REGION_HOB;

#endif
