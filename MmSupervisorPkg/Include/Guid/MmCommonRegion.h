/** @file
  HOB data structure definition for allocated MM communication buffers.
  This HOBs will be consumed by MM core during MM foundation setup process.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __MM_COMM_REGION_HOB_H__
#define __MM_COMM_REGION_HOB_H__

#define MM_COMM_REGION_HOB_GUID \
  { 0xd4ffc718, 0xfb82, 0x4274, { 0x9a, 0xfc, 0xaa, 0x8b, 0x1e, 0xef, 0x52, 0x93 } }

#define MM_SUPERVISOR_BUFFER_T  0
#define MM_USER_BUFFER_T        1

#define MM_OPEN_BUFFER_CNT  2           // The number of all supported buffer types listed above

typedef struct {
  UINT64                  MmCommonRegionType;     // Should be either MM_SUPERVISOR_BUFFER_T or MM_USER_BUFFER_T
  EFI_PHYSICAL_ADDRESS    MmCommonRegionAddr;
  UINT64                  MmCommonRegionPages;
} MM_COMM_REGION_HOB;

extern EFI_GUID  gMmCommonRegionHobGuid;

#endif
