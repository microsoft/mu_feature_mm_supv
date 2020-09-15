/** @file
  Hob data structure definition for regions that needs to be unblocked by MM core
  from its entry point.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_UNBLOCK_REGION_HOB_H__
#define MM_UNBLOCK_REGION_HOB_H__

#define MM_UNBLOCK_REGION_HOB_GUID \
  { 0xcf0bd54a, 0x38fe, 0x4f85, { 0xb4, 0xfd, 0x94, 0xd2, 0xc7, 0xe3, 0xf0, 0x13 } }

extern EFI_GUID  gMmUnblockRegionHobGuid;

#endif // MM_UNBLOCK_REGION_HOB_H__
