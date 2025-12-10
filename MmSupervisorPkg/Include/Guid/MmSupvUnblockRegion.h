/** @file
  Hob data structure definition for regions that needs to be unblocked by MM supervisor
  core from its entry point.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPV_UNBLOCK_REGION_HOB_H_
#define MM_SUPV_UNBLOCK_REGION_HOB_H_

#define MM_SUPV_UNBLOCK_REGION_HOB_GUID \
  { 0x3def51c5, 0x228f, 0x481d, { 0x82, 0x1b, 0x32, 0xec, 0x4d, 0xf7, 0xd9, 0xc7 } }

extern EFI_GUID  gMmSupvUnblockRegionHobGuid;

#endif // MM_SUPV_UNBLOCK_REGION_HOB_H_
