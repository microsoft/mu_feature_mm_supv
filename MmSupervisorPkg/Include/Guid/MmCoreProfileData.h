/** @file
  MM Core data.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2018, ARM Limited. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __MM_CORE_PROFILE_DATA_H__
#define __MM_CORE_PROFILE_DATA_H__

#define MM_CORE_MM_PROFILE_DATA_GUID \
  { 0xf34014c5, 0xbcec, 0x4f36, { 0xad, 0xa7, 0x49, 0xff, 0xf5, 0xdd, 0x17, 0x9f }}

extern EFI_GUID  gMmCoreMmProfileGuid;

typedef struct {
  //
  // Address pointer to MM_CORE_PRIVATE_DATA
  //
  EFI_PHYSICAL_ADDRESS    Address;
  UINT32                  Size;
} MM_CORE_MM_PROFILE_DATA;

#endif
