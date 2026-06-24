/** @file
  The internal header file includes routines supporting MM Supervisor requests.

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPV_DEPEX_H_
#define MM_SUPV_DEPEX_H_

#define MM_SUPV_DEPEX_HOB_GUID \
  { 0xb17f0049, 0xaffd, 0x4530, { 0xac, 0xd6, 0xe2, 0x45, 0xe1, 0x9d, 0xea, 0xf1 } }

#pragma pack (1)
//
typedef struct {
  EFI_GUID                  Name;
  UINT64                    Length;
  UINT8                     Data[];
} MM_SUPV_DEPEX_HOB_DATA;

#pragma pack ()

extern EFI_GUID  gMmSupervisorDepexHobGuid;

#endif // MM_SUPV_DEPEX_H_
