/** @file
  The internal header file includes routines supporting MM Supervisor requests.

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPV_PASS_DOWN_H_
#define MM_SUPV_PASS_DOWN_H_

#define MM_SUPV_PASS_DOWN_HOB_REVISION  1

#define MM_SUPV_PASS_DOWN_HOB_GUID \
  { 0x3f2d2d1a, 0x7c6a, 0x4e2e, { 0x91, 0x2e, 0x5c, 0x4f, 0x5b, 0x8c, 0x2a, 0x9d } }

#pragma pack (1)
//
typedef struct {
  UINT32                    Revision;
  UINT32                    Reserved;
  EFI_PHYSICAL_ADDRESS      MmSupervisorCpl3StackBase;
  UINT64                    MmSupervisorCpl3PerCoreStackSize;
  EFI_PHYSICAL_ADDRESS      MmSupvCpuPrivate;
  UINT64                    MmSupvCpuPrivateSize;
  EFI_PHYSICAL_ADDRESS      MmInitializedBuffer;
  EFI_PHYSICAL_ADDRESS      MmSupvFirmwarePolicyBuffer;
  UINT64                    MmSupvFirmwarePolicyBufferSize;
  UINT64                    MmiEntrypointSize;
  UINT64                    BspMmBaseAddress;
} MM_SUPV_PASS_DOWN_HOB_DATA;

#pragma pack ()

extern EFI_GUID  gMmSupervisorPassDownHobGuid;

#endif // MM_SUPV_PASS_DOWN_H_
