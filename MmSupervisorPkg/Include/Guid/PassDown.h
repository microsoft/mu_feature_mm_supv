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
  // EFI_PHYSICAL_ADDRESS      MmSupervisorCoreStackBase;
  // UINT64                    MmSupervisorCoreStackSize;
  EFI_PHYSICAL_ADDRESS      MmSupervisorCpl3StackBase;
  UINT64                    MmSupervisorCpl3PerCoreStackSize;
  EFI_PHYSICAL_ADDRESS      MmSupvCpuPrivate;
  UINT64                    MmSupvCpuPrivateSize;
  EFI_PHYSICAL_ADDRESS      MmSupvMpSyncData;
  UINT64                    MmSupvMpSyncDataSize;
  EFI_PHYSICAL_ADDRESS      MmSupvCommBuffer;
  EFI_PHYSICAL_ADDRESS      MmSupvCommBufferInternal;
  UINT64                    MmSupvCommBufferSize;
  EFI_PHYSICAL_ADDRESS      MmUserCommBuffer;
  EFI_PHYSICAL_ADDRESS      MmUserCommBufferInternal;
  UINT64                    MmUserCommBufferSize;
  EFI_PHYSICAL_ADDRESS      MmSupvStatusBuffer;
  EFI_PHYSICAL_ADDRESS      MmSupvToUserBuffer;
  UINT64                    MmSupvToUserBufferSize;
  EFI_PHYSICAL_ADDRESS      MmSupvGdtBuffer;
  UINT64                    MmSupvGdtBufferSize;
  UINT64                    MmSupvGdtStepSize;
  EFI_PHYSICAL_ADDRESS      MmInitializedBuffer;
  EFI_PHYSICAL_ADDRESS      MmSupvFirmwarePolicyBuffer;
  UINT64                    MmSupvFirmwarePolicyBufferSize;
  EFI_PHYSICAL_ADDRESS      MmSupvMemoryPolicyBuffer;
  UINT64                    MmSupvMemoryPolicyBufferSize;
  UINT64                    BspMmBaseAddress;
  UINT64                    MmiEntrypointSize;
} MM_SUPV_PASS_DOWN_HOB_DATA;

#pragma pack ()

extern EFI_GUID  gMmSupervisorPassDownHobGuid;

#endif // MM_SUPV_PASS_DOWN_H_
