/** @file -- SmmSupervisor.h
Defines necessary structures and constants for SMM supervisor usage.

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (C) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SPAM_RESPONDER_H_
#define SPAM_RESPONDER_H_

//FixupOffsets
#define SMM_ADDR_OFFSET           0
#define GDT_DSEC_OFFSET           1
//
#define FIXUP64_SMM_DBG_ENTRY     0
#define FIXUP64_SMM_DBG_EXIT      1
#define FIXUP64_SMI_RDZ_ENTRY     2
#define FIXUP64_XD_SUPPORTED      3
#define FIXUP64_CET_SUPPORTED     4
#define FIXUP64_SMI_HANDLER_IDTR  5
#define FIXUP64_OFFSET6_RSVD      6

#define FIXUP32_mPatchCetPl0Ssp             0
#define FIXUP32_GDTR                        1
#define FIXUP32_CR3_OFFSET                  2
#define FIXUP32_mPatchCetInterruptSsp       3
#define FIXUP32_mPatchCetInterruptSspTable  4
#define FIXUP32_STACK_OFFSET_CPL0           5
#define FIXUP32_MSR_SMM_BASE                6

#define FIXUP8_gPatchXdSupported                0
#define FIXUP8_gPatchMsrIa32MiscEnableSupported 1
#define FIXUP8_gPatch5LevelPagingNeeded         2
#define FIXUP8_mPatchCetSupported               3
#define FIXUP8_OFFSET4_RSVD                     4
#define FIXUP8_OFFSET5_RSVD                     5
#define FIXUP8_OFFSET6_RSVD                     6
#define FIXUP8_OFFSET7_RSVD                     

#pragma pack(push,1)

typedef struct {
  UINT32  HeaderVersion;     //4 For Version 4 Header
  UINT8   FixUpStructOffset; // Offset to FixUpStruct Arrary
  UINT8   FixUpStructNum;    // number of FixUpStruct Arrary member
  UINT8   FixUp64Offset;     // Offset to FixUp64 Arrary
  UINT8   FixUp64Num;        // Number of FixUp64 Arrary member
  UINT8   FixUp32Offset;     // Offset to FixUp32 Arrary
  UINT8   FixUp32Num;        // Number of FixUp32 Arrary member
  UINT8   FixUp8Offset;      // Offset to FixUp32 Arrary
  UINT8   FixUp8Num;         // Number of FixUp32 Arrary member
  UINT16  BinaryVersion;     // SmiEntry Binary Version
  UINT32  SplValue;          // SPL value for SmiEntry Binary
  UINT32  Reserved;          // Reserved for future use
} PER_CORE_MMI_ENTRY_STRUCT_HDR;

#pragma pack(pop)

#define SPAM_RESPONDER_STRUCT_SIGNATURE  SIGNATURE_32 ('S', 'P', 'A', 'M')  
#define SPAM_REPSONDER_STRUCT_MAJOR_VER  0x0000
#define SPAM_REPSONDER_STRUCT_MINOR_VER  0x0001

#pragma pack(push,1)

typedef struct {
  UINT32                Signature;           // SPAM
  UINT16                VersionMinor;        // 0x0001
  UINT16                VersionMajor;        // 0x0000
  UINT32                Size;
  UINT32                Reserved;
  UINT64                CpuIndex;
  EFI_PHYSICAL_ADDRESS  MmEntryBase;
  UINT64                MmEntrySize;
  EFI_PHYSICAL_ADDRESS  MmSupervisorBase;
  UINT64                MmSupervisorSize;
  EFI_PHYSICAL_ADDRESS  MmSecurePolicyBase;
  UINT64                MmSecurePolicySize;
  UINT32                UserModuleOffset;
  UINT32                UserModuleCount;
  // USER_MODULE_INFO      UserModules[];
} SPAM_RESPONDER_DATA;

typedef struct {
  EFI_PHYSICAL_ADDRESS  UserModuleBase;
  UINT64                UserModuleSize;
} USER_MODULE_INFO;

#pragma pack(pop)

#endif // SPAM_RESPONDER_H_
