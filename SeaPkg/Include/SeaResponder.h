/** @file -- SmmSupervisor.h
Defines necessary structures and constants for SMM supervisor usage.

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SEA_RESPONDER_H_
#define SEA_RESPONDER_H_

// FixupOffsets
#define SMM_ADDR_OFFSET  0
#define GDT_DSEC_OFFSET  1
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

#define FIXUP8_gPatchXdSupported                 0
#define FIXUP8_gPatchMsrIa32MiscEnableSupported  1
#define FIXUP8_m5LevelPagingNeeded               2
#define FIXUP8_mPatchCetSupported                3
#define FIXUP8_OFFSET4_RSVD                      4
#define FIXUP8_OFFSET5_RSVD                      5
#define FIXUP8_OFFSET6_RSVD                      6
#define FIXUP8_OFFSET7_RSVD

#define MMI_ENTRY_STRUCT_VERSION  4

#define SEA_SPEC_VERSION_MAJOR  1
#define SEA_SPEC_VERSION_MINOR  0

#pragma pack(push,1)

typedef struct {
  UINT64    VerifyMmiEntry : 1;    /// > bitfield
  UINT64    VerifyMmSupv   : 1;    /// > bitfield
  UINT64    VerifyMmPolicy : 1;    /// > bitfield
  UINT64    HashAlg        : 3;    /// > bitfield
  UINT64    Reserved       : 58;   /// > must be 0
} SEA_CAPS;

typedef struct {
  UINT16      SeaSpecVerMinor;
  UINT16      SeaSpecVerMajor;
  ///
  /// Must be zero
  ///
  UINT32      Reserved;
  UINT32      SeaHeaderSize;
  UINT32      SeaTotalSize;
  SEA_CAPS    SeaFeatures;
} SEA_CAPABILITIES_STRUCT;

typedef struct {
  UINT32    HeaderVersion;     // 4 For Version 4 Header
  UINT8     FixUpStructOffset; // Offset to FixUpStruct Arrary
  UINT8     FixUpStructNum;    // number of FixUpStruct Arrary member
  UINT8     FixUp64Offset;     // Offset to FixUp64 Arrary
  UINT8     FixUp64Num;        // Number of FixUp64 Arrary member
  UINT8     FixUp32Offset;     // Offset to FixUp32 Arrary
  UINT8     FixUp32Num;        // Number of FixUp32 Arrary member
  UINT8     FixUp8Offset;      // Offset to FixUp32 Arrary
  UINT8     FixUp8Num;         // Number of FixUp32 Arrary member
  UINT16    BinaryVersion;     // SmiEntry Binary Version
  UINT32    SplValue;          // SPL value for SmiEntry Binary
  UINT32    Reserved;          // Reserved for future use
} PER_CORE_MMI_ENTRY_STRUCT_HDR;

#pragma pack(pop)

// Key Symbols for MmSupervisorCore
#define KEY_SYMBOL_FW_POLICY_SIGNATURE  SIGNATURE_32 ('F', 'P', 'O', 'L')
#define KEY_SYMBOL_PAGE_TBL_SIGNATURE   SIGNATURE_32 ('P', 'G', 'T', 'B')
#define KEY_SYMBOL_MMI_RDV_SIGNATURE    SIGNATURE_32 ('M', 'R', 'D', 'V')

#define MMI_ENTRY_DIGEST_INDEX  0
#define MM_SUPV_DIGEST_INDEX    1
#define SUPPORTED_DIGEST_COUNT  2

#define SEA_API_GET_CAPABILITIES  (BIT16 | BIT8 | 1)
#define SEA_API_GET_RESOURCES     (BIT16 | BIT8 | 2)

#endif // SEA_RESPONDER_H_
