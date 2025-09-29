/**
 * Copyright 2008 - 2020 ADVANCED MICRO DEVICES, INC.  All Rights Reserved.
 * Copyright (c) Microsoft Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 **/

#ifndef _SMM_SECURE_POLICY_H_
#define _SMM_SECURE_POLICY_H_

#define SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM          1
#define SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO           2
#define SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR          3
#define SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION  4
#define SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE   5

#define SECURE_POLICY_RESOURCE_ATTR_READ_DIS      BIT0
#define SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS     BIT1
#define SECURE_POLICY_RESOURCE_ATTR_EXECUTE_DIS   BIT2
#define SECURE_POLICY_RESOURCE_ATTR_STRICT_WIDTH  BIT3

#define SMM_SUPV_ACCESS_ATTR_ALLOW  0
#define SMM_SUPV_ACCESS_ATTR_DENY   1

// Starting from v1.0 of SMM supervisor policy, the attribute bits only define attribute type,
// whereas the access type is described by the AccessAttr from its policy root (see SMM_SUPV_POLICY_ROOT)
#define SECURE_POLICY_RESOURCE_ATTR_READ          BIT0
#define SECURE_POLICY_RESOURCE_ATTR_WRITE         BIT1
#define SECURE_POLICY_RESOURCE_ATTR_EXECUTE       BIT2
#define SECURE_POLICY_RESOURCE_ATTR_STRICT_WIDTH  BIT3
#define SECURE_POLICY_RESOURCE_ATTR_COND_READ     BIT4
#define SECURE_POLICY_RESOURCE_ATTR_COND_WRITE    BIT5

// Index of privileged instruction execution
typedef enum {
  SECURE_POLICY_INSTRUCTION_CLI    = 0,
  SECURE_POLICY_INSTRUCTION_WBINVD = 1,
  SECURE_POLICY_INSTRUCTION_HLT    = 2,
  SECURE_POLICY_INSTRUCTION_STI    = 3,
  SECURE_POLICY_INSTRUCTION_INVD   = 4,
  // Do not append after COUNT entry
  SECURE_POLICY_INSTRUCTION_COUNT = 5
} SECURE_POLICY_INSTRUCTION;

// Index of SMM save state access
typedef enum {
  SECURE_POLICY_SVST_RAX     = 0,
  SECURE_POLICY_SVST_IO_TRAP = 1,
  // Do not append after COUNT entry
  SECURE_POLICY_SVST_COUNT = 2
} SECURE_POLICY_SVST;

// Index of SMM save state access conditions
typedef enum {
  SECURE_POLICY_SVST_UNCONDITIONAL   = 0,
  SECURE_POLICY_SVST_CONDITION_IO_RD = 1,
  SECURE_POLICY_SVST_CONDITION_IO_WR = 2,
  // Do not append after COUNT entry
  SECURE_POLICY_SVST_CONDITION_COUNT = 3
} SECURE_POLICY_SVST_CONDITION;

#pragma pack (push, 1)
typedef struct  {
  UINT32    Version;        // The version of this descriptor. Current Version is 1.
  UINT32    Type;           // The Type of this Parameter.
  UINT32    DescriptorSize; // The size of the descriptor in bytes including the header.
} SMM_SUPV_SECURE_POLICY_DESCRIPTOR_V1;

// SMM Supervisor Secure policy memory descriptor
typedef struct {
  SMM_SUPV_SECURE_POLICY_DESCRIPTOR_V1    Header;        // SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM
  UINT64                                  BaseAddress;   // Base address of memory
  UINT64                                  Size;          // Size of memory
  UINT32                                  MemAttributes; // Attributes of memory
} SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR;

// SMM Supervisor Secure policy IO descriptor, define IO address SMM handler doesn't allow to access
// e.g. if disable the IO write access 0x3F8-0x3FC to SMM handler
// The struct need set to {Header, 0x3F8, 4, SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS}
typedef struct {
  SMM_SUPV_SECURE_POLICY_DESCRIPTOR_V1    Header;     // SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO
  UINT16                                  IoAddress;  // Base address of IO
  UINT16                                  Size;       // Range of IO
  UINT16                                  Attributes; // Attributes of IO
} SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR;

// SMM Supervisor Secure policy MSR descriptor, define MSR address SMM handler doesn't allow to access
// e.g. if disable the MSR write access 0xC001_2000- 0xC001_2FFF to SMM handler
// The struct need set to {Header, 0xC0012000, 0x1000, SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS}
typedef struct {
  SMM_SUPV_SECURE_POLICY_DESCRIPTOR_V1    Header;     // SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR
  UINT32                                  MsrAddress; // Base address of MSR
  UINT16                                  Size;       // Range of MSR
  UINT16                                  Attributes; // Attributes of MSR
} SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR;

// SMM Supervisor Secure policy instruction descriptor, define privileged instrcutin allow to access
// e.g. if allow the instruction "cli" execution to SMM handler
// The struct need set to {Header, SECURE_POLICY_INSTRUCTION_CLI, 0}
typedef struct {
  SMM_SUPV_SECURE_POLICY_DESCRIPTOR_V1    Header;           // SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION
  UINT16                                  InstructionIndex; // Instruction index from SECURE_POLICY_INSTRUCTION
  UINT16                                  Attributes;       // Attributes of instruction
} SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR;

typedef struct {
  UINT32                                   Version;           // 1
  UINT32                                   MemoryPolicyCount; // Count of MemoryPolicy
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR    MemoryPolicy[1];   // Size depend on the MemoryPolicyCount

  // UINT32 IoPolicyCount;     //Count of IOPolicy
  // SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR IoPolicy[1]; ////Size depend on the IoPolicyCount

  // UINT32 MsrPolicyCount;     //Count of MsrPolicy
  // SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR MsrPolicy[1]; //Size depend on the MsrPolicyCount

  // UINT32 InstructionPolicyCount;   //Count of InstructionPolicy
  // SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR InstructionPolicy[1]; //Size depend on the InstructionPolicyCount
} SMM_SUPV_SECURE_POLICY_DATA_V1;

typedef struct {
  UINT32    Version;            // 2
  UINT32    Size;               // Size in bytes of the whole blocks include Memory/IO/Msr/Instruction Policy
  UINT32    MemoryPolicyOffset;
  UINT32    MemoryPolicyCount;  // Count of MemoryPolicy
  UINT32    IoPolicyOffset;
  UINT32    IoPolicyCount;      // Count of IoPolicy
  UINT32    MsrPolicyOffset;
  UINT32    MsrPolicyCount;     // Count of MsrPolicy
  UINT32    InstructionPolicyOffset;
  UINT32    InstructionPolicyCount; // Count of InstructionPolicy
} SMM_SUPV_SECURE_POLICY_DATA_V2;

// **************************************************************************************//
//                                                                                      //
//            SMM Supervisor Policy v1.0 Defintion, for score 30 and beyond             //
//                                                                                      //
// **************************************************************************************//

//
// Secure Policy V1.0 uses 2 16-bit integers to differentiate from the versioning number from previous design.
// The policy data header will contain flag and capability bits to indicate certain status or capabilities
// enabled/supported in the supervisor. This header is followed by policy roots for each supported descriptor
// types, where AccessAttr is used to define all descriptors of this type is denied, allowed, etc. The offset
// field in SMM_SUPV_POLICY_ROOT_V* contains the offset value, relative to the policy start, pointing to a
// contiguous memory blob of all desriptors with the same type.
//
// If a platform chooses to support SMM isolation measurement as early as Windows 20H1, the MemoryPolicyOffset
// and MemoryPolicyCount should point to legacy memory descriptors defined the same as in SMM_SUPV_SECURE_POLICY_DATA_V2.
//
//  +-----------------------------+  <-- SMM_SUPV_SECURE_POLICY_DATA_V1_0
//  | VersionMinor | VersionMajor |
//  +-----------------------------+
//  |   Size                      |
//  +-----------------------------+
//  |   MemoryPolicyOffset        |  <-- Points to "Group of legacy memory descriptors" below, if supported
//  +-----------------------------+
//  |   MemoryPolicyCount         |  <-- Number of legacy memory descriptor included, if any
//  +-----------------------------+
//  |   Flags                     |
//  +-----------------------------+
//  |   Capabilities              |
//  +-----------------------------+
//  |   Reserved                  |
//  +-----------------------------+
//  |   PolicyRootCount           |
//  +#############################+  <-- Group of SMM_SUPV_POLICY_ROOT_V* for each SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_*
//  |   Version                   |
//  +-----------------------------+
//  |   PolicyRootSize            |
//  +-----------------------------+
//  |   Type 1                    |  <-- Should be one of SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_* defined in this file
//  +-----------------------------+
//  |   Offset 1                  |  <-- Points to group of descriptors of the same type, i.e. SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO
//  +-----------------------------+
//  |   Count 1                   |
//  +-----------------------------+
//  |   AccessAttr 1              |  <-- Should be one of SMM_SUPV_ACCESS_ATTR_* defined in this file
//  +-----------------------------+
//  |   Reserved                  |
//  +=============================+  <-- More SMM_SUPV_POLICY_ROOT_V* for more supported types
//  |   . . . . . . . . . . . .   |
//  +=============================+
//  |   Version                   |
//  +-----------------------------+
//  |   PolicyRootSize            |
//  +-----------------------------+
//  |   Type N                    |
//  +-----------------------------+
//  |   Offset N                  |  <-- Points to group of descriptors of the same type, i.e. SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE
//  +-----------------------------+
//  |   Count N                   |
//  +-----------------------------+
//  |   AccessAttr N              |  <-- Should be one of SMM_SUPV_ACCESS_ATTR_* defined in this file
//  +-----------------------------+
//  |   Reserved                  |
//  +#############################+  <-- Group of descriptors of the same type, example here is for SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO
//  |   IoAddress 1  | Size 1     |
//  +-----------------------------+
//  |   Attributes 1 | Reserved   |
//  +=============================+  <-- More SMM_SUPV_SECURE_POLICY_*_DESCRIPTOR_V1_0 for the same type
//  |   . . . . . . . . . . . .   |
//  +=============================+
//  |   IoAddress M  | Size N     |
//  +-----------------------------+
//  |   Attributes M | Reserved   |
//  +#############################+  <-- More groups of descriptors of other types defined by SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_*
//  |   . . . . . . . . . . . .   |
//  +#############################+  <-- Group of legacy memory descriptors "SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR", if supervisor supports 20H1
//  |   Header                    |
//  +-----------------------------+
//  |   BaseAddress 1             |
//  +-----------------------------+
//  |   Size 1                    |
//  +-----------------------------+
//  |   MemAttributes 1           |
//  +=============================+  <-- More legacy memory descriptors "SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR"
//  |   . . . . . . . . . . . .   |
//  +=============================+  <-- The last legacy memory descriptors "SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR"
//  |   Header                    |
//  +-----------------------------+
//  |   BaseAddress K             |
//  +-----------------------------+
//  |   Size K                    |
//  +-----------------------------+
//  |   MemAttributes K           |
//  +#############################+  <-- End of secure policy v1.0
//

// SMM Supervisor Secure policy memory descriptor,
// paired with SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM in v1.0 of secure policy
typedef struct {
  UINT64    BaseAddress;   // Base address of memory
  UINT64    Size;          // Size of memory
  UINT32    MemAttributes; // Attributes of memory
  UINT32    Reserved;      // Reserved, must be 0
} SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0;

// SMM Supervisor Secure policy IO descriptor, define IO address SMM handler doesn't allow to access
// paired with SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO in v1.0 of secure policy
// e.g. if disable the IO write access 0x3F8-0x3FC to SMM handler
// The policy root needs to have:
//   SMM_SUPV_POLICY_ROOT.Type = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO
//   SMM_SUPV_POLICY_ROOT.AccessAttr = SMM_SUPV_ACCESS_ATTR_DENY
// The descriptor should be set to {0x3F8, 4, SECURE_POLICY_RESOURCE_ATTR_WRITE}
typedef struct {
  UINT16    IoAddress;     // Base address of IO
  UINT16    LengthOrWidth; // Range of IO
  UINT16    Attributes;    // Attributes of IO
  UINT16    Reserved;      // Reserved, must be 0
} SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0;

// SMM Supervisor Secure policy MSR descriptor, define MSR address SMM handler doesn't allow to access
// paired with SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR in v1.0 of secure policy
// e.g. if disable the MSR write access 0xC001_2000- 0xC001_2FFF to SMM handler
// The policy root needs to have:
//   SMM_SUPV_POLICY_ROOT.Type = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR
//   SMM_SUPV_POLICY_ROOT.AccessAttr = SMM_SUPV_ACCESS_ATTR_DENY
// The descriptor should be set to {0xC0012000, 0x1000, SECURE_POLICY_RESOURCE_ATTR_WRITE}
typedef struct {
  UINT32    MsrAddress; // Base address of MSR
  UINT16    Length;     // Range of MSR
  UINT16    Attributes; // Attributes of MSR
} SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0;

// SMM Supervisor Secure policy instruction descriptor, define privileged instrcutin allow to access
// paired with SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION in v1.0 of secure policy
// e.g. if allow the instruction "cli" execution to SMM handler
// The policy root needs to have:
//   SMM_SUPV_POLICY_ROOT.Type = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION
//   SMM_SUPV_POLICY_ROOT.AccessAttr = SMM_SUPV_ACCESS_ATTR_ALLOW
// The struct need set to {SECURE_POLICY_INSTRUCTION_CLI, SECURE_POLICY_RESOURCE_ATTR_EXECUTE}
typedef struct {
  UINT16    InstructionIndex; // Instruction index from SECURE_POLICY_INSTRUCTION
  UINT16    Attributes;       // Attributes of instruction
  UINT32    Reserved;         // Reserved, must be 0
} SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0;

// SMM Supervisor Secure policy save state descriptor, define save state content access attribute
// paired with SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE in v1.0 of secure policy
// e.g. if allow the save state region "RAX" read access to SMM handler
// The policy root needs to have:
//   SMM_SUPV_POLICY_ROOT.Type = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE
//   SMM_SUPV_POLICY_ROOT.AccessAttr = SMM_SUPV_ACCESS_ATTR_ALLOW
// The struct need set to {SECURE_POLICY_SVST_RAX, SECURE_POLICY_RESOURCE_ATTR_COND_READ, SECURE_POLICY_SVST_CONDITION_IO_WR}
typedef struct {
  UINT32    MapField;                           // The field of protection in save state map, defined in SECURE_POLICY_SVST
  UINT32    Attributes;                         // Attributes of described save state content
  UINT32    AccessCondition;                    // Save state content accessible condition
  UINT32    Reserved;                           // Reserved, must be 0s.
} SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0;

typedef struct {
  UINT32    Version;        // The version of this descriptor. Current Version is 1.
  UINT32    PolicyRootSize; // The size of the SMM_SUPV_POLICY_ROOT_V* in bytes.
  UINT32    Type;           // The Type of this parameter, defined as SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_*
  UINT32    Offset;         // The offset of the leaf descriptors in bytes from the beginning of this table.
  UINT32    Count;          // Number of entries of 'Type', starting from 'Offset'
  UINT8     AccessAttr;     // The access attribute of all policy entries of this Type, value defined as
                            // SMM_SUPV_ACCESS_ATTR_ALLOW or SMM_SUPV_ACCESS_ATTR_DENY.
  UINT8     Reserved[3];    // Reserved, must be 0s.
  // Note: For backwards compatibility concern, one should not remove/rearrange the above fields if/when updating
  // the structure version to higher than 1.
} SMM_SUPV_POLICY_ROOT_V1;

typedef struct {
  UINT16    VersionMinor;        // 0x0000
  UINT16    VersionMajor;        // 0x0001
  UINT32    Size;                // Size in bytes of the entire policy block
  UINT32    MemoryPolicyOffset;  // Offset of legacy memory policy, if supported, otherwise 0
  UINT32    MemoryPolicyCount;   // Count of MemoryPolicy, if supported, otherwise 0
  // Note: For backwards compatibility concern, one should not change the above fields even for future versions.
  UINT32    Flags;               // Flag field to indicate supervisor status when policy is requested/reported
  UINT32    Capabilities;        // Capability field to indicate features supported by supervisor
  UINT64    Reserved;            // Reserved, must be 0
  UINT32    PolicyRootOffset;    // Offset from this structure to the beginning of the policy root array.
  UINT32    PolicyRootCount;     // Count of policy roots
  // SMM_SUPV_POLICY_ROOT PolicyRoots[];
} SMM_SUPV_SECURE_POLICY_DATA_V1_0;

#pragma pack (pop)
#endif
