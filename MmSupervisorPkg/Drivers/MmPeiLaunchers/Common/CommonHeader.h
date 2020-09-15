/** @file
  Common header file with context switching data structure definitions
  for MM PEI IPLs.

  Copyright (c) 2011 - 2016, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_IPL_PEI_COMMON_HEADER_
#define MM_IPL_PEI_COMMON_HEADER_

//
// 8 extra pages for PF handler.
//
#define EXTRA_PAGE_TABLE_PAGES  8

#define PAGING_1G_ADDRESS_MASK_64  0x000FFFFFC0000000ull

#if defined (MDE_CPU_IA32) || defined (MDE_CPU_X64)
  #pragma pack(1)
typedef struct {
  EFI_PHYSICAL_ADDRESS    EntryPoint;
  EFI_PHYSICAL_ADDRESS    StackBufferBase;
  UINT64                  StackBufferLength;
  EFI_PHYSICAL_ADDRESS    JumpBuffer;
  // MU_CHANGE: Updated structure members to be suitable for MM foundation setup
  EFI_PHYSICAL_ADDRESS    MmCoreEntryPointAddr;
  EFI_PHYSICAL_ADDRESS    HobStartAddr;
  BOOLEAN                 Page1GSupport;
  UINT64                  AddressEncMask;
} SWITCH_32_TO_64_CONTEXT;

typedef struct {
  UINT16                  ReturnCs;
  // MU_CHANGE: Updated structure members to be more comprehensive for environment context
  UINT16                  InterruptState;
  UINT32                  ReturnCr0;
  UINT32                  ReturnCr3;
  UINT32                  ReturnCr4;
  EFI_PHYSICAL_ADDRESS    ReturnEntryPoint;
  UINT64                  ReturnStatus;
  //
  // NOTICE:
  // Be careful about the Base field of IA32_DESCRIPTOR
  // that is UINTN type.
  // To extend new field for this structure, add it to
  // right before this Gdtr field.
  //
  IA32_DESCRIPTOR         Gdtr;
} SWITCH_64_TO_32_CONTEXT;
  #pragma pack()
#endif

#ifdef MDE_CPU_IA32

  #pragma pack(1)

//
// Page-Map Level-4 Offset (PML4) and
// Page-Directory-Pointer Offset (PDPE) entries 4K & 2MB
//

typedef union {
  struct {
    UINT64    Present              : 1;  // 0 = Not present in memory, 1 = Present in memory
    UINT64    ReadWrite            : 1;  // 0 = Read-Only, 1= Read/Write
    UINT64    UserSupervisor       : 1;  // 0 = Supervisor, 1=User
    UINT64    WriteThrough         : 1;  // 0 = Write-Back caching, 1=Write-Through caching
    UINT64    CacheDisabled        : 1;  // 0 = Cached, 1=Non-Cached
    UINT64    Accessed             : 1;  // 0 = Not accessed, 1 = Accessed (set by CPU)
    UINT64    Reserved             : 1;  // Reserved
    UINT64    MustBeZero           : 2;  // Must Be Zero
    UINT64    Available            : 3;  // Available for use by system software
    UINT64    PageTableBaseAddress : 40; // Page Table Base Address
    UINT64    AvailableHigh        : 11; // Available for use by system software
    UINT64    Nx                   : 1;  // No Execute bit
  } Bits;
  UINT64    Uint64;
} PAGE_MAP_AND_DIRECTORY_POINTER;

//
// Page Table Entry 2MB
//
typedef union {
  struct {
    UINT64    Present              : 1;  // 0 = Not present in memory, 1 = Present in memory
    UINT64    ReadWrite            : 1;  // 0 = Read-Only, 1= Read/Write
    UINT64    UserSupervisor       : 1;  // 0 = Supervisor, 1=User
    UINT64    WriteThrough         : 1;  // 0 = Write-Back caching, 1=Write-Through caching
    UINT64    CacheDisabled        : 1;  // 0 = Cached, 1=Non-Cached
    UINT64    Accessed             : 1;  // 0 = Not accessed, 1 = Accessed (set by CPU)
    UINT64    Dirty                : 1;  // 0 = Not Dirty, 1 = written by processor on access to page
    UINT64    MustBe1              : 1;  // Must be 1
    UINT64    Global               : 1;  // 0 = Not global page, 1 = global page TLB not cleared on CR3 write
    UINT64    Available            : 3;  // Available for use by system software
    UINT64    PAT                  : 1;  //
    UINT64    MustBeZero           : 8;  // Must be zero;
    UINT64    PageTableBaseAddress : 31; // Page Table Base Address
    UINT64    AvailableHigh        : 11; // Available for use by system software
    UINT64    Nx                   : 1;  // 0 = Execute Code, 1 = No Code Execution
  } Bits;
  UINT64    Uint64;
} PAGE_TABLE_ENTRY;

//
// Page Table Entry 1GB
//
typedef union {
  struct {
    UINT64    Present              : 1;  // 0 = Not present in memory, 1 = Present in memory
    UINT64    ReadWrite            : 1;  // 0 = Read-Only, 1= Read/Write
    UINT64    UserSupervisor       : 1;  // 0 = Supervisor, 1=User
    UINT64    WriteThrough         : 1;  // 0 = Write-Back caching, 1=Write-Through caching
    UINT64    CacheDisabled        : 1;  // 0 = Cached, 1=Non-Cached
    UINT64    Accessed             : 1;  // 0 = Not accessed, 1 = Accessed (set by CPU)
    UINT64    Dirty                : 1;  // 0 = Not Dirty, 1 = written by processor on access to page
    UINT64    MustBe1              : 1;  // Must be 1
    UINT64    Global               : 1;  // 0 = Not global page, 1 = global page TLB not cleared on CR3 write
    UINT64    Available            : 3;  // Available for use by system software
    UINT64    PAT                  : 1;  //
    UINT64    MustBeZero           : 17; // Must be zero;
    UINT64    PageTableBaseAddress : 22; // Page Table Base Address
    UINT64    AvailableHigh        : 11; // Available for use by system software
    UINT64    Nx                   : 1;  // 0 = Execute Code, 1 = No Code Execution
  } Bits;
  UINT64    Uint64;
} PAGE_TABLE_1G_ENTRY;

  #pragma pack()

typedef
EFI_STATUS
(*RELAY_ENTRY) (
  SWITCH_32_TO_64_CONTEXT  *EntrypointContext,
  SWITCH_64_TO_32_CONTEXT  *ReturnContext
  );

#endif

#endif
