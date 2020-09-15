/** @file -- PageTableDumpCommon.h
Shared definitions between the DXE and SMM drivers.
Mostly used for SMM communication.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_PAGING_AUDIT_H_
#define MM_PAGING_AUDIT_H_

#pragma pack(1)

#define MAX_IMAGE_NAME_SIZE  100

typedef struct {
  UINT64      ImageBase;
  UINT64      ImageSize;
  EFI_GUID    ImageGuid;
  CHAR8       ImageName[MAX_IMAGE_NAME_SIZE];
} IMAGE_STRUCT;

#define BUFFER_COUNT_1G       300
#define BUFFER_COUNT_2M       500
#define BUFFER_COUNT_4K       1000
#define BUFFER_COUNT_GUARD    100
#define BUFFER_COUNT_PDE      20
#define BUFFER_COUNT_IMAGES   25
#define BUFFER_COUNT_CORES    8
#define BUFFER_COUNT_UNBLOCK  20

#define SMM_PAGE_AUDIT_TABLE_REQUEST       0x01
#define SMM_PAGE_AUDIT_PDE_REQUEST         0x02
#define SMM_PAGE_AUDIT_MISC_DATA_REQUEST   0x03
#define SMM_PAGE_AUDIT_CLEAR_DATA_REQUEST  0x04
#define SMM_PAGE_AUDIT_SMI_ENTRY_REQUEST   0x05
#define SMM_PAGE_AUDIT_UNBLOCKED_REQUEST   0x06
#define SMM_PAGE_AUDIT_GUARD_PAGE_REQUEST  0x07

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
// Page Table Entry 4KB
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
    UINT64    PAT                  : 1;  //
    UINT64    Global               : 1;  // 0 = Not global page, 1 = global page TLB not cleared on CR3 write
    UINT64    Available            : 3;  // Available for use by system software
    UINT64    PageTableBaseAddress : 40; // Page Table Base Address
    UINT64    AvailableHigh        : 11; // Available for use by system software
    UINT64    Nx                   : 1;  // 0 = Execute Code, 1 = No Code Execution
  } Bits;
  UINT64    Uint64;
} PAGE_TABLE_4K_ENTRY;

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

//
// Structures for page table entries and miscellaneous memory
// information from SMM.
//
typedef struct _SMM_PAGE_AUDIT_COMM_HEADER {
  UINTN    RequestType;
  UINTN    RequestIndex;
} SMM_PAGE_AUDIT_COMM_HEADER;

typedef struct _PAGE_TABLE_ENTRY_COMM_BUFFER {
  PAGE_TABLE_1G_ENTRY    Pte1G[BUFFER_COUNT_1G];
  PAGE_TABLE_ENTRY       Pte2M[BUFFER_COUNT_2M];
  PAGE_TABLE_4K_ENTRY    Pte4K[BUFFER_COUNT_4K];
  UINTN                  Pte1GCount;
  UINTN                  Pte2MCount;
  UINTN                  Pte4KCount;
  BOOLEAN                HasMore;
} SMM_PAGE_AUDIT_TABLE_ENTRY_COMM_BUFFER;

typedef struct _GUARD_ENTRY_COMM_BUFFER {
  UINT64     GuardPage[BUFFER_COUNT_GUARD];
  UINTN      GuardPageCount;
  BOOLEAN    HasMore;
} SMM_PAGE_AUDIT_GUARD_ENTRY_COMM_BUFFER;

typedef struct _SMM_PAGE_AUDIT_PDE_ENTRY_COMM_BUFFER {
  UINT64     Pde[BUFFER_COUNT_PDE];
  UINTN      PdeCount;
  BOOLEAN    HasMore;
} SMM_PAGE_AUDIT_PDE_ENTRY_COMM_BUFFER;

typedef struct _SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER {
  UINT8                   MaxAddessBitwidth;
  IA32_DESCRIPTOR         Idtr;
  IMAGE_STRUCT            SmmImage[BUFFER_COUNT_IMAGES];
  UINTN                   SmmImageCount;
  EFI_PHYSICAL_ADDRESS    SupvStackBaseAddr;
  UINTN                   SupvStackSize;
  EFI_PHYSICAL_ADDRESS    UserStackBaseAddr;
  UINTN                   UserStackSize;
  EFI_PHYSICAL_ADDRESS    SupvCommBufferBase;
  UINTN                   SupvCommBufferSize;
  EFI_PHYSICAL_ADDRESS    UserCommBufferBase;
  EFI_PHYSICAL_ADDRESS    UserCommBufferSize;
  BOOLEAN                 HasMore;
} SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER;

typedef struct _SMM_PAGE_AUDIT_SMI_ENTRY_COMM_BUFFER {
  IA32_DESCRIPTOR         Gdtr[BUFFER_COUNT_CORES];
  EFI_PHYSICAL_ADDRESS    SmiEntryBase[BUFFER_COUNT_CORES];
  EFI_PHYSICAL_ADDRESS    SmiSaveStateBase[BUFFER_COUNT_CORES];
  UINTN                   SmiEntrySize;
  UINTN                   SmiSaveStateSize;
  UINTN                   SmiEntryCount;
  BOOLEAN                 HasMore;
} SMM_PAGE_AUDIT_SMI_ENTRY_COMM_BUFFER;

typedef struct _SMM_PAGE_AUDIT_UNBLOCK_REGION_COMM_BUFFER {
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS    UnblockedRegions[BUFFER_COUNT_UNBLOCK];
  UINTN                                  UnblockedRegionCount;
  BOOLEAN                                HasMore;
} SMM_PAGE_AUDIT_UNBLOCK_REGION_COMM_BUFFER;

typedef struct _SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER {
  SMM_PAGE_AUDIT_COMM_HEADER    Header;
  union {
    SMM_PAGE_AUDIT_TABLE_ENTRY_COMM_BUFFER       TableEntry;
    SMM_PAGE_AUDIT_PDE_ENTRY_COMM_BUFFER         PdeEntry;
    SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER         MiscData;
    SMM_PAGE_AUDIT_SMI_ENTRY_COMM_BUFFER         SmiEntry;
    SMM_PAGE_AUDIT_UNBLOCK_REGION_COMM_BUFFER    UnblockedRegion;
    SMM_PAGE_AUDIT_GUARD_ENTRY_COMM_BUFFER       GuardPages;
  } Data;
} SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER;

#pragma pack()

// {0059B149-1117-47DC-80BB-1125E98B418C}
#define MM_PAGING_AUDIT_MMI_HANDLER_GUID \
{ 0x59b149, 0x1117, 0x47dc, { 0x80, 0xbb, 0x11, 0x25, 0xe9, 0x8b, 0x41, 0x8c } };

extern EFI_GUID  gMmPagingAuditMmiHandlerGuid;

#endif // MM_PAGING_AUDIT_H_
