/** @file
  The internal header file that declared a data structure that is shared
  between the MM IPL and the MM Core.

  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_CORE_MEM_H_
#define _MM_CORE_MEM_H_

#include <Guid/MmCoreData.h>

///
/// Page Table Entry
///
#define IA32_PG_P       BIT0
#define IA32_PG_RW      BIT1
#define IA32_PG_U       BIT2
#define IA32_PG_WT      BIT3
#define IA32_PG_CD      BIT4
#define IA32_PG_A       BIT5
#define IA32_PG_D       BIT6
#define IA32_PG_PS      BIT7
#define IA32_PG_PAT_2M  BIT12
#define IA32_PG_PAT_4K  IA32_PG_PS
#define IA32_PG_PMNT    BIT62
#define IA32_PG_NX      BIT63

#define PAGE_ATTRIBUTE_BITS  (IA32_PG_D | IA32_PG_A | IA32_PG_U | IA32_PG_RW | IA32_PG_P)
//
// Bits 1, 2, 5, 6 are reserved in the IA32 PAE PDPTE
// X64 PAE PDPTE does not have such restriction
//
#define IA32_PAE_PDPTE_ATTRIBUTE_BITS  (IA32_PG_P)

#define PAGE_PROGATE_BITS  (IA32_PG_NX | PAGE_ATTRIBUTE_BITS)

#define PAGING_4K_MASK  0xFFF
#define PAGING_2M_MASK  0x1FFFFF
#define PAGING_1G_MASK  0x3FFFFFFF

#define PAGING_PAE_INDEX_MASK  0x1FF

#define PAGING_4K_ADDRESS_MASK_64  0x000FFFFFFFFFF000ull
#define PAGING_2M_ADDRESS_MASK_64  0x000FFFFFFFE00000ull
#define PAGING_1G_ADDRESS_MASK_64  0x000FFFFFC0000000ull

#define SMRR_MAX_ADDRESS  BASE_4GB

typedef enum {
  PageNone,
  Page4K,
  Page2M,
  Page1G,
} PAGE_ATTRIBUTE;

typedef struct {
  PAGE_ATTRIBUTE    Attribute;
  UINT64            Length;
  UINT64            AddressMask;
} PAGE_ATTRIBUTE_TABLE;

//
// Page management
//

typedef struct {
  LIST_ENTRY    Link;
  UINTN         NumberOfPages;
} FREE_PAGE_LIST;

//
// Pool management
//

//
// MIN_POOL_SHIFT must not be less than 5
//
#define MIN_POOL_SHIFT  6
#define MIN_POOL_SIZE   (1 << MIN_POOL_SHIFT)

//
// MAX_POOL_SHIFT must not be less than EFI_PAGE_SHIFT - 1
//
#define MAX_POOL_SHIFT  (EFI_PAGE_SHIFT - 1)
#define MAX_POOL_SIZE   (1 << MAX_POOL_SHIFT)

//
// MAX_POOL_INDEX are calculated by maximum and minimum pool sizes
//
#define MAX_POOL_INDEX  (MAX_POOL_SHIFT - MIN_POOL_SHIFT + 1)

#define POOL_HEAD_SIGNATURE  SIGNATURE_32('s','p','h','d')

typedef struct {
  UINT32             Signature;
  BOOLEAN            Available;
  EFI_MEMORY_TYPE    Type;
  UINTN              Size;
} POOL_HEADER;

#define POOL_TAIL_SIGNATURE  SIGNATURE_32('s','p','t','l')

typedef struct {
  UINT32    Signature;
  UINT32    Reserved;
  UINTN     Size;
} POOL_TAIL;

#define POOL_OVERHEAD  (sizeof(POOL_HEADER) + sizeof(POOL_TAIL))

#define HEAD_TO_TAIL(a)   \
  ((POOL_TAIL *) (((CHAR8 *) (a)) + (a)->Size - sizeof(POOL_TAIL)));

typedef struct {
  POOL_HEADER    Header;
  LIST_ENTRY     Link;
} FREE_POOL_HEADER;

typedef enum {
  MmPoolTypeCode,
  MmPoolTypeData,
  MmPoolTypeMax,
} MM_POOL_TYPE;

extern LIST_ENTRY  mMmMemoryMap;
extern LIST_ENTRY  mMmPoolLists[MmPoolTypeMax][MAX_POOL_INDEX];

#define PAGE_TABLE_POOL_UNIT_SIZE   SIZE_512KB
#define PAGE_TABLE_POOL_UNIT_PAGES  EFI_SIZE_TO_PAGES (PAGE_TABLE_POOL_UNIT_SIZE)

typedef struct {
  VOID     *PoolHeader;
  UINTN    Offset;
  UINTN    FreePages;
} PAGE_TABLE_POOL;

extern PAGE_TABLE_POOL  mPageTablePool;

//
// Copy of the PcdPteMemoryEncryptionAddressOrMask
//
extern UINT64  mAddressEncMask;
extern UINT8   mPhysicalAddressBits;

extern EFI_MEMORY_DESCRIPTOR  *mInitMemoryMap;
extern UINTN                  mInitDescriptorSize;
extern UINTN                  mInitMemoryMapSize;

/**
  Internal Function. Allocate n pages from given free page node.

  @param  Pages                  The free page node.
  @param  NumberOfPages          Number of pages to be allocated.
  @param  MaxAddress             Request to allocate memory below this address.

  @return Memory address of allocated pages.

**/
UINTN
InternalAllocPagesOnOneNode (
  IN OUT FREE_PAGE_LIST  *Pages,
  IN     UINTN           NumberOfPages,
  IN     UINTN           MaxAddress
  );

/**
  Update SMM memory map entry.

  @param[in]  Type                   The type of allocation to perform.
  @param[in]  Memory                 The base of memory address.
  @param[in]  NumberOfPages          The number of pages to allocate.
  @param[in]  AddRegion              If this memory is new added region.
  @param[in]  SupervisorPage         If this memory is allocated as supervisor region.
**/
VOID
ConvertMmMemoryMapEntry (
  IN EFI_MEMORY_TYPE       Type,
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN BOOLEAN               AddRegion,
  IN BOOLEAN               SupervisorPage
  );

/**
  Internal function.  Moves any memory descriptors that are on the
  temporary descriptor stack to heap.

**/
VOID
CoreFreeMemoryMapStack (
  VOID
  );

/**
  Frees previous allocated pages.

  @param[in]  Memory                 Base address of memory being freed.
  @param[in]  NumberOfPages          The number of pages to free.
  @param[in]  AddRegion              If this memory is new added region.
  @param[in]  SupervisorPage         If this buffer is a supervisor page.

  @retval EFI_NOT_FOUND          Could not find the entry that covers the range.
  @retval EFI_INVALID_PARAMETER  Address not aligned, Address is zero or NumberOfPages is zero.
  @return EFI_SUCCESS            Pages successfully freed.

**/
EFI_STATUS
MmInternalFreePagesEx (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN BOOLEAN               AddRegion,
  IN BOOLEAN               SupervisorPage
  );

/**
  This function sets memory attribute for page table.
**/
VOID
SetPageTableAttributes (
  VOID
  );

/**
  This function sets the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]   PageTableBase    The page table base.
  @param[in]   EnablePML5Paging If PML5 paging is enabled.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to set for the memory region.
  @param[out]  IsSplitted       TRUE means page table splitted. FALSE means page table not splitted.

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmSetMemoryAttributesEx (
  IN  UINTN                 PageTableBase,
  IN  BOOLEAN               EnablePML5Paging,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes,
  OUT BOOLEAN               *IsSplitted  OPTIONAL
  );

/**
  This function clears the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]   PageTableBase    The page table base.
  @param[in]   EnablePML5Paging If PML5 paging is enabled.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to clear for the memory region.
  @param[out]  IsSplitted       TRUE means page table splitted. FALSE means page table not splitted.

  @retval EFI_SUCCESS           The attributes were cleared for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
SmmClearMemoryAttributesEx (
  IN  UINTN                 PageTableBase,
  IN  BOOLEAN               EnablePML5Paging,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes,
  OUT BOOLEAN               *IsSplitted  OPTIONAL
  );

/**
  This function sets the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]  BaseAddress      The physical address that is the start address of a memory region.
  @param[in]  Length           The size in bytes of the memory region.
  @param[in]  Attributes       The bit mask of attributes to set for the memory region.

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmSetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  );

/**
  This function clears the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]  BaseAddress      The physical address that is the start address of a memory region.
  @param[in]  Length           The size in bytes of the memory region.
  @param[in]  Attributes       The bit mask of attributes to clear for the memory region.

  @retval EFI_SUCCESS           The attributes were cleared for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmClearMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  );

/**
  This function sets the read only attributes of GDT pages of currently executing CPU.

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not supported for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
SmmSetGdtReadOnlyForThisProcessor (
  VOID
  );

/**
  This function clears the read only attributes of GDT pages of currently executing CPU.

  @retval EFI_SUCCESS           The attributes were cleared for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be cleared together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not supported for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
SmmClearGdtReadOnlyForThisProcessor (
  VOID
  );

/**
  This function retrieves the attributes of the memory region specified by
  BaseAddress and Length. If different attributes are got from different part
  of the memory region, EFI_NO_MAPPING will be returned.

  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        Pointer to attributes returned.

  @retval EFI_SUCCESS           The attributes got for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes is NULL.
                                Length is larger than MAX_INT64. // MU_CHANGE: Avoid Length overflow for INT64
  @retval EFI_NO_MAPPING        Attributes are not consistent cross the memory
                                region.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
SmmGetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                *Attributes
  );

/**
  This API provides a way to allocate memory for page table.

  This API can be called more once to allocate memory for page tables.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
AllocatePageTableMemory (
  IN UINTN  Pages
  );

/**
  This API provides a way to allocate memory for page table.

  This API can be called more once to allocate memory for page tables.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
AllocateExtendedPageTableMemory (
  IN UINTN  Pages
  );

/**
  Allocate pages for code.

  @param[in]  Pages Number of pages to be allocated.

  @return Allocated memory.
**/
VOID *
AllocateCodePages (
  IN UINTN  Pages
  );

/**
  Allocate aligned pages for code.

  @param[in]  Pages                 Number of pages to be allocated.
  @param[in]  Alignment             The requested alignment of the allocation.
                                    Must be a power of two.
                                    If Alignment is zero, then byte alignment is used.

  @return Allocated memory.
**/
VOID *
AllocateAlignedCodePages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  );

/*
Helper function to mark all non SMM memory ranges reported through hobs as non present
*/
VOID
EFIAPI
SetNonSmmMemMapAttributes (
  VOID
  );

/**
  Set the internal page table base address.
  If it is non zero, further MemoryAttribute modification will be on this page table.
  If it is zero, further MemoryAttribute modification will be on real page table.

  @param Cr3 page table base.
**/
VOID
SetPageTableBase (
  IN UINTN  Cr3
  );

/*
Helper function to mark common buffer range as accessible from inside MM
*/
EFI_STATUS
EFIAPI
SetCommonBufferRegionAttribute (
  VOID
  );

/*
Helper function to mark regions needs protection to be certain attributes
*/
EFI_STATUS
EFIAPI
SetProtectedRegionAttribute (
  VOID
  );

/*
  Helper function to mark regions needs unblocking to corresponding attributes.
*/
EFI_STATUS
EFIAPI
SetUnblockRegionAttribute (
  VOID
  );

/**
  Set ShadowStack memory.

  @param[in]  Cr3              The page table base address.
  @param[in]  BaseAddress      The physical address that is the start address of a memory region.
  @param[in]  Length           The size in bytes of the memory region.

  @retval EFI_SUCCESS           The shadow stack memory is set.
**/
EFI_STATUS
SetShadowStack (
  IN  UINTN                 Cr3,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length
  );

/**
  Set not present memory.

  @param[in]  Cr3              The page table base address.
  @param[in]  BaseAddress      The physical address that is the start address of a memory region.
  @param[in]  Length           The size in bytes of the memory region.

  @retval EFI_SUCCESS           The not present memory is set.
**/
EFI_STATUS
SetNotPresentPage (
  IN  UINTN                 Cr3,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length
  );

/**
  This function sets memory attribute according to MemoryAttributesTable.
**/
VOID
SetMemMapAttributes (
  VOID
  );

/**
  Helper function that will evaluate the page where the input address is located belongs to a
  user page that is mapped inside MM.

  @param  Address           Target address to be inspected.
  @param  Size              Address range to be inspected.
  @param  IsUserRange       Pointer to hold inspection result, TRUE if the region is in User pages, FALSE if
                            the page is in supervisor pages. Should not be used if return value is not EFI_SUCCESS.

  @return     The result of inspection operation.

**/
EFI_STATUS
InspectTargetRangeOwnership (
  IN  EFI_PHYSICAL_ADDRESS  Address,
  IN  UINTN                 Size,
  OUT BOOLEAN               *IsUserRange
  );

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This buffer is not part of MMRAM.
  @retval FALSE This buffer is from MMRAM.
**/
BOOLEAN
IsBufferInsideMmram (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  );

/**
  Helper function to validate legitimacy for incoming supervisor communcate buffer for MMI handlers.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestSupvCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize
  );

/**
  Helper function to validate legitimacy for incoming user communcate buffer for MMI handlers.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestUserCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize
  );

#endif
