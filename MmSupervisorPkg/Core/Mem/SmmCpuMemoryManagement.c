/** @file

Copyright (c) 2016 - 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/MmProtectedRegion.h>
#include <Guid/MmUnblockRegion.h>
#include <Guid/MmSupervisorRequestData.h>
#include <Protocol/MpService.h>
#include <Protocol/SmmConfiguration.h>

#include <Library/BaseLib.h>
#include <Library/CpuLib.h>
#include <Library/SortLib.h>
#include <Library/SmmCpuPlatformHookLib.h>
#include <Library/ResetSystemLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "Services/CpuService/CpuService.h"
#include "Services/MpService/MpService.h"
#include "Relocate/Relocate.h"
#include "Request/Request.h"

//
// attributes for reserved memory before it is promoted to system memory
//
#define EFI_MEMORY_PRESENT      0x0100000000000000ULL
#define EFI_MEMORY_INITIALIZED  0x0200000000000000ULL
#define EFI_MEMORY_TESTED       0x0400000000000000ULL

#define PREVIOUS_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) - (Size)))

///
/// Define macros to encapsulate the write unprotect/protect
/// read-only pages.
/// Below pieces of logic are defined as macros and not functions
/// because "CET" feature disable & enable must be in the same
/// function to avoid shadow stack and normal SMI stack mismatch,
/// thus WRITE_UNPROTECT_RO_PAGES () must be called pair with
/// WRITE_PROTECT_RO_PAGES () in same function.
///
/// @param[in,out] Wp   A BOOLEAN variable local to the containing
///                     function, carrying write protection status from
///                     WRITE_UNPROTECT_RO_PAGES() to
///                     WRITE_PROTECT_RO_PAGES().
///
/// @param[in,out] Cet  A BOOLEAN variable local to the containing
///                     function, carrying control flow integrity
///                     enforcement status from
///                     WRITE_UNPROTECT_RO_PAGES() to
///                     WRITE_PROTECT_RO_PAGES().
///
#define WRITE_UNPROTECT_RO_PAGES(Wp, Cet) \
  do { \
    Cet = ((AsmReadCr4 () & CR4_CET_ENABLE) != 0); \
    if (Cet) { \
      DisableCet (); \
    } \
    SmmWriteUnprotectReadOnlyPage (&Wp); \
  } while (FALSE)

#define WRITE_PROTECT_RO_PAGES(Wp, Cet) \
  do { \
    SmmWriteProtectReadOnlyPage (Wp); \
    if (Cet) { \
      EnableCet (); \
    } \
  } while (FALSE)

// Note: This is ordered this type intentionally as tie breaker,
// thus when an address is at the end of both DXE and SMM range,
// SMM will eliminate the previous range for inclusion, vice versa
typedef enum {
  SMM_RANGE_END,
  DXE_RANGE_END,
  SPECIAL_RANGE_END,
  SPECIAL_RANGE_START,
  DXE_RANGE_START,
  SMM_RANGE_START,
} MEMORY_RANGE_TYPE;

typedef struct {
  UINTN                   Type;   // Should be one of MEMORY_RANGE_TYPE
  EFI_PHYSICAL_ADDRESS    Address;
} MEMORY_ADDRESS_POINT;

UINTN                  mInternalCr3;
BOOLEAN                mIsShadowStack      = FALSE;
BOOLEAN                m5LevelPagingNeeded = FALSE;
PAGING_MODE            mPagingMode         = PagingModeMax;
EFI_MEMORY_DESCRIPTOR  *mInitMemoryMap     = NULL;
UINTN                  mInitDescriptorSize = 0;
UINTN                  mInitMemoryMapSize  = 0;

//
// Global variable to keep track current available memory used as page table.
//
PAGE_TABLE_POOL  *mPageTablePool = NULL;

//
// If memory used by SMM page table has been mareked as ReadOnly.
//
BOOLEAN  mIsReadOnlyPageTable = FALSE;

/**
  Write unprotect read-only pages if Cr0.Bits.WP is 1.
  @param[out]  WriteProtect      If Cr0.Bits.WP is enabled.
**/
VOID
SmmWriteUnprotectReadOnlyPage (
  OUT BOOLEAN  *WriteProtect
  )
{
  IA32_CR0  Cr0;

  Cr0.UintN     = AsmReadCr0 ();
  *WriteProtect = (Cr0.Bits.WP != 0);
  if (*WriteProtect) {
    Cr0.Bits.WP = 0;
    AsmWriteCr0 (Cr0.UintN);
  }
}

/**
  Write protect read-only pages.
  @param[in]  WriteProtect      If Cr0.Bits.WP should be enabled.
**/
VOID
SmmWriteProtectReadOnlyPage (
  IN  BOOLEAN  WriteProtect
  )
{
  IA32_CR0  Cr0;

  if (WriteProtect) {
    Cr0.UintN   = AsmReadCr0 ();
    Cr0.Bits.WP = 1;
    AsmWriteCr0 (Cr0.UintN);
  }
}

/**
  Initialize a buffer pool for page table use only.

  To reduce the potential split operation on page table, the pages reserved for
  page table should be allocated in the times of PAGE_TABLE_POOL_UNIT_PAGES and
  at the boundary of PAGE_TABLE_POOL_ALIGNMENT. So the page pool is always
  initialized with number of pages greater than or equal to the given PoolPages.

  Once the pages in the pool are used up, this method should be called again to
  reserve at least another PAGE_TABLE_POOL_UNIT_PAGES. But usually this won't
  happen in practice.

  @param PoolPages  The least page number of the pool to be created.

  @retval TRUE    The pool is initialized successfully.
  @retval FALSE   The memory is out of resource.

**/
BOOLEAN
InitializePageTablePool (
  IN UINTN  PoolPages
  )
{
  VOID     *Buffer;
  BOOLEAN  WriteProtect;
  BOOLEAN  CetEnabled;

  //
  // Always reserve at least PAGE_TABLE_POOL_UNIT_PAGES, including one page for
  // header.
  //
  PoolPages += 1;   // Add one page for header.
  PoolPages  = ((PoolPages - 1) / PAGE_TABLE_POOL_UNIT_PAGES + 1) *
               PAGE_TABLE_POOL_UNIT_PAGES;
  Buffer = AllocateAlignedPages (PoolPages, PAGE_TABLE_POOL_ALIGNMENT);
  if (Buffer == NULL) {
    DEBUG ((DEBUG_ERROR, "ERROR: Out of aligned pages\r\n"));
    return FALSE;
  }

  //
  // Link all pools into a list for easier track later.
  //
  if (mPageTablePool == NULL) {
    mPageTablePool           = Buffer;
    mPageTablePool->NextPool = mPageTablePool;
  } else {
    ((PAGE_TABLE_POOL *)Buffer)->NextPool = mPageTablePool->NextPool;
    mPageTablePool->NextPool              = Buffer;
    mPageTablePool                        = Buffer;
  }

  //
  // Reserve one page for pool header.
  //
  mPageTablePool->FreePages = PoolPages - 1;
  mPageTablePool->Offset    = EFI_PAGES_TO_SIZE (1);

  //
  // If page table memory has been marked as RO, mark the new pool pages as read-only.
  //
  if (mIsReadOnlyPageTable) {
    WRITE_UNPROTECT_RO_PAGES (WriteProtect, CetEnabled);

    SmmSetMemoryAttributes ((EFI_PHYSICAL_ADDRESS)(UINTN)Buffer, EFI_PAGES_TO_SIZE (PoolPages), EFI_MEMORY_RO);

    WRITE_PROTECT_RO_PAGES (WriteProtect, CetEnabled);
  }

  return TRUE;
}

/**
  This API provides a way to allocate memory for page table.

  This API can be called more than once to allocate memory for page tables.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  NewAllocation         Pointer to a passed in BOOLEAN that will be TRUE if new pages have been allocated
                                for the page pool and FALSE otherwise.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
AllocatePageTableMemory (
  IN UINTN     Pages,
  OUT BOOLEAN  *NewAllocation OPTIONAL
  )
{
  VOID  *Buffer;

  if (NewAllocation != NULL) {
    *NewAllocation = FALSE;
  }

  if (Pages == 0) {
    return NULL;
  }

  //
  // Renew the pool if necessary.
  //
  if ((mPageTablePool == NULL) ||
      (Pages > mPageTablePool->FreePages))
  {
    if (NewAllocation != NULL) {
      *NewAllocation = TRUE;
    }

    if (!InitializePageTablePool (Pages)) {
      // No new allocation was done because we ran out of memory
      if (NewAllocation != NULL) {
        *NewAllocation = FALSE;
      }

      return NULL;
    }
  }

  Buffer = (UINT8 *)mPageTablePool + mPageTablePool->Offset;

  mPageTablePool->Offset    += EFI_PAGES_TO_SIZE (Pages);
  mPageTablePool->FreePages -= Pages;

  return Buffer;
}

/**
  Set the internal page table base address.
  If it is non zero, further MemoryAttribute modification will be on this page table.
  If it is zero, further MemoryAttribute modification will be on real page table.
  @param Cr3 page table base.
**/
VOID
SetPageTableBase (
  IN UINTN  Cr3
  )
{
  mInternalCr3 = Cr3;
}

/**
  Return page table entry to match the address.

  @param[in]   PageTableBase      The page table base.
  @param[in]   Enable5LevelPaging If PML5 paging is enabled.
  @param[in]   Address            The address to be checked.
  @param[out]  PageAttributes     The page attribute of the page entry.

  @return The page entry.
**/
VOID *
GetPageTableEntry (
  IN  UINTN             PageTableBase,
  IN  BOOLEAN           Enable5LevelPaging,
  IN  PHYSICAL_ADDRESS  Address,
  OUT PAGE_ATTRIBUTE    *PageAttribute
  )
{
  UINTN   Index1;
  UINTN   Index2;
  UINTN   Index3;
  UINTN   Index4;
  UINTN   Index5;
  UINT64  *L1PageTable;
  UINT64  *L2PageTable;
  UINT64  *L3PageTable;
  UINT64  *L4PageTable;
  UINT64  *L5PageTable;

  Index5 = ((UINTN)RShiftU64 (Address, 48)) & PAGING_PAE_INDEX_MASK;
  Index4 = ((UINTN)RShiftU64 (Address, 39)) & PAGING_PAE_INDEX_MASK;
  Index3 = ((UINTN)Address >> 30) & PAGING_PAE_INDEX_MASK;
  Index2 = ((UINTN)Address >> 21) & PAGING_PAE_INDEX_MASK;
  Index1 = ((UINTN)Address >> 12) & PAGING_PAE_INDEX_MASK;

  ASSERT (
    (mCoreInitializationComplete && mInternalCr3 == 0) ||
    (!mCoreInitializationComplete && mInternalCr3 != 0)
    );

  if (sizeof (UINTN) == sizeof (UINT64)) {
    if (Enable5LevelPaging) {
      L5PageTable = (UINT64 *)PageTableBase;
      if (L5PageTable[Index5] == 0) {
        *PageAttribute = PageNone;
        return NULL;
      }

      L4PageTable = (UINT64 *)(UINTN)(L5PageTable[Index5] & ~mAddressEncMask & PAGING_4K_ADDRESS_MASK_64);
    } else {
      L4PageTable = (UINT64 *)PageTableBase;
    }

    if (L4PageTable[Index4] == 0) {
      *PageAttribute = PageNone;
      return NULL;
    }

    L3PageTable = (UINT64 *)(UINTN)(L4PageTable[Index4] & ~mAddressEncMask & PAGING_4K_ADDRESS_MASK_64);
  } else {
    L3PageTable = (UINT64 *)PageTableBase;
  }

  if (L3PageTable[Index3] == 0) {
    *PageAttribute = PageNone;
    return NULL;
  }

  if ((L3PageTable[Index3] & IA32_PG_PS) != 0) {
    // 1G
    *PageAttribute = Page1G;
    return &L3PageTable[Index3];
  }

  L2PageTable = (UINT64 *)(UINTN)(L3PageTable[Index3] & ~mAddressEncMask & PAGING_4K_ADDRESS_MASK_64);
  if (L2PageTable[Index2] == 0) {
    *PageAttribute = PageNone;
    return NULL;
  }

  if ((L2PageTable[Index2] & IA32_PG_PS) != 0) {
    // 2M
    *PageAttribute = Page2M;
    return &L2PageTable[Index2];
  }

  // 4k
  L1PageTable = (UINT64 *)(UINTN)(L2PageTable[Index2] & ~mAddressEncMask & PAGING_4K_ADDRESS_MASK_64);
  if ((L1PageTable[Index1] == 0) && (Address != 0)) {
    *PageAttribute = PageNone;
    return NULL;
  }

  *PageAttribute = Page4K;
  return &L1PageTable[Index1];
}

/**
  Return memory attributes of page entry.

  @param[in]  PageEntry        The page entry.

  @return Memory attributes of page entry.
**/
UINT64
GetAttributesFromPageEntry (
  IN  UINT64  *PageEntry
  )
{
  UINT64  Attributes;

  Attributes = 0;
  if ((*PageEntry & IA32_PG_P) == 0) {
    Attributes |= EFI_MEMORY_RP;
  }

  if ((*PageEntry & IA32_PG_RW) == 0) {
    Attributes |= EFI_MEMORY_RO;
  }

  if ((*PageEntry & IA32_PG_NX) != 0) {
    Attributes |= EFI_MEMORY_XP;
  }

  if ((*PageEntry & IA32_PG_U) == 0) {
    // UINT64  UserSupervisor:1;         // 0 = Supervisor, 1=User
    Attributes |= EFI_MEMORY_SP;
  }

  return Attributes;
}

/**
  This function modifies the page attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  @param[in]   PageTableBase    The page table base.
  @param[in]   PagingMode       The paging mode.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to modify for the memory region.
  @param[in]   IsSet            TRUE means to set attributes. FALSE means to clear attributes.
  @param[out]  IsModified       TRUE means page table modified. FALSE means page table not modified.

  @retval RETURN_SUCCESS           The attributes were modified for the memory region.
  @retval RETURN_ACCESS_DENIED     The attributes for the memory resource range specified by
                                   BaseAddress and Length cannot be modified.
  @retval RETURN_INVALID_PARAMETER Length is zero.
                                   Attributes specified an illegal combination of attributes that
                                   cannot be set together.
  @retval RETURN_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                   the memory resource range.
  @retval RETURN_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                   resource range specified by BaseAddress and Length.
                                   The bit mask of attributes is not support for the memory resource
                                   range specified by BaseAddress and Length.
**/
RETURN_STATUS
ConvertMemoryPageAttributes (
  IN  UINTN             PageTableBase,
  IN  PAGING_MODE       PagingMode,
  IN  PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64            Length,
  IN  UINT64            Attributes,
  IN  BOOLEAN           IsSet,
  OUT BOOLEAN           *IsModified   OPTIONAL
  )
{
  RETURN_STATUS         Status;
  IA32_MAP_ATTRIBUTE    PagingAttribute;
  IA32_MAP_ATTRIBUTE    PagingAttrMask;
  UINTN                 PageTableBufferSize;
  VOID                  *PageTableBuffer;
  EFI_PHYSICAL_ADDRESS  MaximumSupportMemAddress;
  BOOLEAN               WriteProtect;
  BOOLEAN               CetEnabled;
  BOOLEAN               UpdatedPageTable;

  UpdatedPageTable = TRUE;

  ASSERT (Attributes != 0);
  ASSERT ((Attributes & ~EFI_MEMORY_ATTRIBUTE_MASK) == 0);

  ASSERT ((BaseAddress & (SIZE_4KB - 1)) == 0);
  ASSERT ((Length & (SIZE_4KB - 1)) == 0);
  ASSERT (PageTableBase != 0);

  ASSERT (
    (mCoreInitializationComplete && mInternalCr3 == 0) ||
    (!mCoreInitializationComplete && mInternalCr3 != 0)
    );

  if (Length == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  MaximumSupportMemAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)(LShiftU64 (1, mPhysicalAddressBits) - 1);
  if (BaseAddress > MaximumSupportMemAddress) {
    return RETURN_UNSUPPORTED;
  }

  if (Length > MaximumSupportMemAddress) {
    return RETURN_UNSUPPORTED;
  }

  if ((Length != 0) && (BaseAddress > MaximumSupportMemAddress - (Length - 1))) {
    return RETURN_UNSUPPORTED;
  }

  if (IsModified != NULL) {
    *IsModified = FALSE;
  }

  PagingAttribute.Uint64 = 0;
  PagingAttribute.Uint64 = mAddressEncMask | BaseAddress;
  PagingAttrMask.Uint64  = 0;

  if ((Attributes & EFI_MEMORY_RO) != 0) {
    PagingAttrMask.Bits.ReadWrite = 1;
    if (IsSet) {
      PagingAttribute.Bits.ReadWrite = 0;
      PagingAttrMask.Bits.Dirty      = 1;
      // MU_CHANGE: MM_SUPV: Check to see if we are programming for a different CR3
      if ((mInternalCr3 != 0) || mIsShadowStack) {
        // Environment setup
        // ReadOnly page need set Dirty bit for shadow stack
        PagingAttribute.Bits.Dirty = 1;
        // MU_CHANGE: MM_SUPV: Ignoreing the following as it will mess with our access integrity
        // // Clear user bit for supervisor shadow stack
        // PagingAttribute.Bits.UserSupervisor = 0;
        // PagingAttrMask.Bits.UserSupervisor  = 1;
      } else {
        // Runtime update
        // Clear dirty bit for non shadow stack, to protect RO page.
        PagingAttribute.Bits.Dirty = 0;
      }
    } else {
      PagingAttribute.Bits.ReadWrite = 1;
    }
  }

  if ((Attributes & EFI_MEMORY_XP) != 0) {
    if (mXdSupported) {
      PagingAttribute.Bits.Nx = IsSet ? 1 : 0;
      PagingAttrMask.Bits.Nx  = 1;
    }
  }

  if ((Attributes & EFI_MEMORY_RP) != 0) {
    if (IsSet) {
      PagingAttribute.Bits.Present = 0;
      //
      // When map a range to non-present, all attributes except Present should not be provided.
      //
      PagingAttrMask.Uint64       = 0;
      PagingAttrMask.Bits.Present = 1;
    } else {
      //
      // When map range to present range, provide all attributes.
      //
      PagingAttribute.Bits.Present = 1;
      PagingAttrMask.Uint64        = MAX_UINT64;

      //
      // MU_CHANGE: MM_SUPV: Change default to supervisor access only
      // By default memory is Ring 0 accessble.
      //
      PagingAttribute.Bits.UserSupervisor = 0;
    }
  }

  if ((Attributes & EFI_MEMORY_SP) != 0) {
    // UINT64  UserSupervisor:1;         // 0 = Supervisor, 1=User
    PagingAttrMask.Bits.UserSupervisor = 1;
    if (IsSet) {
      // Clear user bit for supervisor attribute set request
      PagingAttribute.Bits.UserSupervisor = 0;
    } else {
      PagingAttribute.Bits.UserSupervisor = 1;
    }
  }

  if (PagingAttrMask.Uint64 == 0) {
    return RETURN_SUCCESS;
  }

  while (UpdatedPageTable) {
    PageTableBufferSize = 0;
    WRITE_UNPROTECT_RO_PAGES (WriteProtect, CetEnabled);
    Status = PageTableMap (&PageTableBase, PagingMode, NULL, &PageTableBufferSize, BaseAddress, Length, &PagingAttribute, &PagingAttrMask, IsModified);

    if (Status == RETURN_BUFFER_TOO_SMALL) {
      PageTableBuffer = AllocatePageTableMemory (EFI_SIZE_TO_PAGES (PageTableBufferSize), &UpdatedPageTable);
      if (PageTableBuffer == NULL) {
        DEBUG ((DEBUG_ERROR, "Failed to allocate page table memory for the page pool!\n"));
        ASSERT (PageTableBuffer != NULL);
        break; // We failed to allocate more memory so exit the loop and don't call into PageTableMap again
      }

      if (UpdatedPageTable) {
        // Need to check the PageTableMap again with the newly allocated pages
        continue;
      }

      Status = PageTableMap (&PageTableBase, PagingMode, PageTableBuffer, &PageTableBufferSize, BaseAddress, Length, &PagingAttribute, &PagingAttrMask, IsModified);
    } else {
      break; // In the off chance we don't return BUFFER_TOO_SMALL we need to exit the loop or be stuck
    }
  }

  WRITE_PROTECT_RO_PAGES (WriteProtect, CetEnabled);

  if (Status == RETURN_INVALID_PARAMETER) {
    //
    // The only reason that PageTableMap returns RETURN_INVALID_PARAMETER here is to modify other attributes
    // of a non-present range but remains the non-present range still as non-present.
    //
    DEBUG ((DEBUG_ERROR, "SMM ConvertMemoryPageAttributes: Only change EFI_MEMORY_XP/EFI_MEMORY_RO for non-present range in [0x%lx, 0x%lx] is not permitted\n", BaseAddress, BaseAddress + Length));
  }

  ASSERT_RETURN_ERROR (Status);
  ASSERT (PageTableBufferSize == 0);

  return RETURN_SUCCESS;
}

/**
  FlushTlb on current processor.

  @param[in,out] Buffer  Pointer to private data buffer.
**/
VOID
EFIAPI
FlushTlbOnCurrentProcessor (
  IN OUT VOID  *Buffer
  )
{
  CpuFlushTlb ();
}

/**
  FlushTlb for all processors.
**/
VOID
FlushTlbForAll (
  VOID
  )
{
  FlushTlbOnCurrentProcessor (NULL);
  InternalSmmStartupAllAPs (
    (EFI_AP_PROCEDURE2)FlushTlbOnCurrentProcessor,
    0,
    NULL,
    NULL,
    NULL
    );
}

/**
  This function sets the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]   PageTableBase    The page table base.
  @param[in]   PagingMode       The paging mode.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to set for the memory region.

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
  IN  PAGING_MODE           PagingMode,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsModified;

  Status = ConvertMemoryPageAttributes (PageTableBase, PagingMode, BaseAddress, Length, Attributes, TRUE, &IsModified);
  if (!EFI_ERROR (Status)) {
    if (IsModified) {
      //
      // Flush TLB as last step
      //
      FlushTlbForAll ();
    }
  }

  return Status;
}

/**
  This function clears the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]   PageTableBase    The page table base.
  @param[in]   PagingMode       The paging mode.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to clear for the memory region.

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
SmmClearMemoryAttributesEx (
  IN  UINTN                 PageTableBase,
  IN  PAGING_MODE           PagingMode,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsModified;

  Status = ConvertMemoryPageAttributes (PageTableBase, PagingMode, BaseAddress, Length, Attributes, FALSE, &IsModified);
  if (!EFI_ERROR (Status)) {
    if (IsModified) {
      //
      // Flush TLB as last step
      //
      FlushTlbForAll ();
    }
  }

  return Status;
}

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
                                The bit mask of attributes is not supported for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmSetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  )
{
  UINTN  PageTableBase;

  // MU_CHANGE: MM_SUPV: Use GetPageTable to get the page table base instead of reading from CR3 because we could be
  // using a different CR3 when initializing the environment.
  GetPageTable (&PageTableBase, NULL);
  return SmmSetMemoryAttributesEx (PageTableBase, mPagingMode, BaseAddress, Length, Attributes);
}

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
                                cannot be cleared together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not supported for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmClearMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  )
{
  UINTN  PageTableBase;

  // MU_CHANGE: MM_SUPV: Use GetPageTable to get the page table base instead of reading from CR3 because we could be
  // using a different CR3 when initializing the environment.
  GetPageTable (&PageTableBase, NULL);
  return SmmClearMemoryAttributesEx (PageTableBase, mPagingMode, BaseAddress, Length, Attributes);
}

/**
  Create page table based on input PagingMode, LinearAddress and Length.

  @param[in, out]  PageTable           The pointer to the page table.
  @param[in]       PagingMode          The paging mode.
  @param[in]       LinearAddress       The start of the linear address range.
  @param[in]       Length              The length of the linear address range.

**/
VOID
GenPageTable (
  IN OUT UINTN        *PageTable,
  IN     PAGING_MODE  PagingMode,
  IN     UINT64       LinearAddress,
  IN     UINT64       Length
  )
{
  RETURN_STATUS       Status;
  UINTN               PageTableBufferSize;
  VOID                *PageTableBuffer;
  IA32_MAP_ATTRIBUTE  MapAttribute;
  IA32_MAP_ATTRIBUTE  MapMask;

  MapMask.Uint64                   = MAX_UINT64;
  MapAttribute.Uint64              = mAddressEncMask|LinearAddress;
  MapAttribute.Bits.Present        = 1;
  MapAttribute.Bits.ReadWrite      = 1;
  MapAttribute.Bits.UserSupervisor = 1;
  MapAttribute.Bits.Accessed       = 1;
  MapAttribute.Bits.Dirty          = 1;
  PageTableBufferSize              = 0;
  // MU_CHANGE: MM_SUPV: Change default to NX
  MapAttribute.Bits.Nx = 1;

  Status = PageTableMap (
             PageTable,
             PagingMode,
             NULL,
             &PageTableBufferSize,
             LinearAddress,
             Length,
             &MapAttribute,
             &MapMask,
             NULL
             );
  if (Status == RETURN_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_INFO, "GenSMMPageTable: 0x%x bytes needed for initial SMM page table\n", PageTableBufferSize));
    PageTableBuffer = AllocatePageTableMemory (EFI_SIZE_TO_PAGES (PageTableBufferSize), NULL);
    ASSERT (PageTableBuffer != NULL);
    Status = PageTableMap (
               PageTable,
               PagingMode,
               PageTableBuffer,
               &PageTableBufferSize,
               LinearAddress,
               Length,
               &MapAttribute,
               &MapMask,
               NULL
               );
  }

  ASSERT (Status == RETURN_SUCCESS);
  ASSERT (PageTableBufferSize == 0);
}

/**
  Create page table based on input PagingMode and PhysicalAddressBits in smm.
  @param[in]      PagingMode           The paging mode.
  @param[in]      PhysicalAddressBits  The bits of physical address to map.
  @retval         PageTable Address
**/
UINTN
GenSmmPageTable (
  IN PAGING_MODE  PagingMode,
  IN UINT8        PhysicalAddressBits
  )
{
  UINTN          PageTable;
  RETURN_STATUS  Status;
  UINTN          GuardPage;
  UINTN          Index;
  UINT64         Length;
  PAGING_MODE    SmramPagingMode;

  PageTable = 0;
  Length    = LShiftU64 (1, PhysicalAddressBits);
  ASSERT (Length > mCpuHotPlugData.SmrrBase + mCpuHotPlugData.SmrrSize);

  if (sizeof (UINTN) == sizeof (UINT64)) {
    SmramPagingMode = m5LevelPagingNeeded ? Paging5Level4KB : Paging4Level4KB;
  } else {
    SmramPagingMode = PagingPae4KB;
  }

  ASSERT (mCpuHotPlugData.SmrrBase % SIZE_4KB == 0);
  ASSERT (mCpuHotPlugData.SmrrSize % SIZE_4KB == 0);
  GenPageTable (&PageTable, PagingMode, 0, mCpuHotPlugData.SmrrBase);

  //
  // Map smram range in 4K page granularity to avoid subsequent page split when smm ready to lock.
  // If BSP are splitting the 1G/2M paging entries to 512 2M/4K paging entries, and all APs are
  // still running in SMI at the same time, which might access the affected linear-address range
  // between the time of modification and the time of invalidation access. That will be a potential
  // problem leading exception happen.
  //
  GenPageTable (&PageTable, SmramPagingMode, mCpuHotPlugData.SmrrBase, mCpuHotPlugData.SmrrSize);

  GenPageTable (&PageTable, PagingMode, mCpuHotPlugData.SmrrBase + mCpuHotPlugData.SmrrSize, Length - mCpuHotPlugData.SmrrBase - mCpuHotPlugData.SmrrSize);

  if (mCoreInitializationComplete) {
    DEBUG ((DEBUG_ERROR, "%a Trying to generate a new page table after initialization!!!\n", __func__));
    ASSERT (!mCoreInitializationComplete);
    return 0;
  }

  SetPageTableBase (PageTable);

  if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
    //
    // Mark the 4KB guard page between known good stack and smm stack as non-present
    //
    for (Index = 0; Index < gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus; Index++) {
      GuardPage = mSmmStackArrayBase + PcdGet32 (PcdMmSupervisorExceptionStackSize) + Index * (mSmmStackSize + mSmmShadowStackSize);
      Status    = ConvertMemoryPageAttributes (PageTable, PagingMode, GuardPage, EFI_PAGE_SIZE, EFI_MEMORY_RP, TRUE, NULL);
      ASSERT (Status == RETURN_SUCCESS);
    }
  }

  // MU_CHANGE: MM_SUPV: Enable null pointer detection
  if (TRUE) {
    // if ((PcdGet8 (PcdNullPointerDetectionPropertyMask) & BIT1) != 0) {
    //
    // Mark [0, 4k] as non-present
    //
    Status = ConvertMemoryPageAttributes (PageTable, PagingMode, 0, SIZE_4KB, EFI_MEMORY_RP, TRUE, NULL);
    ASSERT (Status == RETURN_SUCCESS);
  }

  SetPageTableBase (0);

  return (UINTN)PageTable;
}

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
  )
{
  EFI_STATUS       Status;
  BOOLEAN          IsModified;
  IA32_DESCRIPTOR  Gdtr;
  UINTN            CpuIndex;
  UINTN            PageTableBase;
  BOOLEAN          EnablePML5Paging;

  AsmReadGdtr (&Gdtr);

  Status = SmmWhoAmI (NULL, &CpuIndex);
  ASSERT_EFI_ERROR (Status);

  ASSERT (Gdtr.Base == mGdtBuffer + CpuIndex * mGdtStepSize);
  ASSERT (Gdtr.Limit < mGdtStepSize);
  ASSERT (CpuIndex < mNumberOfCpus);
  ASSERT (mNumberOfCpus * mGdtStepSize == mGdtBufferSize);
  ASSERT ((mGdtStepSize & EFI_PAGE_MASK) == 0);

  GetPageTable (&PageTableBase, &EnablePML5Paging);

  Status = ConvertMemoryPageAttributes (
             PageTableBase,
             mPagingMode,
             mGdtBuffer + CpuIndex * mGdtStepSize,
             mGdtStepSize,
             EFI_MEMORY_RO | EFI_MEMORY_SP,
             TRUE,
             &IsModified
             );
  if (!EFI_ERROR (Status)) {
    if (IsModified) {
      //
      // Flush TLB for this CPU as last step
      //
      CpuFlushTlb ();
    }
  } else {
    ASSERT_EFI_ERROR (Status);
  }

  return Status;
}

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
  )
{
  EFI_STATUS       Status;
  BOOLEAN          IsModified;
  IA32_DESCRIPTOR  Gdtr;
  UINTN            CpuIndex;
  UINTN            PageTableBase;

  AsmReadGdtr (&Gdtr);

  Status = SmmWhoAmI (NULL, &CpuIndex);
  ASSERT_EFI_ERROR (Status);

  ASSERT (Gdtr.Base == mGdtBuffer + CpuIndex * mGdtStepSize);
  ASSERT (Gdtr.Limit < mGdtStepSize);
  ASSERT (CpuIndex < mNumberOfCpus);
  ASSERT (mNumberOfCpus * mGdtStepSize == mGdtBufferSize);
  ASSERT ((mGdtStepSize & EFI_PAGE_MASK) == 0);

  GetPageTable (&PageTableBase, NULL);
  Status = ConvertMemoryPageAttributes (
             PageTableBase,
             mPagingMode,
             mGdtBuffer + CpuIndex * mGdtStepSize,
             mGdtStepSize,
             EFI_MEMORY_RO,
             FALSE,
             &IsModified
             );
  if (!EFI_ERROR (Status)) {
    if (IsModified) {
      //
      // Flush TLB for this CPU as last step
      //
      CpuFlushTlb ();
    }
  } else {
    ASSERT_EFI_ERROR (Status);
  }

  return Status;
}

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
  )
{
  EFI_STATUS  Status;

  mIsShadowStack = TRUE;
  Status         = SmmSetMemoryAttributesEx (Cr3, mPagingMode, BaseAddress, Length, EFI_MEMORY_RO);
  mIsShadowStack = FALSE;

  return Status;
}

/**
  Retrieves a pointer to the system configuration table from the SMM System Table
  based on a specified GUID.

  @param[in]   TableGuid       The pointer to table's GUID type.
  @param[out]  Table           The pointer to the table associated with TableGuid in the EFI System Table.

  @retval EFI_SUCCESS     A configuration table matching TableGuid was found.
  @retval EFI_NOT_FOUND   A configuration table matching TableGuid could not be found.

**/
EFI_STATUS
EFIAPI
SmmGetSystemConfigurationTable (
  IN  EFI_GUID  *TableGuid,
  OUT VOID      **Table
  )
{
  UINTN  Index;

  ASSERT (TableGuid != NULL);
  ASSERT (Table != NULL);

  *Table = NULL;
  for (Index = 0; Index < gMmCoreMmst.NumberOfTableEntries; Index++) {
    if (CompareGuid (TableGuid, &(gMmCoreMmst.MmConfigurationTable[Index].VendorGuid))) {
      *Table = gMmCoreMmst.MmConfigurationTable[Index].VendorTable;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  This function sets SMM save state buffer to be RW and XP.
**/
VOID
PatchSmmSaveStateMap (
  VOID
  )
{
  UINTN  Index;
  UINTN  TileCodeSize;
  UINTN  TileDataSize;
  UINTN  TileSize;
  UINTN  PageTableBase;

  TileCodeSize = GetSmiHandlerSize ();
  TileCodeSize = ALIGN_VALUE (TileCodeSize, SIZE_4KB);
  TileDataSize = (SMRAM_SAVE_STATE_MAP_OFFSET - SMM_PSD_OFFSET) + sizeof (SMRAM_SAVE_STATE_MAP);
  TileDataSize = ALIGN_VALUE (TileDataSize, SIZE_4KB);
  TileSize     = TileDataSize + TileCodeSize - 1;
  TileSize     = 2 * GetPowerOfTwo32 ((UINT32)TileSize);

  GetPageTable (&PageTableBase, NULL);
  PageTableBase = PageTableBase & PAGING_4K_ADDRESS_MASK_64;

  DEBUG ((DEBUG_INFO, "PatchSmmSaveStateMap:\n"));
  for (Index = 0; Index < mMaxNumberOfCpus - 1; Index++) {
    //
    // Code
    //
    ConvertMemoryPageAttributes (
      PageTableBase,
      mPagingMode,
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET,
      TileCodeSize,
      EFI_MEMORY_RO | EFI_MEMORY_SP,
      TRUE,
      NULL
      );
    ConvertMemoryPageAttributes (
      PageTableBase,
      mPagingMode,
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET,
      TileCodeSize,
      EFI_MEMORY_XP,
      FALSE,
      NULL
      );

    //
    // Data
    //
    ConvertMemoryPageAttributes (
      PageTableBase,
      mPagingMode,
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET + TileCodeSize,
      TileSize - TileCodeSize,
      EFI_MEMORY_RO,
      FALSE,
      NULL
      );
    ConvertMemoryPageAttributes (
      PageTableBase,
      mPagingMode,
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET + TileCodeSize,
      TileSize - TileCodeSize,
      EFI_MEMORY_XP | EFI_MEMORY_SP,
      TRUE,
      NULL
      );
  }

  //
  // Code
  //
  ConvertMemoryPageAttributes (
    PageTableBase,
    mPagingMode,
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET,
    TileCodeSize,
    EFI_MEMORY_RO | EFI_MEMORY_SP,
    TRUE,
    NULL
    );
  ConvertMemoryPageAttributes (
    PageTableBase,
    mPagingMode,
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET,
    TileCodeSize,
    EFI_MEMORY_XP,
    FALSE,
    NULL
    );

  //
  // Data
  //
  ConvertMemoryPageAttributes (
    PageTableBase,
    mPagingMode,
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET + TileCodeSize,
    SIZE_32KB - TileCodeSize,
    EFI_MEMORY_RO,
    FALSE,
    NULL
    );
  ConvertMemoryPageAttributes (
    PageTableBase,
    mPagingMode,
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET + TileCodeSize,
    SIZE_32KB - TileCodeSize,
    EFI_MEMORY_XP | EFI_MEMORY_SP,
    TRUE,
    NULL
    );

  FlushTlbForAll ();
}

/**
  This function sets GDT/IDT buffer to be RO and XP.
**/
VOID
PatchGdtIdtMap (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  BaseAddress;
  UINTN                 Size;

  //
  // GDT
  //
  DEBUG ((DEBUG_INFO, "PatchGdtIdtMap - GDT:\n"));

  BaseAddress = mGdtBuffer;
  Size        = ALIGN_VALUE (mGdtBufferSize, SIZE_4KB);
  //
  // The range should have been set to RO
  // if it is allocated with EfiRuntimeServicesCode.
  //
  SmmSetMemoryAttributes (
    BaseAddress,
    Size,
    EFI_MEMORY_XP | EFI_MEMORY_SP
    );

  //
  // IDT
  //
  DEBUG ((DEBUG_INFO, "PatchGdtIdtMap - IDT:\n"));

  BaseAddress = gcSmiIdtr.Base;
  Size        = ALIGN_VALUE (gcSmiIdtr.Limit + 1, SIZE_4KB);
  //
  // The range should have been set to RO
  // if it is allocated with EfiRuntimeServicesCode.
  //
  SmmSetMemoryAttributes (
    BaseAddress,
    Size,
    EFI_MEMORY_XP | EFI_MEMORY_SP
    );
}

VOID
EFIAPI
PatchMmSupervisorCoreRegion (
  VOID
  )
{
  //
  // Patch MM Supervisor Core
  //
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "%a - Enter\n", __FUNCTION__));

  //
  // The range should have been set to RO/XP based on image record routines
  // this is the last pass that makes sure the entire region is still in
  // supervisor realm.
  //
  Status = SmmSetImagePageAttributes (mMmCoreDriverEntry, TRUE);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to set image attribute for MM core %r!!!\n", __FUNCTION__, Status));
    // We should not continue with this configuration, either hang the system or reboot
    ResetCold ();
    // Should not be here
    CpuDeadLoop ();
  }

  Status = SmmSetMemoryAttributes (
             mMmCoreDriverEntry->ImageBuffer,
             EFI_PAGES_TO_SIZE (mMmCoreDriverEntry->NumberOfPage),
             EFI_MEMORY_SP
             );

  if (FirmwarePolicy == NULL) {
    Status = EFI_SECURITY_VIOLATION;
    ASSERT (FALSE);
    return;
  }

  //
  // Mark firmware policy pages as supervisor read only
  // EFI_MEMORY_XP should be given as they are data pages
  //
  Status = SmmSetMemoryAttributes (
             (EFI_PHYSICAL_ADDRESS)(UINTN)FirmwarePolicy,
             (FirmwarePolicy->Size + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE -1),
             EFI_MEMORY_RO | EFI_MEMORY_SP
             );

  DEBUG ((DEBUG_INFO, "%a - Exit - %r\n", __FUNCTION__, Status));
}

VOID
PatchMmUserSpecialPurposeRegion (
  VOID
  )
{
  //
  // Patch MM Supervisor Prepared/Maintained user pages
  //
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "%a - Enter\n", __FUNCTION__));

  // Patch published hob list region to be CPL3, RO and XP
  if ((mMmHobStart == NULL) || (mMmHobSize == 0)) {
    DEBUG ((DEBUG_ERROR, "%a - Hob is not initialized!\n", __FUNCTION__));
    ASSERT (FALSE);
  }

  Status = SmmSetMemoryAttributes (
             (EFI_PHYSICAL_ADDRESS)(UINTN)mMmHobStart,
             (mMmHobSize + EFI_PAGE_MASK) & ~EFI_PAGE_MASK,
             (EFI_MEMORY_RO | EFI_MEMORY_XP)
             );
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_INFO, "%a - Exit - %r\n", __FUNCTION__, Status));
}

/**
  This function set [Base, Limit] to the input MemoryAttribute.
  @param  Base        Start address of range.
  @param  Limit       Limit address of range.
  @param  Attribute   The bit mask of attributes to modify for the memory region.
  @param  Map         Pointer to the array of Cr3 IA32_MAP_ENTRY.
  @param  Count       Count of IA32_MAP_ENTRY in Map.
**/
VOID
SetMemMapWithNonPresentRange (
  UINT64          Base,
  UINT64          Limit,
  UINT64          Attribute,
  IA32_MAP_ENTRY  *Map,
  UINTN           Count
  )
{
  UINTN   Index;
  UINT64  NonPresentRangeStart;

  NonPresentRangeStart = 0;
  for (Index = 0; Index < Count; Index++) {
    if ((Map[Index].LinearAddress > NonPresentRangeStart) &&
        (Base < Map[Index].LinearAddress) && (Limit > NonPresentRangeStart))
    {
      //
      // We should NOT set attributes for non-present range.
      //
      //
      // There is a non-present ( [NonPresentStart, Map[Index].LinearAddress] ) range before current Map[Index]
      // and it is overlapped with [Base, Limit].
      //
      if (Base < NonPresentRangeStart) {
        SmmSetMemoryAttributes (
          Base,
          NonPresentRangeStart - Base,
          Attribute
          );
      }

      Base = Map[Index].LinearAddress;
    }

    NonPresentRangeStart = Map[Index].LinearAddress + Map[Index].Length;
    if (NonPresentRangeStart >= Limit) {
      break;
    }
  }

  Limit = MIN (NonPresentRangeStart, Limit);

  if (Base < Limit) {
    //
    // There is no non-present range in current [Base, Limit] anymore.
    //
    SmmSetMemoryAttributes (
      Base,
      Limit - Base,
      Attribute
      );
  }
}

/**
  This function sets memory attribute according to MemoryAttributesTable.
**/
VOID
SetMemMapAttributes (
  VOID
  )
{
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapStart;
  UINTN                  MemoryMapEntryCount;
  UINTN                  DescriptorSize;
  UINTN                  Index;
  UINT64                 SupervisorMarker;
  UINTN                  PageTable;
  EFI_STATUS             Status;
  IA32_MAP_ENTRY         *Map;
  UINTN                  Count;
  UINT64                 MemoryAttribute;

  if ((mInitMemoryMap == NULL) ||
      (mInitMemoryMapSize == 0) ||
      (mInitDescriptorSize == 0))
  {
    DEBUG ((DEBUG_ERROR, "Initialization memory map not initialized!\n"));
    ASSERT (FALSE);
    return;
  }

  PERF_FUNCTION_BEGIN ();

  MemoryMapEntryCount = mInitMemoryMapSize/mInitDescriptorSize;
  DescriptorSize      = mInitDescriptorSize;
  MemoryMapStart      = mInitMemoryMap;
  MemoryMap           = MemoryMapStart;
  for (Index = 0; Index < MemoryMapEntryCount; Index++) {
    DEBUG ((DEBUG_INFO, "Entry (0x%x)\n", MemoryMap));
    DEBUG ((DEBUG_INFO, "  Type              - 0x%x\n", MemoryMap->Type));
    DEBUG ((DEBUG_INFO, "  PhysicalStart     - 0x%016lx\n", MemoryMap->PhysicalStart));
    DEBUG ((DEBUG_INFO, "  VirtualStart      - 0x%016lx\n", MemoryMap->VirtualStart));
    DEBUG ((DEBUG_INFO, "  NumberOfPages     - 0x%016lx\n", MemoryMap->NumberOfPages));
    DEBUG ((DEBUG_INFO, "  Attribute         - 0x%016lx\n", MemoryMap->Attribute));
    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, DescriptorSize);
  }

  Count = 0;
  Map   = NULL;
  // MU_CHANGE: MM_SUPV: Use GetPageTable to get the page table base instead of reading from CR3 because we could be
  // using a different CR3 when initializing the environment.
  GetPageTable (&PageTable, NULL);
  Status = PageTableParse (PageTable, mPagingMode, NULL, &Count);
  while (Status == RETURN_BUFFER_TOO_SMALL) {
    if (Map != NULL) {
      FreePool (Map);
    }

    Map = AllocatePool (Count * sizeof (IA32_MAP_ENTRY));
    ASSERT (Map != NULL);
    Status = PageTableParse (PageTable, mPagingMode, Map, &Count);
  }

  ASSERT_RETURN_ERROR (Status);

  MemoryMap = MemoryMapStart;
  for (Index = 0; Index < MemoryMapEntryCount; Index++) {
    DEBUG ((DEBUG_VERBOSE, "SetAttribute: Memory Entry - 0x%lx, 0x%x\n", MemoryMap->PhysicalStart, MemoryMap->NumberOfPages));
    if (MemoryMap->Attribute & EFI_MEMORY_SP) {
      SupervisorMarker = EFI_MEMORY_SP;
    } else {
      SupervisorMarker = 0;
    }

    MemoryAttribute = MemoryMap->Attribute & (EFI_MEMORY_ACCESS_MASK | EFI_MEMORY_SP);
    if (MemoryAttribute == 0) {
      if (MemoryMap->Type == EfiRuntimeServicesCode) {
        MemoryAttribute = EFI_MEMORY_RO | SupervisorMarker;
      } else {
        ASSERT ((MemoryMap->Type == EfiRuntimeServicesData) || (MemoryMap->Type == EfiConventionalMemory));
        //
        // Set other type memory as NX.
        //
        MemoryAttribute = EFI_MEMORY_XP | SupervisorMarker;
      }
    }

    //
    // There may exist non-present range overlaps with the MemoryMap range.
    // Do not change other attributes of non-present range while still remaining it as non-present
    //
    SetMemMapWithNonPresentRange (
      MemoryMap->PhysicalStart,
      MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE ((UINTN)MemoryMap->NumberOfPages),
      MemoryAttribute,
      Map,
      Count
      );

    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, DescriptorSize);
  }

  FreePool (Map);

  PatchSmmSaveStateMap ();
  PatchGdtIdtMap ();
  PatchMmSupervisorCoreRegion ();
  PatchMmUserSpecialPurposeRegion ();

  PERF_FUNCTION_END ();
}

/**
  Return if a UEFI memory page should be marked as not present in SMM page table.
  If the memory map entries type is
  EfiLoaderCode/Data, EfiBootServicesCode/Data, EfiConventionalMemory,
  EfiUnusableMemory, EfiACPIReclaimMemory, return TRUE.
  Or return FALSE.

  @param[in]  MemoryMap              A pointer to the memory descriptor.

  @return TRUE  The memory described will be marked as not present in SMM page table.
  @return FALSE The memory described will not be marked as not present in SMM page table.
**/
BOOLEAN
IsUefiPageNotPresent (
  IN EFI_MEMORY_DESCRIPTOR  *MemoryMap
  )
{
  switch (MemoryMap->Type) {
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
    case EfiConventionalMemory:
    case EfiUnusableMemory:
    case EfiACPIReclaimMemory:
      return TRUE;
    default:
      return FALSE;
  }
}

/**
  Return if the Address is forbidden as SMM communication buffer.

  @param[in] Address the address to be checked

  @return TRUE  The address is forbidden as SMM communication buffer.
  @return FALSE The address is allowed as SMM communication buffer.
**/
BOOLEAN
IsSmmCommBufferForbiddenAddress (
  IN UINT64  Address
  )
{
  UINTN  Index;

  // In this function, we only unblock those regions that are intentionally left open
  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    if (mMmSupervisorAccessBuffer[Index].PhysicalStart != 0) {
      if ((Address >= mMmSupervisorAccessBuffer[Index].PhysicalStart) &&
          (Address < mMmSupervisorAccessBuffer[Index].PhysicalStart + EFI_PAGES_TO_SIZE ((UINTN)mMmSupervisorAccessBuffer[Index].NumberOfPages)))
      {
        return FALSE;
      }
    }
  }

  if ((Address >= (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommMailboxBufferStatus) &&
      (Address < (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommMailboxBufferStatus + ((sizeof (mMmCommMailboxBufferStatus) + EFI_PAGE_SIZE -1) & ~(EFI_PAGE_SIZE -1))))
  {
    return FALSE;
  }

  return TRUE;
}

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
  OUT UINT64                *Attributes
  )
{
  EFI_PHYSICAL_ADDRESS  Address;
  UINT64                *PageEntry;
  UINT64                MemAttr;
  PAGE_ATTRIBUTE        PageAttr;
  INT64                 Size;
  UINTN                 PageTableBase;
  BOOLEAN               EnablePML5Paging;
  EFI_STATUS            Status;   // MU_CHANGE: Avoid Length overflow for INT64

  if ((Length < SIZE_4KB) || (Attributes == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE Start: Avoid Length overflow for INT64
  // Size = (INT64)Length;
  Status = SafeUint64ToInt64 (Length, &Size);
  if (EFI_ERROR (Status)) {
    // Length above MAX_INT64 is unrealistic for evaluation as of today, directly fail here.
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE Ends
  MemAttr = (UINT64)-1;

  GetPageTable (&PageTableBase, &EnablePML5Paging);

  do {
    PageEntry = GetPageTableEntry (PageTableBase, EnablePML5Paging, BaseAddress, &PageAttr);
    if ((PageEntry == NULL) || (PageAttr == PageNone)) {
      return EFI_UNSUPPORTED;
    }

    //
    // If the memory range is cross page table boundary, make sure they
    // share the same attribute. Return EFI_NO_MAPPING if not.
    //
    *Attributes = GetAttributesFromPageEntry (PageEntry);
    if ((MemAttr != (UINT64)-1) && (*Attributes != MemAttr)) {
      return EFI_NO_MAPPING;
    }

    switch (PageAttr) {
      case Page4K:
        Address      = *PageEntry & ~mAddressEncMask & PAGING_4K_ADDRESS_MASK_64;
        Size        -= (SIZE_4KB - (BaseAddress - Address));
        BaseAddress += (SIZE_4KB - (BaseAddress - Address));
        break;

      case Page2M:
        Address      = *PageEntry & ~mAddressEncMask & PAGING_2M_ADDRESS_MASK_64;
        Size        -= SIZE_2MB - (BaseAddress - Address);
        BaseAddress += SIZE_2MB - (BaseAddress - Address);
        break;

      case Page1G:
        Address      = *PageEntry & ~mAddressEncMask & PAGING_1G_ADDRESS_MASK_64;
        Size        -= SIZE_1GB - (BaseAddress - Address);
        BaseAddress += SIZE_1GB - (BaseAddress - Address);
        break;

      default:
        return EFI_UNSUPPORTED;
    }

    MemAttr = *Attributes;
  } while (Size > 0);

  return EFI_SUCCESS;
}

/**
  Prototype for comparison function for any two element types.

  @param[in] Buffer1                  The pointer to first buffer.
  @param[in] Buffer2                  The pointer to second buffer.

  @retval 0                           Buffer1 equal to Buffer2.
  @return <0                          Buffer1 is less than Buffer2.
  @return >0                          Buffer1 is greater than Buffer2.
**/
STATIC
INTN
EFIAPI
CompareAddressPoint (
  IN CONST VOID  *Buffer1,
  IN CONST VOID  *Buffer2
  )
{
  if ((Buffer1 == NULL) || (Buffer2 == NULL)) {
    ASSERT (FALSE);
    // Cannot do much other than that...
    return 0;
  }

  // Address as the first order criteria
  if (((MEMORY_ADDRESS_POINT *)Buffer1)->Address !=
      ((MEMORY_ADDRESS_POINT *)Buffer2)->Address)
  {
    return (INTN)((MEMORY_ADDRESS_POINT *)Buffer1)->Address -
           ((MEMORY_ADDRESS_POINT *)Buffer2)->Address;
  }

  // Type as second order tiebreaker
  if (((MEMORY_ADDRESS_POINT *)Buffer1)->Type !=
      ((MEMORY_ADDRESS_POINT *)Buffer2)->Type)
  {
    return (INTN)((MEMORY_ADDRESS_POINT *)Buffer1)->Type -
           ((MEMORY_ADDRESS_POINT *)Buffer2)->Type;
  }

  DEBUG ((DEBUG_ERROR, "%a - Identical Address Point Detected!!!\n", __func__));
  DEBUG ((DEBUG_ERROR, "Address(0x%0lx) Type(0x%x)\n", ((MEMORY_ADDRESS_POINT *)Buffer1)->Address, ((MEMORY_ADDRESS_POINT *)Buffer1)->Type));

  // This should not happen that resource hob has 2 identical address points
  ASSERT (FALSE);
  return 0;
}

/**
  Helper function to determine if this descriptor needs to be part of overlap check routine.

  @param[out] ResourceDesc             Pointer to target resource descriptor.

  @retval TRUE                        This type will be ignored for memory management purpose.
  @retval FALSE                       This resource descriptor will be added to memory management list during scanning.
**/
BOOLEAN
SkipResourceDescriptor (
  EFI_HOB_RESOURCE_DESCRIPTOR  *ResourceDesc
  )
{
  if ((ResourceDesc == NULL) ||
      (ResourceDesc->ResourceType == EFI_RESOURCE_IO) ||
      (ResourceDesc->ResourceType == EFI_RESOURCE_IO_RESERVED))
  {
    return TRUE;
  }

  return FALSE;
}

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length in bytes to be checked.

  @retval TRUE  This buffer is not part of MMRAM.
  @retval FALSE This buffer is from MMRAM.
**/
BOOLEAN
EFIAPI
IsBufferInsideMmram (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  UINTN                 Index;
  EFI_PHYSICAL_ADDRESS  TempBufferAddress;
  UINT64                TempRemainingLength;

  TempBufferAddress   = Buffer;
  TempRemainingLength = Length;
  Index               = 0;
  while (Index < mMmramRangeCount) {
    // if the range is fully immersive, the beginning has to belong to one of the MMRAM ranges
    if ((TempBufferAddress >= mMmramRanges[Index].CpuStart) && (TempBufferAddress < mMmramRanges[Index].CpuStart + mMmramRanges[Index].PhysicalSize)) {
      // The beginning overlaps with this MMRAM
      TempBufferAddress = mMmramRanges[Index].CpuStart + mMmramRanges[Index].PhysicalSize;
      if (TempRemainingLength > mMmramRanges[Index].PhysicalSize) {
        TempRemainingLength = TempRemainingLength - mMmramRanges[Index].PhysicalSize;
        // We reset the index here in case of MMRAM info is not sorted
        Index = 0;
        continue;
      } else {
        // All consumed, we can bail here
        return TRUE;
      }
    }

    Index++;
  }

  return FALSE;
}

/**
  Helper function to coalesce memory and MMRAM resources from hob.

  @param[out] MemAddrBuffer           Pointer to hold returned memory address point buffer, caller is
                                      responsible for freeing the memory after use.
  @param[out] Count                   Pointer to hold count of address points from returned buffer.

  @retval EFI_SUCCESS                 The hob overcheck passed without errors.
  @retval EFI_INVALID_PARAMETER       Input argument contains null pointer.
  @retval EFI_OUT_OF_RESOURCES        Cannot allocate enough resource to hold coalesced memory data.
**/
EFI_STATUS
CoalesceHobMemory (
  OUT MEMORY_ADDRESS_POINT  **MemAddrBuffer,
  OUT UINTN                 *Count
  )
{
  EFI_HOB_RESOURCE_DESCRIPTOR  *ResourceDescriptor;
  EFI_PEI_HOB_POINTERS         Hob;
  UINTN                        Index;
  UINTN                        MmIndex;
  MEMORY_ADDRESS_POINT         *TempBuffer;

  if ((Count == NULL) || (MemAddrBuffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Index              = mMmramRangeCount;
  Hob.Raw            = GetHobList ();
  ResourceDescriptor = NULL;

  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR2) {
      ResourceDescriptor = &Hob.ResourceDescriptorV2->V1;
    } else if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      ResourceDescriptor = Hob.ResourceDescriptor;
    }

    if ((ResourceDescriptor != NULL) && !SkipResourceDescriptor (ResourceDescriptor)) {
      Index++;
    }

    ResourceDescriptor = NULL;
    Hob.Raw            = GET_NEXT_HOB (Hob);
  }

  TempBuffer = AllocateZeroPool (sizeof (MEMORY_ADDRESS_POINT) * Index * 2);
  if (TempBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // This is dumb, let me know if you have better ways...
  Index   = 0;
  Hob.Raw = GetHobList ();
  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR2) {
      ResourceDescriptor = &Hob.ResourceDescriptorV2->V1;
    } else if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      ResourceDescriptor = Hob.ResourceDescriptor;
    }

    if ((ResourceDescriptor != NULL) && !SkipResourceDescriptor (ResourceDescriptor)) {
      DEBUG ((
        DEBUG_INFO,
        "%a - MemoryResource - Start(0x%0lx) Length(0x%0lx) Type(0x%x)\n",
        __FUNCTION__,
        ResourceDescriptor->PhysicalStart,
        ResourceDescriptor->ResourceLength,
        ResourceDescriptor->ResourceType
        ));
      TempBuffer[Index].Address     = ResourceDescriptor->PhysicalStart;
      TempBuffer[Index + 1].Address = ResourceDescriptor->PhysicalStart + ResourceDescriptor->ResourceLength;
      if ((ResourceDescriptor->ResourceType == EFI_RESOURCE_MEMORY_MAPPED_IO) ||
          (ResourceDescriptor->ResourceType == EFI_RESOURCE_FIRMWARE_DEVICE))
      {
        TempBuffer[Index].Type     = SPECIAL_RANGE_START;
        TempBuffer[Index + 1].Type = SPECIAL_RANGE_END;
      } else {
        TempBuffer[Index].Type     = DXE_RANGE_START;
        TempBuffer[Index + 1].Type = DXE_RANGE_END;
      }

      Index += 2;
    }

    ResourceDescriptor = NULL;
    Hob.Raw            = GET_NEXT_HOB (Hob);
  }

  ASSERT (mMmramRanges != NULL);
  for (MmIndex = 0; MmIndex < mMmramRangeCount; MmIndex++) {
    DEBUG ((
      DEBUG_INFO,
      "%a - MMRAM - Start(0x%0lx) Length(0x%0lx)\n",
      __FUNCTION__,
      mMmramRanges[MmIndex].PhysicalStart,
      mMmramRanges[MmIndex].PhysicalSize
      ));
    TempBuffer[Index].Address = mMmramRanges[MmIndex].PhysicalStart;
    TempBuffer[Index].Type    = SMM_RANGE_START;
    Index++;
    TempBuffer[Index].Address = mMmramRanges[MmIndex].PhysicalStart + mMmramRanges[MmIndex].PhysicalSize;
    TempBuffer[Index].Type    = SMM_RANGE_END;
    Index++;
  }

  // Sort all the address points we have found
  PerformQuickSort (TempBuffer, Index, sizeof (MEMORY_ADDRESS_POINT), CompareAddressPoint);

  *Count         = Index;
  *MemAddrBuffer = TempBuffer;

  return EFI_SUCCESS;
}

/*
Helper function to mark all non SMM memory ranges reported through hobs as non present
*/
VOID
EFIAPI
SetNonSmmMemMapAttributes (
  VOID
  )
{
  UINTN                                MemIdx;
  UINTN                                Index;
  MEMORY_ADDRESS_POINT                 *TempBuffer;
  EFI_STATUS                           Status;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockRegionParams;
  EFI_PHYSICAL_ADDRESS                 MaximumSupportMemAddress;

  TempBuffer = NULL;
  Status     = CoalesceHobMemory (&TempBuffer, &MemIdx);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Coalesce hob memory overlap failed, unable to proceed - %r\n", __FUNCTION__, Status));
    goto Exit;
  }

  if ((MemIdx == 0) || (MemIdx & BIT0)) {
    // Should not happen
    DEBUG ((DEBUG_ERROR, "%a - Memory resources has odd number of ends - 0x%x\n", __FUNCTION__, MemIdx));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Initialize the starting instance of memory address point
  if ((TempBuffer[0].Type == DXE_RANGE_END) ||
      (TempBuffer[0].Type == SMM_RANGE_END) ||
      (TempBuffer[0].Type == SPECIAL_RANGE_END))
  {
    Status = EFI_SECURITY_VIOLATION;
    DEBUG ((DEBUG_ERROR, "%a - Memory resources starts with 'END' type - %r\n", __FUNCTION__, Status));
    goto Exit;
  }

  // Brute force coverage extension, this portion covers range from 0 to first published hob
  if (TempBuffer[0].Address != 0) {
    Status = SmmSetMemoryAttributes (0, TempBuffer[0].Address, EFI_MEMORY_RP);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - Marking memory region 0 - 0x%x failed - %r\n", __FUNCTION__, TempBuffer[0].Address, Status));
      goto Exit;
    }
  }

  // Interate through the TempBuffer now
  // The rules to pass the scanning:
  // 1. Non-MM region should not overlap with another non-MM region
  // 2. MM region should not overlap with another MM region
  // 3. Each MM range should belong to one and only one dxe range
  // 4. Lengths for all ranges should be EFI_PAGE_SIZE aligned
  for (Index = 1; Index < MemIdx; Index++) {
    switch (TempBuffer[Index].Type) {
      case DXE_RANGE_START:
        if ((TempBuffer[Index-1].Type != DXE_RANGE_END) &&
            (TempBuffer[Index-1].Type != SPECIAL_RANGE_END))
        {
          // A non-MM region starts after MMRAM or inside another region, should not happen...
          DEBUG ((
            DEBUG_ERROR,
            "%a - Non-MM memory region starts with 0x%p clashes with range 0x%p of type %x!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            TempBuffer[Index-1].Address,
            TempBuffer[Index-1].Type
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // Otherwise, new start from previous non MMRAM ends, mark the gap not present
        // because paging initialization might page everything as RW...
        if (TempBuffer[Index].Address > TempBuffer[Index-1].Address) {
          // No need to set RP if reported memory resources are not contiguous
          DEBUG ((
            DEBUG_INFO,
            "%a - Mark Non-SMM Pages - Start(0x%0lx) Length(0x%0lx)\n",
            __FUNCTION__,
            TempBuffer[Index-1].Address,
            TempBuffer[Index].Address - TempBuffer[Index-1].Address
            ));
          Status = SmmSetMemoryAttributes (
                     TempBuffer[Index-1].Address,
                     TempBuffer[Index].Address - TempBuffer[Index-1].Address,
                     EFI_MEMORY_RP
                     );
          if (EFI_ERROR (Status)) {
            goto Exit;
          }
        }

        break;
      case SMM_RANGE_START:
        if ((TempBuffer[Index-1].Type != DXE_RANGE_START) &&
            (TempBuffer[Index-1].Type != SMM_RANGE_END))
        {
          // Either SMM not starting inside a DXE region, or overlaps with over MMRAM, should not happen...
          DEBUG ((
            DEBUG_ERROR,
            "%a - MMRAM memory region starts with 0x%p clashes with range 0x%p of type %x!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            TempBuffer[Index-1].Address,
            TempBuffer[Index-1].Type
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // Either normal DXE range needs to end here or gap between MMRAMs, mark it not present
        if (TempBuffer[Index].Address > TempBuffer[Index-1].Address) {
          // No need to set RP if this MMRAM is at the beginning of DXE range or end of previous MMRAM
          DEBUG ((
            DEBUG_INFO,
            "%a - Mark Non-SMM Pages - Start(0x%0lx) Length(0x%0lx)\n",
            __FUNCTION__,
            TempBuffer[Index-1].Address,
            TempBuffer[Index].Address - TempBuffer[Index-1].Address
            ));
          Status = SmmSetMemoryAttributes (
                     TempBuffer[Index-1].Address,
                     TempBuffer[Index].Address - TempBuffer[Index-1].Address,
                     EFI_MEMORY_RP
                     );
          if (EFI_ERROR (Status)) {
            goto Exit;
          }
        }

        // Check the following entry as well
        if ((Index + 1 >= MemIdx) || (TempBuffer[Index+1].Type != SMM_RANGE_END)) {
          // A single MMRAM region is not consistent in resource type
          DEBUG ((
            DEBUG_ERROR,
            "%a - MMRAM memory region starts with 0x%p clashes with range at index 0x%x before ending!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            Index+1
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // Then we can fall through into SMM_RANGE_END case
        Index++;
      case SMM_RANGE_END:
        if (TempBuffer[Index-1].Type != SMM_RANGE_START) {
          // Special region has suspicious start...
          DEBUG ((
            DEBUG_ERROR,
            "%a - MMRAM region ends at 0x%p has suspicious start addr 0x%p, type 0x%x!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            TempBuffer[Index-1].Address,
            TempBuffer[Index-1].Type
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        break;
      case DXE_RANGE_END:
        if ((TempBuffer[Index-1].Type != DXE_RANGE_START) &&
            (TempBuffer[Index-1].Type != SMM_RANGE_END))
        {
          // DXE region ends after unexpected memory resource type, should not happen...
          DEBUG ((
            DEBUG_ERROR,
            "%a - DXE memory region ends at 0x%p after unexpected memory resource type %x!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            TempBuffer[Index-1].Type
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // DXE range ends here, mark it not present from the previous point
        // It could be SMM end or DXE start.
        if ((TempBuffer[Index].Address > TempBuffer[Index-1].Address) ||
            (TempBuffer[Index-1].Type == DXE_RANGE_START))
        {
          // No need to set RP if MMRAM is at the end of this DXE range
          DEBUG ((
            DEBUG_INFO,
            "%a - Mark Non-SMM Pages - Start(0x%0lx) Length(0x%0lx)\n",
            __FUNCTION__,
            TempBuffer[Index-1].Address,
            TempBuffer[Index].Address - TempBuffer[Index-1].Address
            ));
          Status = SmmSetMemoryAttributes (
                     TempBuffer[Index-1].Address,
                     TempBuffer[Index].Address - TempBuffer[Index-1].Address,
                     EFI_MEMORY_RP
                     );
        }

        if (EFI_ERROR (Status)) {
          goto Exit;
        }

        break;
      case SPECIAL_RANGE_START:
        // Special range has to start after a non-MM end and followed by a special range end
        if (((TempBuffer[Index-1].Type != DXE_RANGE_END) &&
             (TempBuffer[Index-1].Type != SPECIAL_RANGE_END)) ||
            (Index+1 >= MemIdx) ||
            (TempBuffer[Index+1].Type != SPECIAL_RANGE_END))
        {
          // Special region has suspicious neighbors...
          DEBUG ((
            DEBUG_ERROR,
            "%a - Special region starts at 0x%p has suspicious neighbors of: 1. addr 0x%p, type 0x%x and 2. addr 0x%p, type 0x%x!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            TempBuffer[Index-1].Address,
            TempBuffer[Index-1].Type,
            TempBuffer[Index+1].Address,
            TempBuffer[Index+1].Type
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // There is a gap between a previous NON-MM range and this special range, mark it not present
        if (TempBuffer[Index].Address > TempBuffer[Index-1].Address) {
          // For the gap region following MMIO range, we round up the start and stick to the original end to align to EFI_PAGE_SIZE
          DEBUG ((
            DEBUG_INFO,
            "%a - Mark Non-SMM Pages - Start(0x%0lx) Length(0x%0lx)\n",
            __FUNCTION__,
            TempBuffer[Index-1].Address,
            TempBuffer[Index].Address - TempBuffer[Index-1].Address
            ));
          Status = SmmSetMemoryAttributes (
                     (TempBuffer[Index-1].Address + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE -1),
                     TempBuffer[Index].Address - ((TempBuffer[Index-1].Address + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE -1)),
                     EFI_MEMORY_RP
                     );
          if (EFI_ERROR (Status)) {
            goto Exit;
          }
        }

        Index++;
      // Fall through to SPECIAL_RANGE_END
      case SPECIAL_RANGE_END:
        if (TempBuffer[Index-1].Type != SPECIAL_RANGE_START) {
          // Special region has suspicious start...
          DEBUG ((
            DEBUG_ERROR,
            "%a - Special region ends at 0x%p has suspicious start addr 0x%p, type 0x%x!!!\n",
            __FUNCTION__,
            TempBuffer[Index].Address,
            TempBuffer[Index-1].Address,
            TempBuffer[Index-1].Type
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // MMIO range ends here, mark it not present first, since ProcessUnblockPages will only unblock blocked pages..
        // For the MMIO region, we stick to original start and round up the length to align to EFI_PAGE_SIZE
        DEBUG ((
          DEBUG_INFO,
          "%a - Mark MMIO Pages - Start(0x%0lx) Length(0x%0lx)\n",
          __FUNCTION__,
          TempBuffer[Index-1].Address,
          TempBuffer[Index].Address - TempBuffer[Index-1].Address
          ));
        Status = SmmSetMemoryAttributes (
                   TempBuffer[Index-1].Address,
                   (TempBuffer[Index].Address - TempBuffer[Index-1].Address + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE -1),
                   EFI_MEMORY_RP
                   );
        if (EFI_ERROR (Status)) {
          goto Exit;
        }

        ZeroMem (&UnblockRegionParams, sizeof (UnblockRegionParams));
        CopyMem (&UnblockRegionParams.IdentifierGuid, &gEfiCallerIdGuid, sizeof (EFI_GUID));
        UnblockRegionParams.MemoryDescriptor.PhysicalStart = TempBuffer[Index-1].Address;
        UnblockRegionParams.MemoryDescriptor.NumberOfPages = EFI_SIZE_TO_PAGES ((TempBuffer[Index].Address - TempBuffer[Index-1].Address + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE -1));
        Status                                             = ProcessUnblockPages (&UnblockRegionParams);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __FUNCTION__, Status));
          ASSERT (FALSE);
        }

        break;
      default:
        // Should not happen...
        Status = EFI_SECURITY_VIOLATION;
        ASSERT (FALSE);
        goto Exit;
    }
  }

  // If we get here safely, brutal force coverage extension again, this portion covers range from last entry to MaximumSupportMemAddress + 1
  MaximumSupportMemAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)(LShiftU64 (1, mPhysicalAddressBits) - 1);
  if (MaximumSupportMemAddress >= TempBuffer[MemIdx - 1].Address) {
    DEBUG ((DEBUG_INFO, "%a - Marking top of memory region 0x%lx - 0x%lx\n", __FUNCTION__, TempBuffer[MemIdx - 1].Address, MaximumSupportMemAddress + 1));
    Status = SmmSetMemoryAttributes (TempBuffer[MemIdx - 1].Address, MaximumSupportMemAddress - TempBuffer[MemIdx - 1].Address + 1, EFI_MEMORY_RP);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - Marking top of memory region 0x%lx - MaximumSupportMemAddress failed - %r\n", __FUNCTION__, TempBuffer[MemIdx - 1].Address, Status));
      goto Exit;
    }
  }

Exit:
  if (TempBuffer != NULL) {
    FreePool (TempBuffer);
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Some step in setting the non MMRAM memory has gone wrong - %r!!!\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    ResetCold ();
  }
}

/*
Helper function to mark common buffer range as accessible from inside MM
*/
EFI_STATUS
EFIAPI
SetCommonBufferRegionAttribute (
  VOID
  )
{
  EFI_STATUS                           Status;
  UINTN                                Index;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockRegionParams;

  ZeroMem (&UnblockRegionParams, sizeof (UnblockRegionParams));
  CopyMem (&UnblockRegionParams.IdentifierGuid, &gEfiCallerIdGuid, sizeof (EFI_GUID));

  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    // For the supervisor buffer communication buffer space
    if (mMmSupervisorAccessBuffer[Index].PhysicalStart == 0) {
      // For the supervisor communication buffer space
      ASSERT (mMmSupervisorAccessBuffer[Index].PhysicalStart != 0);
      Status = EFI_NOT_AVAILABLE_YET;
      goto Cleanup;
    } else {
      // Sanity check on the comm buffers and the mailbox data region
      if (InternalIsBufferOverlapped (
            (UINT8 *)mMmCommMailboxBufferStatus,
            sizeof (MM_COMM_BUFFER_STATUS),
            (UINT8 *)(UINTN)mMmSupervisorAccessBuffer[Index].PhysicalStart,
            EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages)
            ))
      {
        DEBUG ((DEBUG_ERROR, "%a - Communicate buffer overlaps with mailbox buffer with IPL!\n", __FUNCTION__));
        ASSERT_EFI_ERROR (Status);
        Status = EFI_SECURITY_VIOLATION;
        goto Cleanup;
      }

      // Remove RX set above
      CopyMem (&UnblockRegionParams.MemoryDescriptor, &mMmSupervisorAccessBuffer[Index], sizeof (EFI_MEMORY_DESCRIPTOR));
      Status = ProcessUnblockPages (&UnblockRegionParams);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __FUNCTION__, Status));
        ASSERT (FALSE);
        goto Cleanup;
      }
    }
  }

  // For the supervisor core private data that is shared with the IPL
  // TODO: really do not want this region to be accessible by the IPL, but what
  // is the difference if you will need it for common buffer anyway?
  // Remove RX set above
  ZeroMem (&UnblockRegionParams.MemoryDescriptor, sizeof (EFI_MEMORY_DESCRIPTOR));
  UnblockRegionParams.MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommMailboxBufferStatus;
  UnblockRegionParams.MemoryDescriptor.NumberOfPages = EFI_SIZE_TO_PAGES ((sizeof (mMmCommMailboxBufferStatus) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK));
  UnblockRegionParams.MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  UnblockRegionParams.MemoryDescriptor.Type          = EfiRuntimeServicesData;
  Status                                             = ProcessUnblockPages (&UnblockRegionParams);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __FUNCTION__, Status));
    ASSERT (FALSE);
  }

Cleanup:
  return Status;
}

/*
  Helper function to mark regions needs protection to be certain attributes, the implementation here will
  only impact platform measurement security level, so do it as non-blocking operation.
*/
EFI_STATUS
EFIAPI
SetProtectedRegionAttribute (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS  GuidHob;
  MM_PROT_REGION_HOB    *ProtRegionHob;
  EFI_STATUS            Status;

  GuidHob.Guid = GetFirstGuidHob (&gMmProtectedRegionHobGuid);
  while (GuidHob.Guid != NULL) {
    ProtRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);

    switch (ProtRegionHob->MmProtectedRegionType) {
      case MM_PROT_MMIO_IOMMU_T:
        DEBUG ((
          DEBUG_INFO,
          "%a - IOMMU region 0x%p of 0x%x pages\n",
          __FUNCTION__,
          ProtRegionHob->MmProtectedRegionAddr,
          ProtRegionHob->MmProtectedRegionPages
          ));

        Status = SmmClearMemoryAttributes (
                   ProtRegionHob->MmProtectedRegionAddr,
                   EFI_PAGES_TO_SIZE (ProtRegionHob->MmProtectedRegionPages),
                   EFI_MEMORY_RP | EFI_MEMORY_SP
                   );
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "%a - Failed to clear IOMMU region attributes - %r\n", __FUNCTION__, Status));
          ASSERT (FALSE);
        }

        Status = SmmSetMemoryAttributes (
                   ProtRegionHob->MmProtectedRegionAddr,
                   EFI_PAGES_TO_SIZE (ProtRegionHob->MmProtectedRegionPages),
                   EFI_MEMORY_RO | EFI_MEMORY_XP
                   );
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "%a - Failed to set IOMMU region attributes - %r\n", __FUNCTION__, Status));
          ASSERT (FALSE);
        }

        break;
      case MM_PROT_MMIO_SEC_BIO_T:
        DEBUG ((DEBUG_INFO, "%a - Secure Bio region found 0x%x\n", __FUNCTION__, ProtRegionHob->MmProtectedRegionType));
        Status = EFI_UNSUPPORTED;
        break;
      default:
        DEBUG ((DEBUG_ERROR, "%a - Unrecognized protected region type found 0x%x\n", __FUNCTION__, ProtRegionHob->MmProtectedRegionType));
        ASSERT (FALSE);
        Status = EFI_INVALID_PARAMETER;
        break;
    }

    if (EFI_ERROR (Status)) {
      break;
    }

    GuidHob.Guid = GET_NEXT_HOB (GuidHob);
    GuidHob.Guid = GetNextGuidHob (&gMmProtectedRegionHobGuid, GuidHob.Guid);
  }

  return Status;
}

/*
  Helper function to mark regions needs unblocking to corresponding attributes.
*/
EFI_STATUS
EFIAPI
SetUnblockRegionAttribute (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS                 GuidHob;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *UnblockRegionHob;
  EFI_STATUS                           Status;

  DEBUG ((DEBUG_INFO, "%a - Entry...\n", __FUNCTION__));
  Status       = EFI_SUCCESS;
  GuidHob.Guid = GetFirstGuidHob (&gMmUnblockRegionHobGuid);
  while (GuidHob.Guid != NULL) {
    UnblockRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);
    Status           = ProcessUnblockPages (UnblockRegionHob);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - Unblock region exits with error - %r\n", __FUNCTION__, Status));
      ASSERT (FALSE);
    }

    GuidHob.Guid = GET_NEXT_HOB (GuidHob);
    GuidHob.Guid = GetNextGuidHob (&gMmUnblockRegionHobGuid, GuidHob.Guid);
  }

  DEBUG ((DEBUG_INFO, "%a - Exit - %r\n", __FUNCTION__, Status));
  return Status;
}

/**
  Prevent the memory pages used for SMM page table from being overwritten.
**/
VOID
EnablePageTableProtection (
  VOID
  )
{
  PAGE_TABLE_POOL       *HeadPool;
  PAGE_TABLE_POOL       *Pool;
  UINT64                PoolSize;
  EFI_PHYSICAL_ADDRESS  Address;
  UINTN                 PageTableBase;

  if (mPageTablePool == NULL) {
    return;
  }

  GetPageTable (&PageTableBase, NULL);

  PageTableBase = PageTableBase & PAGING_4K_ADDRESS_MASK_64;

  //
  // ConvertMemoryPageAttributes might update mPageTablePool. It's safer to
  // remember original one in advance.
  //
  HeadPool = mPageTablePool;
  Pool     = HeadPool;
  do {
    Address  = (EFI_PHYSICAL_ADDRESS)(UINTN)Pool;
    PoolSize = Pool->Offset + EFI_PAGES_TO_SIZE (Pool->FreePages);
    //
    // Set entire pool including header, used-memory and left free-memory as ReadOnly in SMM page table.
    //
    ConvertMemoryPageAttributes (PageTableBase, mPagingMode, Address, PoolSize, EFI_MEMORY_RO | EFI_MEMORY_SP, TRUE, NULL);
    Pool = Pool->NextPool;
  } while (Pool != HeadPool);
}

/**
  Return whether memory used by SMM page table need to be set as Read Only.

  @retval TRUE  Need to set SMM page table as Read Only.
  @retval FALSE Do not set SMM page table as Read Only.
**/
BOOLEAN
IfReadOnlyPageTableNeeded (
  VOID
  )
{
  //
  // Don't mark page table memory as read-only if
  //  - no restriction on access to non-SMRAM memory; or
  //  - SMM heap guard feature enabled; or
  //      BIT2: SMM page guard enabled
  //      BIT3: SMM pool guard enabled
  //  - SMM profile feature enabled
  //
  if (!IsRestrictedMemoryAccess ()) {
    if (sizeof (UINTN) == sizeof (UINT64)) {
      //
      // Restriction on access to non-SMRAM memory and heap guard could not be enabled at the same time.
      //
      // MU_CHANGE START

      /*ASSERT (
        !(IsRestrictedMemoryAccess () &&
          (PcdGet8 (PcdHeapGuardPropertyMask) & (BIT3 | BIT2)) != 0)
        ); */
      ASSERT (
        !(IsRestrictedMemoryAccess () &&
          (gMmMps.HeapGuardPolicy.Fields.MmPageGuard | gMmMps.HeapGuardPolicy.Fields.MmPoolGuard) != 0)
        );
      // MU_CHANGE END
    }

    return FALSE;
  }

  return TRUE;
}

/**
  This function sets memory attribute for page table.
**/
VOID
SetPageTableAttributes (
  VOID
  )
{
  if (!IfReadOnlyPageTableNeeded ()) {
    return;
  }

  PERF_FUNCTION_BEGIN ();
  DEBUG ((DEBUG_INFO, "SetPageTableAttributes\n"));

  // Set memory used by page table as Read Only.
  DEBUG ((DEBUG_INFO, "Start...\n"));
  EnablePageTableProtection ();

  //
  // Enable write protection, after page table attribute updated.
  //
  // MU_CHANGE: MM_SUPV Starts: Need to restore CR0 when this routine is executed before
  // initialization complete.
  if (mCoreInitializationComplete) {
    //
    // Flush TLB after mark all page table pool as read only.
    //
    FlushTlbForAll ();
  }

  // MU_CHANGE: MM_SUPV Ends

  mIsReadOnlyPageTable = TRUE;

  PERF_FUNCTION_END ();
}
