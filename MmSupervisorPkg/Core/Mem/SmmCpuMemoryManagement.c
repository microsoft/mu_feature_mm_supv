/** @file

Copyright (c) 2016 - 2019, Intel Corporation. All rights reserved.<BR>
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
#include "Policy/Policy.h"

//
// attributes for reserved memory before it is promoted to system memory
//
#define EFI_MEMORY_PRESENT      0x0100000000000000ULL
#define EFI_MEMORY_INITIALIZED  0x0200000000000000ULL
#define EFI_MEMORY_TESTED       0x0400000000000000ULL

#define PREVIOUS_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) - (Size)))

PAGE_ATTRIBUTE_TABLE  mPageAttributeTable[] = {
  { Page4K, SIZE_4KB, PAGING_4K_ADDRESS_MASK_64 },
  { Page2M, SIZE_2MB, PAGING_2M_ADDRESS_MASK_64 },
  { Page1G, SIZE_1GB, PAGING_1G_ADDRESS_MASK_64 },
};

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
EFI_MEMORY_DESCRIPTOR  *mInitMemoryMap     = NULL;
UINTN                  mInitDescriptorSize = 0;
UINTN                  mInitMemoryMapSize  = 0;

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
  Return length according to page attributes.

  @param[in]  PageAttributes   The page attribute of the page entry.

  @return The length of page entry.
**/
UINTN
PageAttributeToLength (
  IN PAGE_ATTRIBUTE  PageAttribute
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof (mPageAttributeTable)/sizeof (mPageAttributeTable[0]); Index++) {
    if (PageAttribute == mPageAttributeTable[Index].Attribute) {
      return (UINTN)mPageAttributeTable[Index].Length;
    }
  }

  return 0;
}

/**
  Return address mask according to page attributes.

  @param[in]  PageAttributes   The page attribute of the page entry.

  @return The address mask of page entry.
**/
UINTN
PageAttributeToMask (
  IN PAGE_ATTRIBUTE  PageAttribute
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof (mPageAttributeTable)/sizeof (mPageAttributeTable[0]); Index++) {
    if (PageAttribute == mPageAttributeTable[Index].Attribute) {
      return (UINTN)mPageAttributeTable[Index].AddressMask;
    }
  }

  return 0;
}

/**
  Return page table entry to match the address.

  @param[in]   Address          The address to be checked.
  @param[out]  PageAttributes   The page attribute of the page entry.

  @return The page entry.
**/
VOID *
GetPageTableEntry (
  IN  PHYSICAL_ADDRESS  Address,
  OUT PAGE_ATTRIBUTE    *PageAttribute
  )
{
  UINTN    Index1;
  UINTN    Index2;
  UINTN    Index3;
  UINTN    Index4;
  UINTN    Index5;
  UINT64   *L1PageTable;
  UINT64   *L2PageTable;
  UINT64   *L3PageTable;
  UINT64   *L4PageTable;
  UINT64   *L5PageTable;
  UINTN    PageTableBase;
  BOOLEAN  Enable5LevelPaging;

  GetPageTable (&PageTableBase, &Enable5LevelPaging);

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
  Modify memory attributes of page entry.

  @param[in]   PageEntry        The page entry.
  @param[in]   Attributes       The bit mask of attributes to modify for the memory region.
  @param[in]   IsSet            TRUE means to set attributes. FALSE means to clear attributes.
  @param[out]  IsModified       TRUE means page table modified. FALSE means page table not modified.
**/
VOID
ConvertPageEntryAttribute (
  IN  UINT64   *PageEntry,
  IN  UINT64   Attributes,
  IN  BOOLEAN  IsSet,
  OUT BOOLEAN  *IsModified
  )
{
  UINT64  CurrentPageEntry;
  UINT64  NewPageEntry;

  CurrentPageEntry = *PageEntry;
  NewPageEntry     = CurrentPageEntry;
  if ((Attributes & EFI_MEMORY_RP) != 0) {
    if (IsSet) {
      NewPageEntry &= ~(UINT64)IA32_PG_P;
    } else {
      NewPageEntry |= IA32_PG_P;
    }
  }

  if ((Attributes & EFI_MEMORY_RO) != 0) {
    if (IsSet) {
      NewPageEntry &= ~(UINT64)IA32_PG_RW;
      if (mInternalCr3 != 0) {
        // Environment setup
        // ReadOnly page need set Dirty bit for shadow stack
        NewPageEntry |= IA32_PG_D;
        // TODO: I have not idea what this bit is for the shadow stack...
        // // Clear user bit for supervisor shadow stack
        // NewPageEntry &= ~(UINT64)IA32_PG_U;
      } else {
        // Runtime update
        // Clear dirty bit for non shadow stack, to protect RO page.
        NewPageEntry &= ~(UINT64)IA32_PG_D;
      }
    } else {
      NewPageEntry |= IA32_PG_RW;
    }
  }

  if ((Attributes & EFI_MEMORY_XP) != 0) {
    if (mXdSupported) {
      if (IsSet) {
        NewPageEntry |= IA32_PG_NX;
      } else {
        NewPageEntry &= ~IA32_PG_NX;
      }
    }
  }

  if ((Attributes & EFI_MEMORY_SP) != 0) {
    // UINT64  UserSupervisor:1;         // 0 = Supervisor, 1=User
    if (IsSet) {
      // Clear user bit for supervisor shadow stack
      NewPageEntry &= ~(UINT64)IA32_PG_U;
    } else {
      NewPageEntry |= IA32_PG_U;
    }
  }

  *PageEntry = NewPageEntry;
  if (CurrentPageEntry != NewPageEntry) {
    *IsModified = TRUE;
    DEBUG ((DEBUG_VERBOSE, "ConvertPageEntryAttribute 0x%lx", CurrentPageEntry));
    DEBUG ((DEBUG_VERBOSE, "->0x%lx\n", NewPageEntry));
  } else {
    *IsModified = FALSE;
  }
}

/**
  This function returns if there is need to split page entry.

  @param[in]  BaseAddress      The base address to be checked.
  @param[in]  Length           The length to be checked.
  @param[in]  PageEntry        The page entry to be checked.
  @param[in]  PageAttribute    The page attribute of the page entry.

  @retval SplitAttributes on if there is need to split page entry.
**/
PAGE_ATTRIBUTE
NeedSplitPage (
  IN  PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64            Length,
  IN  UINT64            *PageEntry,
  IN  PAGE_ATTRIBUTE    PageAttribute
  )
{
  UINT64  PageEntryLength;

  PageEntryLength = PageAttributeToLength (PageAttribute);

  if (((BaseAddress & (PageEntryLength - 1)) == 0) && (Length >= PageEntryLength)) {
    return PageNone;
  }

  if (((BaseAddress & PAGING_2M_MASK) != 0) || (Length < SIZE_2MB)) {
    return Page4K;
  }

  return Page2M;
}

/**
  This function splits one page entry to small page entries.

  @param[in]  PageEntry        The page entry to be splitted.
  @param[in]  PageAttribute    The page attribute of the page entry.
  @param[in]  SplitAttribute   How to split the page entry.

  @retval RETURN_SUCCESS            The page entry is splitted.
  @retval RETURN_UNSUPPORTED        The page entry does not support to be splitted.
  @retval RETURN_OUT_OF_RESOURCES   No resource to split page entry.
**/
RETURN_STATUS
SplitPage (
  IN  UINT64          *PageEntry,
  IN  PAGE_ATTRIBUTE  PageAttribute,
  IN  PAGE_ATTRIBUTE  SplitAttribute
  )
{
  UINT64  BaseAddress;
  UINT64  *NewPageEntry;
  UINTN   Index;

  ASSERT (PageAttribute == Page2M || PageAttribute == Page1G);

  if (PageAttribute == Page2M) {
    //
    // Split 2M to 4K
    //
    ASSERT (SplitAttribute == Page4K);
    if (SplitAttribute == Page4K) {
      NewPageEntry = AllocateExtendedPageTableMemory (1);
      DEBUG ((DEBUG_VERBOSE, "Split - 0x%x\n", NewPageEntry));
      if (NewPageEntry == NULL) {
        return RETURN_OUT_OF_RESOURCES;
      }

      BaseAddress = *PageEntry & PAGING_2M_ADDRESS_MASK_64;
      for (Index = 0; Index < SIZE_4KB / sizeof (UINT64); Index++) {
        NewPageEntry[Index] = (BaseAddress + SIZE_4KB * Index) | mAddressEncMask | ((*PageEntry) & PAGE_PROGATE_BITS);
      }

      (*PageEntry) = (UINT64)(UINTN)NewPageEntry | mAddressEncMask | PAGE_ATTRIBUTE_BITS;
      return RETURN_SUCCESS;
    } else {
      return RETURN_UNSUPPORTED;
    }
  } else if (PageAttribute == Page1G) {
    //
    // Split 1G to 2M
    // No need support 1G->4K directly, we should use 1G->2M, then 2M->4K to get more compact page table.
    //
    ASSERT (SplitAttribute == Page2M || SplitAttribute == Page4K);
    if (((SplitAttribute == Page2M) || (SplitAttribute == Page4K))) {
      NewPageEntry = AllocateExtendedPageTableMemory (1);
      DEBUG ((DEBUG_VERBOSE, "Split - 0x%x\n", NewPageEntry));
      if (NewPageEntry == NULL) {
        return RETURN_OUT_OF_RESOURCES;
      }

      BaseAddress = *PageEntry & PAGING_1G_ADDRESS_MASK_64;
      for (Index = 0; Index < SIZE_4KB / sizeof (UINT64); Index++) {
        NewPageEntry[Index] = (BaseAddress + SIZE_2MB * Index) | mAddressEncMask | IA32_PG_PS | ((*PageEntry) & PAGE_PROGATE_BITS);
      }

      (*PageEntry) = (UINT64)(UINTN)NewPageEntry | mAddressEncMask | PAGE_ATTRIBUTE_BITS;
      return RETURN_SUCCESS;
    } else {
      return RETURN_UNSUPPORTED;
    }
  } else {
    return RETURN_UNSUPPORTED;
  }
}

/**
  This function modifies the page attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to modify for the memory region.
  @param[in]   IsSet            TRUE means to set attributes. FALSE means to clear attributes.
  @param[out]  IsSplitted       TRUE means page table splitted. FALSE means page table not splitted.
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
EFIAPI
ConvertMemoryPageAttributes (
  IN  PHYSICAL_ADDRESS BaseAddress,
  IN  UINT64 Length,
  IN  UINT64 Attributes,
  IN  BOOLEAN IsSet,
  OUT BOOLEAN *IsSplitted, OPTIONAL
  OUT BOOLEAN                           *IsModified   OPTIONAL
  )
{
  UINT64                *PageEntry;
  PAGE_ATTRIBUTE        PageAttribute;
  UINTN                 PageEntryLength;
  PAGE_ATTRIBUTE        SplitAttribute;
  RETURN_STATUS         Status;
  BOOLEAN               IsEntryModified;
  EFI_PHYSICAL_ADDRESS  MaximumSupportMemAddress;

  ASSERT (Attributes != 0);
  ASSERT ((Attributes & ~EFI_MEMORY_ATTRIBUTE_MASK) == 0);

  ASSERT ((BaseAddress & (SIZE_4KB - 1)) == 0);
  ASSERT ((Length & (SIZE_4KB - 1)) == 0);

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

  //  DEBUG ((DEBUG_ERROR, "ConvertMemoryPageAttributes(%x) - %016lx, %016lx, %02lx\n", IsSet, BaseAddress, Length, Attributes));

  if (IsSplitted != NULL) {
    *IsSplitted = FALSE;
  }

  if (IsModified != NULL) {
    *IsModified = FALSE;
  }

  //
  // Below logic is to check 2M/4K page to make sure we do not waste memory.
  //
  while (Length != 0) {
    PageEntry = GetPageTableEntry (BaseAddress, &PageAttribute);
    if (PageEntry == NULL) {
      return RETURN_UNSUPPORTED;
    }

    PageEntryLength = PageAttributeToLength (PageAttribute);
    SplitAttribute  = NeedSplitPage (BaseAddress, Length, PageEntry, PageAttribute);
    if (SplitAttribute == PageNone) {
      ConvertPageEntryAttribute (PageEntry, Attributes, IsSet, &IsEntryModified);
      if (IsEntryModified) {
        if (IsModified != NULL) {
          *IsModified = TRUE;
        }
      }

      //
      // Convert success, move to next
      //
      BaseAddress += PageEntryLength;
      Length      -= PageEntryLength;
    } else {
      Status = SplitPage (PageEntry, PageAttribute, SplitAttribute);
      if (RETURN_ERROR (Status)) {
        return RETURN_UNSUPPORTED;
      }

      if (IsSplitted != NULL) {
        *IsSplitted = TRUE;
      }

      if (IsModified != NULL) {
        *IsModified = TRUE;
      }

      //
      // Just split current page
      // Convert success in next around
      //
    }
  }

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
  UINTN  Index;

  FlushTlbOnCurrentProcessor (NULL);

  for (Index = 0; Index < gMmCoreMmst.NumberOfCpus; Index++) {
    if (Index != gMmCoreMmst.CurrentlyExecutingCpu) {
      // Force to start up AP in blocking mode,
      SmmBlockingStartupThisAp (FlushTlbOnCurrentProcessor, Index, NULL);
      // Do not check return status, because AP might not be present in some corner cases.
    }
  }
}

/**
  This function sets the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

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
EFIAPI
SmmSetMemoryAttributesEx (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes,
  OUT BOOLEAN               *IsSplitted  OPTIONAL
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsModified;

  Status = ConvertMemoryPageAttributes (BaseAddress, Length, Attributes, TRUE, IsSplitted, &IsModified);
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

  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to clear for the memory region.
  @param[out]  IsSplitted       TRUE means page table splitted. FALSE means page table not splitted.

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
SmmClearMemoryAttributesEx (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes,
  OUT BOOLEAN               *IsSplitted  OPTIONAL
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsModified;

  Status = ConvertMemoryPageAttributes (BaseAddress, Length, Attributes, FALSE, IsSplitted, &IsModified);
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
EFIAPI
SmmSetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  )
{
  return SmmSetMemoryAttributesEx (BaseAddress, Length, Attributes, NULL);
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
EFIAPI
SmmClearMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  )
{
  return SmmClearMemoryAttributesEx (BaseAddress, Length, Attributes, NULL);
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

  AsmReadGdtr (&Gdtr);

  Status = SmmWhoAmI (NULL, &CpuIndex);
  ASSERT_EFI_ERROR (Status);

  ASSERT (Gdtr.Base == mGdtBuffer + CpuIndex * mGdtStepSize);
  ASSERT (Gdtr.Limit < mGdtStepSize);
  ASSERT (CpuIndex < mNumberOfCpus);
  ASSERT (mNumberOfCpus * mGdtStepSize == mGdtBufferSize);
  ASSERT ((mGdtStepSize & EFI_PAGE_MASK) == 0);

  Status = ConvertMemoryPageAttributes (
             mGdtBuffer + CpuIndex * mGdtStepSize,
             mGdtStepSize,
             EFI_MEMORY_RO | EFI_MEMORY_SP,
             TRUE,
             NULL,
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

  AsmReadGdtr (&Gdtr);

  Status = SmmWhoAmI (NULL, &CpuIndex);
  ASSERT_EFI_ERROR (Status);

  ASSERT (Gdtr.Base == mGdtBuffer + CpuIndex * mGdtStepSize);
  ASSERT (Gdtr.Limit < mGdtStepSize);
  ASSERT (CpuIndex < mNumberOfCpus);
  ASSERT (mNumberOfCpus * mGdtStepSize == mGdtBufferSize);
  ASSERT ((mGdtStepSize & EFI_PAGE_MASK) == 0);

  Status = ConvertMemoryPageAttributes (
             mGdtBuffer + CpuIndex * mGdtStepSize,
             mGdtStepSize,
             EFI_MEMORY_RO,
             FALSE,
             NULL,
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

  SetPageTableBase (Cr3);

  Status = SmmSetMemoryAttributes (BaseAddress, Length, EFI_MEMORY_RO);

  SetPageTableBase (0);

  return Status;
}

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
  )
{
  EFI_STATUS  Status;

  SetPageTableBase (Cr3);

  Status = SmmSetMemoryAttributes (BaseAddress, Length, EFI_MEMORY_RP);

  SetPageTableBase (0);

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

  TileCodeSize = GetSmiHandlerSize ();
  TileCodeSize = ALIGN_VALUE (TileCodeSize, SIZE_4KB);
  TileDataSize = (SMRAM_SAVE_STATE_MAP_OFFSET - SMM_PSD_OFFSET) + sizeof (SMRAM_SAVE_STATE_MAP);
  TileDataSize = ALIGN_VALUE (TileDataSize, SIZE_4KB);
  TileSize     = TileDataSize + TileCodeSize - 1;
  TileSize     = 2 * GetPowerOfTwo32 ((UINT32)TileSize);

  DEBUG ((DEBUG_INFO, "PatchSmmSaveStateMap:\n"));
  for (Index = 0; Index < mMaxNumberOfCpus - 1; Index++) {
    //
    // Code
    //
    SmmSetMemoryAttributes (
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET,
      TileCodeSize,
      EFI_MEMORY_RO | EFI_MEMORY_SP
      );
    SmmClearMemoryAttributes (
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET,
      TileCodeSize,
      EFI_MEMORY_XP
      );

    //
    // Data
    //
    SmmClearMemoryAttributes (
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET + TileCodeSize,
      TileSize - TileCodeSize,
      EFI_MEMORY_RO
      );
    SmmSetMemoryAttributes (
      mCpuHotPlugData.SmBase[Index] + SMM_HANDLER_OFFSET + TileCodeSize,
      TileSize - TileCodeSize,
      EFI_MEMORY_XP | EFI_MEMORY_SP
      );
  }

  //
  // Code
  //
  SmmSetMemoryAttributes (
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET,
    TileCodeSize,
    EFI_MEMORY_RO | EFI_MEMORY_SP
    );
  SmmClearMemoryAttributes (
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET,
    TileCodeSize,
    EFI_MEMORY_XP
    );

  //
  // Data
  //
  SmmClearMemoryAttributes (
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET + TileCodeSize,
    SIZE_32KB - TileCodeSize,
    EFI_MEMORY_RO
    );
  SmmSetMemoryAttributes (
    mCpuHotPlugData.SmBase[mMaxNumberOfCpus - 1] + SMM_HANDLER_OFFSET + TileCodeSize,
    SIZE_32KB - TileCodeSize,
    EFI_MEMORY_XP | EFI_MEMORY_SP
    );
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

  if ((mInitMemoryMap == NULL) ||
      (mInitMemoryMapSize == 0) ||
      (mInitDescriptorSize == 0))
  {
    DEBUG ((DEBUG_ERROR, "Initialization memory map not initialized!\n"));
    ASSERT (FALSE);
    return;
  }

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

  MemoryMap = MemoryMapStart;
  for (Index = 0; Index < MemoryMapEntryCount; Index++) {
    DEBUG ((DEBUG_VERBOSE, "SetAttribute: Memory Entry - 0x%lx, 0x%x\n", MemoryMap->PhysicalStart, MemoryMap->NumberOfPages));
    if (MemoryMap->Attribute & EFI_MEMORY_SP) {
      SupervisorMarker = EFI_MEMORY_SP;
    } else {
      SupervisorMarker = 0;
    }

    switch (MemoryMap->Type) {
      case EfiRuntimeServicesCode:
        SmmSetMemoryAttributes (
          MemoryMap->PhysicalStart,
          EFI_PAGES_TO_SIZE ((UINTN)MemoryMap->NumberOfPages),
          EFI_MEMORY_RO | SupervisorMarker
          );
        break;
      case EfiRuntimeServicesData:
        SmmSetMemoryAttributes (
          MemoryMap->PhysicalStart,
          EFI_PAGES_TO_SIZE ((UINTN)MemoryMap->NumberOfPages),
          EFI_MEMORY_XP | SupervisorMarker
          );
        break;
      default:
        SmmSetMemoryAttributes (
          MemoryMap->PhysicalStart,
          EFI_PAGES_TO_SIZE ((UINTN)MemoryMap->NumberOfPages),
          EFI_MEMORY_XP | SupervisorMarker
          );
        break;
    }

    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, DescriptorSize);
  }

  PatchSmmSaveStateMap ();
  PatchGdtIdtMap ();
  PatchMmSupervisorCoreRegion ();
  PatchMmUserSpecialPurposeRegion ();

  return;
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

  if ((Address >= (EFI_PHYSICAL_ADDRESS)(UINTN)gMmCoreMailbox) &&
      (Address < (EFI_PHYSICAL_ADDRESS)(UINTN)gMmCoreMailbox + ((sizeof (MM_CORE_PRIVATE_DATA) + EFI_PAGE_SIZE -1) & ~(EFI_PAGE_SIZE -1))))
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

  do {
    PageEntry = GetPageTableEntry (BaseAddress, &PageAttr);
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

  Index   = mMmramRangeCount;
  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    ResourceDescriptor = (EFI_HOB_RESOURCE_DESCRIPTOR *)Hob.Raw;
    if (!SkipResourceDescriptor (ResourceDescriptor)) {
      Index++;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  TempBuffer = AllocateZeroPool (sizeof (MEMORY_ADDRESS_POINT) * Index * 2);
  if (TempBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // This is dumb, let me know if you have better ways...
  Index   = 0;
  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    ResourceDescriptor = (EFI_HOB_RESOURCE_DESCRIPTOR *)Hob.Raw;
    if (!SkipResourceDescriptor (ResourceDescriptor)) {
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

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
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
            (UINT8 *)gMmCoreMailbox,
            sizeof (MM_CORE_PRIVATE_DATA),
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
  UnblockRegionParams.MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)gMmCoreMailbox;
  UnblockRegionParams.MemoryDescriptor.NumberOfPages = EFI_SIZE_TO_PAGES ((sizeof (MM_CORE_PRIVATE_DATA) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK));
  UnblockRegionParams.MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
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
        Status = SmmSetMemoryAttributes (
                   ProtRegionHob->MmProtectedRegionAddr,
                   EFI_PAGES_TO_SIZE (ProtRegionHob->MmProtectedRegionPages),
                   EFI_MEMORY_RO | EFI_MEMORY_XP
                   );
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
