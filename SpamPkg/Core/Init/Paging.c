/** @file
  STM paging

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "StmInit.h"
#include <Library/SafeIntLib.h>

#define BUS_FROM_PCIE_ADDRESS(PcieAddress)       (UINT8)(((UINTN)(PcieAddress) & 0x0FF00000) >> 20)
#define DEVICE_FROM_PCIE_ADDRESS(PcieAddress)    (UINT8)(((UINTN)(PcieAddress) & 0x000F8000) >> 15)
#define FUNCTION_FROM_PCIE_ADDRESS(PcieAddress)  (UINT8)(((UINTN)(PcieAddress) & 0x00007000) >> 12)
#define REGISTER_FROM_PCIE_ADDRESS(PcieAddress)  (UINT16)((UINTN)(PcieAddress) & 0x00000FFF)

#define PAGE_PROGATE_BITS  (BIT0 | BIT1 | BIT2 | BIT3 | BIT4 | BIT5)

#define PAGING_4K_MASK  0xFFF
#define PAGING_2M_MASK  0x1FFFFF
#define PAGING_1G_MASK  0x3FFFFFFF

#define PAGING_PAE_INDEX_MASK  0x1FF

#define PAGING_4K_ADDRESS_MASK_64  0x000FFFFFFFFFF000ull
#define PAGING_2M_ADDRESS_MASK_64  0x000FFFFFFFE00000ull
#define PAGING_1G_ADDRESS_MASK_64  0x000FFFFFC0000000ull

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

PAGE_ATTRIBUTE_TABLE  mPageAttributeTable[] = {
  { Page4K, SIZE_4KB, PAGING_4K_ADDRESS_MASK_64 },
  { Page2M, SIZE_2MB, PAGING_2M_ADDRESS_MASK_64 },
  { Page1G, SIZE_1GB, PAGING_1G_ADDRESS_MASK_64 },
};

/**
  Check if 1-GByte pages is supported by processor or not.

  @retval TRUE   1-GByte pages is supported.
  @retval FALSE  1-GByte pages is not supported.

**/
BOOLEAN
Is1GPageSupport (
  VOID
  )
{
  UINT32  RegEax;
  UINT32  RegEdx;

  AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
  if (RegEax >= 0x80000001) {
    AsmCpuid (0x80000001, NULL, NULL, NULL, &RegEdx);
    if ((RegEdx & BIT26) != 0) {
      return TRUE;
    }
  }

  return FALSE;
}

/**

  This function create page table for STM host.
  The SINIT/StmLoader should already configured 4G paging, so here
  we just create >4G paging for X64 mode.

**/
VOID
CreateHostPaging (
  VOID
  )
{
  UINTN   PageTable;
  UINTN   Index;
  UINTN   SubIndex;
  UINTN   Pml4Index;
  UINT64  *Pde;
  UINT64  *Pte;
  UINT64  *Pml4;
  UINT64  BaseAddress;
  UINTN   NumberOfPml4EntriesNeeded;
  UINTN   NumberOfPdpEntriesNeeded;

  if (sizeof (UINTN) == sizeof (UINT64)) {
    PageTable = AsmReadCr3 ();
    Pml4      = (UINT64 *)PageTable;

    if (mHostContextCommon.PhysicalAddressBits <= 39) {
      NumberOfPml4EntriesNeeded = 1;
      NumberOfPdpEntriesNeeded  = (UINTN)LShiftU64 (1, mHostContextCommon.PhysicalAddressBits - 30);
    } else {
      NumberOfPml4EntriesNeeded = (UINTN)LShiftU64 (1, mHostContextCommon.PhysicalAddressBits - 39);
      NumberOfPdpEntriesNeeded  = 512;
    }

    BaseAddress = BASE_4GB;
    for (Pml4Index = 0; Pml4Index < NumberOfPml4EntriesNeeded; Pml4Index++) {
      if (Pml4Index > 0) {
        Pde             = (UINT64 *)(UINTN)AllocatePages (1);
        Pml4[Pml4Index] = (UINT64)(UINTN)Pde | IA32_PG_P;
        Index           = 0;
      } else {
        // Start from 4G - Pml4[0] already allocated.
        Pde   = (UINT64 *)(UINTN)(Pml4[0] & 0xFFFFF000);
        Index = 4;
      }

      if (Is1GPageSupport ()) {
        for ( ; Index < NumberOfPdpEntriesNeeded; Index++) {
          Pde[Index]   = (UINT64)(UINTN)BaseAddress | IA32_PG_PS | IA32_PG_RW | IA32_PG_P;
          BaseAddress += SIZE_1GB;
        }
      } else {
        for ( ; Index < NumberOfPdpEntriesNeeded; Index++) {
          Pte        = (UINT64 *)AllocatePages (1);
          Pde[Index] = (UINT64)(UINTN)Pte | IA32_PG_P;

          for (SubIndex = 0; SubIndex < SIZE_4KB / sizeof (*Pte); SubIndex++) {
            Pte[SubIndex] = BaseAddress | IA32_PG_PS | IA32_PG_RW | IA32_PG_P;
            BaseAddress  += SIZE_2MB;
          }
        }
      }
    }
  }
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

  if (sizeof (UINTN) == sizeof (UINT64)) {
    if (Enable5LevelPaging) {
      L5PageTable = (UINT64 *)PageTableBase;
      if (L5PageTable[Index5] == 0) {
        *PageAttribute = PageNone;
        return NULL;
      }

      L4PageTable = (UINT64 *)(UINTN)(L5PageTable[Index5] & PAGING_4K_ADDRESS_MASK_64);
    } else {
      L4PageTable = (UINT64 *)PageTableBase;
    }

    if (L4PageTable[Index4] == 0) {
      *PageAttribute = PageNone;
      return NULL;
    }

    L3PageTable = (UINT64 *)(UINTN)(L4PageTable[Index4] & PAGING_4K_ADDRESS_MASK_64);
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

  L2PageTable = (UINT64 *)(UINTN)(L3PageTable[Index3] & PAGING_4K_ADDRESS_MASK_64);
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
  L1PageTable = (UINT64 *)(UINTN)(L2PageTable[Index2] & PAGING_4K_ADDRESS_MASK_64);
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

  if ((*PageEntry & IA32_PG_USR) == 0) {
    // UINT64  UserSupervisor:1;         // 0 = Supervisor, 1=User
    Attributes |= EFI_MEMORY_SP;
  }

  return Attributes;
}

/**
  This function retrieves the attributes of the memory region specified by
  BaseAddress and Length. If different attributes are got from different part
  of the memory region, EFI_NO_MAPPING will be returned.
  @param  PageTableBase     The base address of the page table.
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
GetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  PageTableBase,
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
  BOOLEAN               EnablePML5Paging;
  EFI_STATUS            Status;   // MU_CHANGE: Avoid Length overflow for INT64
  IA32_CR4              Cr4;

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

  Cr4.UintN         = AsmReadCr4 ();
  EnablePML5Paging  = (BOOLEAN)(Cr4.Bits.LA57 == 1);

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
        Address      = *PageEntry & PAGING_4K_ADDRESS_MASK_64;
        Size        -= (SIZE_4KB - (BaseAddress - Address));
        BaseAddress += (SIZE_4KB - (BaseAddress - Address));
        break;

      case Page2M:
        Address      = *PageEntry & PAGING_2M_ADDRESS_MASK_64;
        Size        -= SIZE_2MB - (BaseAddress - Address);
        BaseAddress += SIZE_2MB - (BaseAddress - Address);
        break;

      case Page1G:
        Address      = *PageEntry & PAGING_1G_ADDRESS_MASK_64;
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
