/** @file
Initial page table setup for X64 processors

Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Register/Cpuid.h>
#include <Protocol/MpService.h>
#include <Protocol/SmmConfiguration.h>

#include <Library/BaseLib.h>
#include <Library/SmmCpuPlatformHookLib.h>
#include <Library/ResetSystemLib.h> // MSCHANGE - Allow system to reset instead of halt in test mode.

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "SmmProfile.h"
#include "SmmProfileInternal.h"
#include "Relocate/Relocate.h"
#include "Services/CpuService/CpuService.h"
#include "Services/MpService/MpService.h"
#include "Telemetry/Telemetry.h"

#include <Library/MmMemoryProtectionHobLib.h> // MU_CHANGE

#define PAGE_TABLE_PAGES  8

LIST_ENTRY  mPagePool           = INITIALIZE_LIST_HEAD_VARIABLE (mPagePool);
BOOLEAN     m1GPageTableSupport = FALSE;
BOOLEAN     mCpuSmmRestrictedMemoryAccess;
UINT8       mPhysicalAddressBits;

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
  The routine returns TRUE when CPU supports it (CPUID[7,0].ECX.BIT[16] is set) and
  the max physical address bits is bigger than 48. Because 4-level paging can support
  to address physical address up to 2^48 - 1, there is no need to enable 5-level paging
  with max physical address bits <= 48.

  @retval TRUE  5-level paging enabling is needed.
  @retval FALSE 5-level paging enabling is not needed.
**/
BOOLEAN
Is5LevelPagingNeeded (
  VOID
  )
{
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX               VirPhyAddressSize;
  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_ECX  ExtFeatureEcx;
  UINT32                                       MaxExtendedFunctionId;

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunctionId, NULL, NULL, NULL);
  if (MaxExtendedFunctionId >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  AsmCpuidEx (
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS,
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO,
    NULL,
    NULL,
    &ExtFeatureEcx.Uint32,
    NULL
    );
  DEBUG ((
    DEBUG_INFO,
    "PhysicalAddressBits = %d, 5LPageTable = %d.\n",
    VirPhyAddressSize.Bits.PhysicalAddressBits,
    ExtFeatureEcx.Bits.FiveLevelPage
    ));

  if ((VirPhyAddressSize.Bits.PhysicalAddressBits > 4 * 9 + 12) &&
      (ExtFeatureEcx.Bits.FiveLevelPage == 1))
  {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
  Get page table base address and the depth of the page table.

  @param[out] Base        Page table base address.
  @param[out] FiveLevels  TRUE means 5 level paging. FALSE means 4 level paging.
**/
VOID
GetPageTable (
  OUT UINTN    *Base,
  OUT BOOLEAN  *FiveLevels OPTIONAL
  )
{
  IA32_CR4  Cr4;

  if (mSmmCr3 == 0) {
    *Base = AsmReadCr3 () & PAGING_4K_ADDRESS_MASK_64;
    if (FiveLevels != NULL) {
      Cr4.UintN   = AsmReadCr4 ();
      *FiveLevels = (BOOLEAN)(Cr4.Bits.LA57 == 1);
    }

    return;
  }

  *Base = mSmmCr3;
  if (FiveLevels != NULL) {
    *FiveLevels = m5LevelPagingNeeded;
  }
}

/**
  Set sub-entries number in entry.

  @param[in, out] Entry        Pointer to entry
  @param[in]      SubEntryNum  Sub-entries number based on 0:
                               0 means there is 1 sub-entry under this entry
                               0x1ff means there is 512 sub-entries under this entry

**/
VOID
SetSubEntriesNum (
  IN OUT UINT64  *Entry,
  IN     UINT64  SubEntryNum
  )
{
  //
  // Sub-entries number is saved in BIT52 to BIT60 (reserved field) in Entry
  //
  *Entry = BitFieldWrite64 (*Entry, 52, 60, SubEntryNum);
}

/**
  Calculate the maximum support address.

  @param[in] Is5LevelPagingNeeded    If 5-level paging enabling is needed.

  @return the maximum support address.
**/
UINT8
CalculateMaximumSupportAddress (
  BOOLEAN  Is5LevelPagingNeeded
  )
{
  UINT32  RegEax;
  UINT8   PhysicalAddressBits;
  VOID    *Hob;

  //
  // Get physical address bits supported.
  //
  Hob = GetFirstHob (EFI_HOB_TYPE_CPU);
  if (Hob != NULL) {
    PhysicalAddressBits = ((EFI_HOB_CPU *)Hob)->SizeOfMemorySpace;
  } else {
    AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
    if (RegEax >= 0x80000008) {
      AsmCpuid (0x80000008, &RegEax, NULL, NULL, NULL);
      PhysicalAddressBits = (UINT8)RegEax;
    } else {
      PhysicalAddressBits = 36;
    }
  }

  //
  // 4-level paging supports translating 48-bit linear addresses to 52-bit physical addresses.
  // Since linear addresses are sign-extended, the linear-address space of 4-level paging is:
  // [0, 2^47-1] and [0xffff8000_00000000, 0xffffffff_ffffffff].
  // So only [0, 2^47-1] linear-address range maps to the identical physical-address range when
  // 5-Level paging is disabled.
  //
  ASSERT (PhysicalAddressBits <= 52);
  if (!Is5LevelPagingNeeded && (PhysicalAddressBits > 47)) {
    PhysicalAddressBits = 47;
  }

  return PhysicalAddressBits;
}

/**
  Create PageTable for SMM use.

  @return The address of PML4 (to set CR3).

**/
UINT32
SmmInitPageTable (
  VOID
  )
{
  UINTN       PageTable;
  LIST_ENTRY  *FreePage;
  UINTN       Index;
  EFI_STATUS  Status;
  UINT64      *PdptEntry;
  UINT64      *Pml4Entry;
  UINT64      *Pml5Entry;
  UINT8       PhysicalAddressBits;

  //
  // Initialize spin lock
  //
  InitializeSpinLock (mPFLock);

  mCpuSmmRestrictedMemoryAccess = PcdGetBool (PcdCpuSmmRestrictedMemoryAccess);
  m1GPageTableSupport           = Is1GPageSupport ();
  m5LevelPagingNeeded           = Is5LevelPagingNeeded ();
  mPhysicalAddressBits          = CalculateMaximumSupportAddress (m5LevelPagingNeeded);

  if (m5LevelPagingNeeded) {
    mPagingMode = m1GPageTableSupport ? Paging5Level1GB : Paging5Level;
  } else {
    mPagingMode = m1GPageTableSupport ? Paging4Level1GB : Paging4Level;
  }

  DEBUG ((DEBUG_INFO, "5LevelPaging Needed             - %d\n", m5LevelPagingNeeded));
  DEBUG ((DEBUG_INFO, "1GPageTable Support             - %d\n", m1GPageTableSupport));
  DEBUG ((DEBUG_INFO, "PcdCpuSmmRestrictedMemoryAccess - %d\n", mCpuSmmRestrictedMemoryAccess));
  DEBUG ((DEBUG_INFO, "PhysicalAddressBits             - %d\n", mPhysicalAddressBits));
  //
  // Generate initial SMM page table.
  // Only map [0, 4G] when PcdCpuSmmRestrictedMemoryAccess is FALSE.
  //
  PhysicalAddressBits = mCpuSmmRestrictedMemoryAccess ? mPhysicalAddressBits : 32;
  PageTable           = GenSmmPageTable (mPagingMode, PhysicalAddressBits);

  if (m5LevelPagingNeeded) {
    Pml5Entry = (UINT64 *)PageTable;
    //
    // Set Pml5Entry sub-entries number for smm PF handler usage.
    //
    SetSubEntriesNum (Pml5Entry, 1);
    Pml4Entry = (UINT64 *)((*Pml5Entry) & ~mAddressEncMask & gPhyMask);
  } else {
    Pml4Entry = (UINT64 *)PageTable;
  }

  if (Pml4Entry == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  //
  // Set IA32_PG_PMNT bit to mask first 4 PdptEntry.
  //
  PdptEntry = (UINT64 *)((*Pml4Entry) & ~mAddressEncMask & gPhyMask);
  for (Index = 0; Index < 4; Index++) {
    PdptEntry[Index] |= IA32_PG_PMNT;
  }

  if (!mCpuSmmRestrictedMemoryAccess) {
    //
    // Set Pml4Entry sub-entries number for smm PF handler usage.
    //
    SetSubEntriesNum (Pml4Entry, 3);

    //
    // Add pages to page pool
    //
    FreePage = (LIST_ENTRY *)AllocatePageTableMemory (PAGE_TABLE_PAGES, NULL);
    if (FreePage == NULL) {
      DEBUG ((DEBUG_ERROR, "%a Failed to allocate page for FreePage!!!\n", __func__));
      Status = EFI_OUT_OF_RESOURCES;
      goto Cleanup;
    }

    for (Index = 0; Index < PAGE_TABLE_PAGES; Index++) {
      InsertTailList (&mPagePool, FreePage);
      FreePage += EFI_PAGE_SIZE / sizeof (*FreePage);
    }
  }

  //
  // Additional SMM IDT initialization for SMM stack guard
  //
  if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
    DEBUG ((DEBUG_INFO, "Initialize IDT IST field for SMM Stack Guard\n"));
    InitializeIdtIst (EXCEPT_IA32_PAGE_FAULT, 1);
  }

  //
  // Additional SMM IDT initialization for SMM CET shadow stack
  //
  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    DEBUG ((DEBUG_INFO, "Initialize IDT IST field for SMM Shadow Stack\n"));
    InitializeIdtIst (EXCEPT_IA32_PAGE_FAULT, 1);
    InitializeIdtIst (EXCEPT_IA32_MACHINE_CHECK, 1);
  }

  Status = EFI_SUCCESS;

Cleanup:
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    if (Pml4Entry != NULL) {
      FreePages (Pml4Entry, 1);
    }

    if (Pml5Entry != NULL) {
      FreePages (Pml5Entry, 1);
    }

    if (FreePage != NULL) {
      FreePages (FreePage, PAGE_TABLE_PAGES);
    }

    return 0;
  } else {
    //
    // Return the address of PML4/PML5 (to set CR3)
    //
    return (UINT32)PageTable;
  }
}

/**
  Return whether access to non-SMRAM is restricted.

  @retval TRUE  Access to non-SMRAM is restricted.
  @retval FALSE Access to non-SMRAM is not restricted.
**/
BOOLEAN
IsRestrictedMemoryAccess (
  VOID
  )
{
  return mCpuSmmRestrictedMemoryAccess;
}
