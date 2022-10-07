/** @file
  SMM Memory pool management functions.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/MmMemoryProtectionHobLib.h> // MU_CHANGE

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "HeapGuard.h"

LIST_ENTRY  mMmSupvPoolLists[MmPoolTypeMax][MAX_POOL_INDEX];
//
// To cache the SMRAM base since when Loading modules At fixed address feature is enabled,
// all module is assigned an offset relative the SMRAM base in build time.
//
GLOBAL_REMOVE_IF_UNREFERENCED  EFI_PHYSICAL_ADDRESS  gLoadModuleAtFixAddressMmramBase = 0;

/**
  Convert a UEFI memory type to SMM pool type.

  @param[in]  MemoryType              Type of pool to allocate.

  @return SMM pool type
**/
MM_POOL_TYPE
UefiMemoryTypeToMmPoolType (
  IN  EFI_MEMORY_TYPE  MemoryType
  )
{
  ASSERT ((MemoryType == EfiRuntimeServicesCode) || (MemoryType == EfiRuntimeServicesData));
  switch (MemoryType) {
    case EfiRuntimeServicesCode:
      return MmPoolTypeCode;
    case EfiRuntimeServicesData:
      return MmPoolTypeData;
    default:
      return MmPoolTypeMax;
  }
}

/**
  Called to initialize the memory service.

  @param   MmramRangeCount       Number of SMRAM Regions
  @param   MmramRanges           Pointer to SMRAM Descriptors

**/
VOID
MmInitializeMemoryServices (
  IN UINTN                 MmramRangeCount,
  IN EFI_SMRAM_DESCRIPTOR  *MmramRanges
  )
{
  UINTN  Index;
  UINTN  MmPoolTypeIndex;

  //
  // Initialize Pool list
  //
  for (MmPoolTypeIndex = 0; MmPoolTypeIndex < MmPoolTypeMax; MmPoolTypeIndex++) {
    for (Index = 0; Index < ARRAY_SIZE (mMmSupvPoolLists[MmPoolTypeIndex]); Index++) {
      InitializeListHead (&mMmSupvPoolLists[MmPoolTypeIndex][Index]);
    }
  }

  //
  // Add Free SMRAM regions
  // Need add Free memory at first, to let gMmMemoryMap record data
  //
  for (Index = 0; Index < MmramRangeCount; Index++) {
    if ((MmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    MmAddMemoryRegion (
      MmramRanges[Index].CpuStart,
      MmramRanges[Index].PhysicalSize,
      EfiConventionalMemory,
      MmramRanges[Index].RegionState
      );
  }

  //
  // Add the allocated SMRAM regions
  //
  for (Index = 0; Index < MmramRangeCount; Index++) {
    if ((MmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) == 0) {
      continue;
    }

    MmAddMemoryRegion (
      MmramRanges[Index].CpuStart,
      MmramRanges[Index].PhysicalSize,
      EfiConventionalMemory,
      MmramRanges[Index].RegionState
      );
  }
}

/**
  Internal Function. Allocate a pool by specified PoolIndex.

  @param  PoolType              Type of pool to allocate.
  @param  PoolIndex             Index which indicate the Pool size.
  @param  FreePoolHdr           The returned Free pool.

  @retval EFI_OUT_OF_RESOURCES   Allocation failed.
  @retval EFI_SECURITY_VIOLATION Discrepencies are found in the ownership of free pool entries.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
InternalAllocPoolByIndex (
  IN  EFI_MEMORY_TYPE   PoolType,
  IN  UINTN             PoolIndex,
  OUT FREE_POOL_HEADER  **FreePoolHdr
  )
{
  EFI_STATUS            Status;
  FREE_POOL_HEADER      *Hdr;
  POOL_TAIL             *Tail;
  EFI_PHYSICAL_ADDRESS  Address;
  MM_POOL_TYPE          MmPoolType;
  LIST_ENTRY            *FLink;
  LIST_ENTRY            *BLink;
  BOOLEAN               IsUserRange;

  Address    = 0;
  MmPoolType = UefiMemoryTypeToMmPoolType (PoolType);

  ASSERT (PoolIndex <= MAX_POOL_INDEX);
  Status = EFI_SUCCESS;
  Hdr    = NULL;
  if (PoolIndex == MAX_POOL_INDEX) {
    Status = MmInternalAllocatePages (
               AllocateAnyPages,
               PoolType,
               EFI_SIZE_TO_PAGES (MAX_POOL_SIZE << 1),
               &Address,
               FALSE,
               TRUE
               );
    if (EFI_ERROR (Status)) {
      return EFI_OUT_OF_RESOURCES;
    }

    Hdr = (FREE_POOL_HEADER *)(UINTN)Address;
  } else if (!IsListEmpty (&mMmSupvPoolLists[MmPoolType][PoolIndex])) {
    Hdr = BASE_CR (GetFirstNode (&mMmSupvPoolLists[MmPoolType][PoolIndex]), FREE_POOL_HEADER, Link);
    if (mCoreInitializationComplete) {
      // Check Hdr represented memory region ownership before removing this link inline.
      if (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)Hdr, MIN_POOL_SIZE << PoolIndex, &IsUserRange)) ||
          (IsUserRange == TRUE))
      {
        ASSERT (FALSE);
        return EFI_SECURITY_VIOLATION;
      }

      // If not directly from mMmSupvPoolLists, check ForwardLink represented pool header ownership
      // before writing to this link inline.
      FLink = Hdr->Link.ForwardLink;
      if ((FLink != &mMmSupvPoolLists[MmPoolType][PoolIndex]) &&
          (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)FLink, sizeof (LIST_ENTRY), &IsUserRange)) ||
           (IsUserRange == TRUE)))
      {
        ASSERT (FALSE);
        return EFI_SECURITY_VIOLATION;
      }

      // If not directly from MmPoolLists, check BackLink represented pool header ownership
      // before writing to this link inline.
      BLink = Hdr->Link.BackLink;
      if ((BLink != &mMmSupvPoolLists[MmPoolType][PoolIndex]) &&
          (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)BLink, sizeof (LIST_ENTRY), &IsUserRange)) ||
           (IsUserRange == TRUE)))
      {
        ASSERT (FALSE);
        return EFI_SECURITY_VIOLATION;
      }
    }

    RemoveEntryList (&Hdr->Link);
  } else {
    Status = InternalAllocPoolByIndex (PoolType, PoolIndex + 1, &Hdr);
    if (!EFI_ERROR (Status)) {
      Hdr->Header.Signature = 0;
      Hdr->Header.Size    >>= 1;
      Hdr->Header.Available = TRUE;
      Hdr->Header.Type      = 0;
      Tail                  = HEAD_TO_TAIL (&Hdr->Header);
      Tail->Signature       = 0;
      Tail->Size            = 0;
      // If not directly from MmPoolLists, check ForwardLink represented pool header ownership
      // before writing to this link inline.
      if (mCoreInitializationComplete) {
        FLink = mMmSupvPoolLists[MmPoolType][PoolIndex].ForwardLink;
        if ((FLink != &mMmSupvPoolLists[MmPoolType][PoolIndex]) &&
            (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)FLink, sizeof (LIST_ENTRY), &IsUserRange)) ||
             (IsUserRange == TRUE)))
        {
          ASSERT (FALSE);
          return EFI_SECURITY_VIOLATION;
        }
      }

      InsertHeadList (&mMmSupvPoolLists[MmPoolType][PoolIndex], &Hdr->Link);
      Hdr = (FREE_POOL_HEADER *)((UINT8 *)Hdr + Hdr->Header.Size);
    }
  }

  if (!EFI_ERROR (Status)) {
    Hdr->Header.Signature = POOL_HEAD_SIGNATURE;
    Hdr->Header.Size      = MIN_POOL_SIZE << PoolIndex;
    Hdr->Header.Available = FALSE;
    Hdr->Header.Type      = PoolType;
    Tail                  = HEAD_TO_TAIL (&Hdr->Header);
    Tail->Signature       = POOL_TAIL_SIGNATURE;
    Tail->Size            = Hdr->Header.Size;
  }

  *FreePoolHdr = Hdr;
  return Status;
}

/**
  Internal Function. Free a pool by specified PoolIndex.

  @param  FreePoolHdr           The pool to free.
  @param  PoolTail              The pointer to the pool tail.

  @retval EFI_SUCCESS           Pool successfully freed.

**/
EFI_STATUS
InternalFreePoolByIndex (
  IN FREE_POOL_HEADER  *FreePoolHdr,
  IN POOL_TAIL         *PoolTail
  )
{
  UINTN         PoolIndex;
  MM_POOL_TYPE  MmPoolType;
  LIST_ENTRY    *FLink;
  BOOLEAN       IsUserRange;

  ASSERT ((FreePoolHdr->Header.Size & (FreePoolHdr->Header.Size - 1)) == 0);
  ASSERT (((UINTN)FreePoolHdr & (FreePoolHdr->Header.Size - 1)) == 0);
  ASSERT (FreePoolHdr->Header.Size >= MIN_POOL_SIZE);

  MmPoolType = UefiMemoryTypeToMmPoolType (FreePoolHdr->Header.Type);

  PoolIndex                     = (UINTN)(HighBitSet32 ((UINT32)FreePoolHdr->Header.Size) - MIN_POOL_SHIFT);
  FreePoolHdr->Header.Signature = 0;
  FreePoolHdr->Header.Available = TRUE;
  FreePoolHdr->Header.Type      = 0;
  PoolTail->Signature           = 0;
  PoolTail->Size                = 0;
  ASSERT (PoolIndex < MAX_POOL_INDEX);
  // If not directly from MmPoolLists, check ForwardLink represented pool header ownership
  // before writing to this link inline.
  if (mCoreInitializationComplete) {
    FLink = mMmSupvPoolLists[MmPoolType][PoolIndex].ForwardLink;
    if ((FLink != &mMmSupvPoolLists[MmPoolType][PoolIndex]) &&
        (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)FLink, sizeof (LIST_ENTRY), &IsUserRange)) ||
         (IsUserRange == TRUE)))
    {
      ASSERT (FALSE);
      return EFI_SECURITY_VIOLATION;
    }
  }

  InsertHeadList (&mMmSupvPoolLists[MmPoolType][PoolIndex], &FreePoolHdr->Link);
  return EFI_SUCCESS;
}

/**
  Allocate pool of a particular type.

  @param  PoolType               Type of pool to allocate.
  @param  Size                   The amount of pool to allocate.
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool.

  @retval EFI_INVALID_PARAMETER  PoolType not valid.
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
MmInternalAllocatePool (
  IN   EFI_MEMORY_TYPE  PoolType,
  IN   UINTN            Size,
  OUT  VOID             **Buffer
  )
{
  POOL_HEADER           *PoolHdr;
  POOL_TAIL             *PoolTail;
  FREE_POOL_HEADER      *FreePoolHdr;
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Address;
  UINTN                 PoolIndex;
  BOOLEAN               HasPoolTail;
  BOOLEAN               NeedGuard;
  BOOLEAN               IsUserRange;
  UINTN                 NoPages;

  Address = 0;

  if ((PoolType != EfiRuntimeServicesCode) &&
      (PoolType != EfiRuntimeServicesData))
  {
    return EFI_INVALID_PARAMETER;
  }

  NeedGuard   = IsPoolTypeToGuard (PoolType);
  HasPoolTail = !(NeedGuard &&
                  // MU_CHANGE START Update to use memory protection settings HOB
                  // ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));
                  gMmMps.HeapGuardPolicy.Fields.Direction == HEAP_GUARD_ALIGNED_TO_TAIL);
  // MU_CHANGE END

  //
  // Adjust the size by the pool header & tail overhead
  //
  Status = SafeUintnAdd (Size, POOL_OVERHEAD, &Size);
  if (EFI_ERROR (Status)) {
    // Calculation overflow, return out of resources in this case.
    return EFI_OUT_OF_RESOURCES;
  }

  if ((Size > MAX_POOL_SIZE) || NeedGuard) {
    if (!HasPoolTail) {
      Size -= sizeof (POOL_TAIL);
    }

    NoPages = EFI_SIZE_TO_PAGES (Size);
    Status  = MmInternalAllocatePages (
                AllocateAnyPages,
                PoolType,
                NoPages,
                &Address,
                NeedGuard,
                TRUE
                );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (NeedGuard) {
      ASSERT (VerifyMemoryGuard (Address, NoPages) == TRUE);
      Address = (EFI_PHYSICAL_ADDRESS)(UINTN)AdjustPoolHeadA (
                                               Address,
                                               NoPages,
                                               Size
                                               );
    }

    PoolHdr            = (POOL_HEADER *)(UINTN)Address;
    PoolHdr->Signature = POOL_HEAD_SIGNATURE;
    PoolHdr->Size      = EFI_PAGES_TO_SIZE (NoPages);
    PoolHdr->Available = FALSE;
    PoolHdr->Type      = PoolType;

    if (HasPoolTail) {
      PoolTail            = HEAD_TO_TAIL (PoolHdr);
      PoolTail->Signature = POOL_TAIL_SIGNATURE;
      PoolTail->Size      = PoolHdr->Size;
    }

    if (mCoreInitializationComplete) {
      if (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)PoolHdr, Size, &IsUserRange)) ||
          (IsUserRange == TRUE))
      {
        ASSERT (FALSE);
        return EFI_SECURITY_VIOLATION;
      }
    }

    *Buffer = PoolHdr + 1;
    return Status;
  }

  Size      = (Size + MIN_POOL_SIZE - 1) >> MIN_POOL_SHIFT;
  PoolIndex = (UINTN)HighBitSet32 ((UINT32)Size);
  if ((Size & (Size - 1)) != 0) {
    PoolIndex++;
  }

  Status = InternalAllocPoolByIndex (PoolType, PoolIndex, &FreePoolHdr);
  if (!EFI_ERROR (Status)) {
    // Before assigning pages, verify the candidate attributes not crossing boundary between user and supervisor
    if (mCoreInitializationComplete) {
      if (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr, FreePoolHdr->Header.Size, &IsUserRange)) ||
          (IsUserRange == TRUE))
      {
        ASSERT (FALSE);
        return EFI_SECURITY_VIOLATION;
      }
    }

    *Buffer = &FreePoolHdr->Header + 1;
  }

  return Status;
}

/**
  Allocate supervisor pool of a particular type.

  @param  PoolType               Type of pool to allocate.
  @param  Size                   The amount of pool to allocate.
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool.

  @retval EFI_INVALID_PARAMETER  PoolType not valid.
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
MmAllocateSupervisorPool (
  IN   EFI_MEMORY_TYPE  PoolType,
  IN   UINTN            Size,
  OUT  VOID             **Buffer
  )
{
  EFI_STATUS  Status;

  Status = MmInternalAllocatePool (PoolType, Size, Buffer);
  if (!EFI_ERROR (Status)) {
    // MmCoreUpdateProfile (
    //   (EFI_PHYSICAL_ADDRESS) (UINTN) RETURN_ADDRESS (0),
    //   MemoryProfileActionAllocatePool,
    //   PoolType,
    //   Size,
    //   *Buffer,
    //   NULL
    //   );
  }

  return Status;
}

/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free.

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
MmInternalFreePool (
  IN VOID  *Buffer
  )
{
  FREE_POOL_HEADER  *FreePoolHdr;
  POOL_TAIL         *PoolTail;
  BOOLEAN           HasPoolTail;
  BOOLEAN           MemoryGuarded;
  BOOLEAN           IsUserRange;

  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  FreePoolHdr = (FREE_POOL_HEADER *)((POOL_HEADER *)Buffer - 1);
  ASSERT (FreePoolHdr->Header.Signature == POOL_HEAD_SIGNATURE);
  ASSERT (!FreePoolHdr->Header.Available);
  if (FreePoolHdr->Header.Signature != POOL_HEAD_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  MemoryGuarded = IsHeapGuardEnabled () &&
                  IsMemoryGuarded ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr);
  HasPoolTail = !(MemoryGuarded &&
                  // MU_CHANGE START Update to use memory protection settings HOB
                  // ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));
                  gMmMps.HeapGuardPolicy.Fields.Direction == HEAP_GUARD_ALIGNED_TO_TAIL);
  // MU_CHANGE END

  if (HasPoolTail) {
    PoolTail = HEAD_TO_TAIL (&FreePoolHdr->Header);
    ASSERT (PoolTail->Signature == POOL_TAIL_SIGNATURE);
    ASSERT (FreePoolHdr->Header.Size == PoolTail->Size);
    if (PoolTail->Signature != POOL_TAIL_SIGNATURE) {
      return EFI_INVALID_PARAMETER;
    }

    if (FreePoolHdr->Header.Size != PoolTail->Size) {
      return EFI_INVALID_PARAMETER;
    }
  } else {
    PoolTail = NULL;
  }

  if (MemoryGuarded) {
    Buffer = AdjustPoolHeadF ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr);
    return MmInternalFreePages (
             (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer,
             EFI_SIZE_TO_PAGES (FreePoolHdr->Header.Size),
             TRUE,
             TRUE
             );
  }

  // Before freeing pool, verify the candidate attributes not crossing boundary between user and supervisor
  if (mCoreInitializationComplete) {
    if (EFI_ERROR (InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr, FreePoolHdr->Header.Size, &IsUserRange)) ||
        (IsUserRange == TRUE))
    {
      ASSERT (FALSE);
      return EFI_SECURITY_VIOLATION;
    }
  }

  if (FreePoolHdr->Header.Size > MAX_POOL_SIZE) {
    ASSERT (((UINTN)FreePoolHdr & EFI_PAGE_MASK) == 0);
    ASSERT ((FreePoolHdr->Header.Size & EFI_PAGE_MASK) == 0);
    return MmInternalFreePages (
             (EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr,
             EFI_SIZE_TO_PAGES (FreePoolHdr->Header.Size),
             FALSE,
             TRUE
             );
  }

  return InternalFreePoolByIndex (FreePoolHdr, PoolTail);
}

/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free.

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
MmFreeSupervisorPool (
  IN VOID  *Buffer
  )
{
  EFI_STATUS  Status;

  Status = MmInternalFreePool (Buffer);
  if (!EFI_ERROR (Status)) {
    // MmCoreUpdateProfile (
    //   (EFI_PHYSICAL_ADDRESS) (UINTN) RETURN_ADDRESS (0),
    //   MemoryProfileActionFreePool,
    //   EfiMaxMemoryType,
    //   0,
    //   Buffer,
    //   NULL
    //   );
  }

  return Status;
}
