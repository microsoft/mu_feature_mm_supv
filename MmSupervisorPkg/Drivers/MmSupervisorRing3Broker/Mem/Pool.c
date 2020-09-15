/** @file
  SMM Memory pool management functions.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/SafeIntLib.h>
#include <Library/MmMemoryProtectionHobLib.h> // MU_CHANGE

#include "MmSupervisorRing3Broker.h"
#include "Mem.h"

LIST_ENTRY  mMmUserPoolLists[MmPoolTypeMax][MAX_POOL_INDEX];

//
// To cache the SMRAM base since when Loading modules At fixed address feature is enabled,
// all module is assigned an offset relative the SMRAM base in build time.
//
GLOBAL_REMOVE_IF_UNREFERENCED  EFI_PHYSICAL_ADDRESS  gLoadModuleAtFixAddressMmramBase = 0;

/**
  Check to see if the heap guard is enabled for page and/or pool allocation.

  @return TRUE/FALSE.
**/
BOOLEAN
IsPoolGuardEnabled (
  VOID
  )
{
  // MU_CHANGE START Update to work with memory protection settings HOB and
  // only check for pool guard settings
  return gMmMps.HeapGuardPolicy.Fields.MmPoolGuard;
  // return IsMemoryTypeToGuard (EfiMaxMemoryType, AllocateAnyPages,
  //                             GUARD_HEAP_TYPE_POOL|GUARD_HEAP_TYPE_PAGE);
  // MU_CHANGE END
}

/**
  Check to see if the memory at the given address should be guarded or not.

  @param[in]  MemoryType      Memory type to check.
  @param[in]  AllocateType    Allocation type to check.

  @return TRUE  The given type of memory should be guarded.
  @return FALSE The given type of memory should not be guarded.
**/
// MU_CHANGE Update to use memory protection settings HOB
BOOLEAN
IsMemoryTypeToGuard (
  IN EFI_MEMORY_TYPE    MemoryType,
  IN EFI_ALLOCATE_TYPE  AllocateType
  )
{
  //   UINT64 TestBit;
  //   UINT64 ConfigBit;

  //   if ((gMPS.HeapGuardPropertyMask & PageOrPool) == 0
  //       || mOnGuarding
  //       || AllocateType == AllocateAddress) {
  //     return FALSE;
  //   }
  // if (mOnGuarding || AllocateType == AllocateAddress) {
  //   return FALSE;
  // }
  //   ConfigBit = 0;
  //   if ((PageOrPool & GUARD_HEAP_TYPE_POOL) != 0) {
  //     ConfigBit |= PcdGet64 (PcdHeapGuardPoolType);
  //   }

  //   if ((PageOrPool & GUARD_HEAP_TYPE_PAGE) != 0) {
  //     ConfigBit |= PcdGet64 (PcdHeapGuardPageType);
  //   }

  //   if (MemoryType == EfiRuntimeServicesData ||
  //       MemoryType == EfiRuntimeServicesCode) {
  //     TestBit = LShiftU64 (1, MemoryType);
  //   } else if (MemoryType == EfiMaxMemoryType) {
  //     TestBit = (UINT64)-1;
  //   } else {
  //     TestBit = 0;
  //   }

  //   return ((ConfigBit & TestBit) != 0);
  if (gMmMps.HeapGuardPolicy.Fields.MmPoolGuard) {
    return GetMmMemoryTypeSettingFromBitfield (MemoryType, gMmMps.HeapGuardPoolType);
  }

  return FALSE;
}

// MU_CHANGE END

/**
  Adjust the pool head position to make sure the Guard page is adjacent to
  pool tail or pool head.

  @param[in]  Memory    Base address of memory allocated.
  @param[in]  NoPages   Number of pages actually allocated.
  @param[in]  Size      Size of memory requested.
                        (plus pool head/tail overhead)

  @return Address of pool head
**/
VOID *
AdjustPoolHeadA (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NoPages,
  IN UINTN                 Size
  )
{
  // MU_CHANGE START Update to use memory protection settings HOB
  // if (Memory == 0 || (PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) != 0) {
  if ((Memory == 0) || (gMmMps.HeapGuardPolicy.Fields.Direction == HEAP_GUARD_ALIGNED_TO_HEAD)) {
    // MU_CHANGE END
    //
    // Pool head is put near the head Guard
    //
    return (VOID *)(UINTN)Memory;
  }

  //
  // Pool head is put near the tail Guard
  //
  Size = ALIGN_VALUE (Size, 8);
  return (VOID *)(UINTN)(Memory + EFI_PAGES_TO_SIZE (NoPages) - Size);
}

/**
  Get the page base address according to pool head address.

  @param[in]  Memory    Head address of pool to free.

  @return Address of pool head.
**/
VOID *
AdjustPoolHeadF (
  IN EFI_PHYSICAL_ADDRESS  Memory
  )
{
  // MU_CHANGE START Update to use memory protection settings HOB
  // if (Memory == 0 || (PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) != 0) {
  if ((Memory == 0) || (gMmMps.HeapGuardPolicy.Fields.Direction == HEAP_GUARD_ALIGNED_TO_HEAD)) {
    // MU_CHANGE END
    //
    // Pool head is put near the head Guard
    //
    return (VOID *)(UINTN)Memory;
  }

  //
  // Pool head is put near the tail Guard
  //
  return (VOID *)(UINTN)(Memory & ~EFI_PAGE_MASK);
}

/**
  Check to see if the pool at the given address should be guarded or not.

  @param[in]  MemoryType      Pool type to check.

  @return TRUE  The given type of pool should be guarded.
  @return FALSE The given type of pool should not be guarded.
**/
BOOLEAN
IsPoolTypeToGuard (
  IN EFI_MEMORY_TYPE  MemoryType
  )
{
  return IsMemoryTypeToGuard (MemoryType, AllocateAnyPages);
}

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
**/
VOID
MmInitializeMemoryServices (
  VOID
  )
{
  UINTN  Index;
  UINTN  MmPoolTypeIndex;

  //
  // Initialize Pool list
  //
  for (MmPoolTypeIndex = 0; MmPoolTypeIndex < MmPoolTypeMax; MmPoolTypeIndex++) {
    for (Index = 0; Index < ARRAY_SIZE (mMmUserPoolLists[MmPoolTypeIndex]); Index++) {
      InitializeListHead (&mMmUserPoolLists[MmPoolTypeIndex][Index]);
    }
  }
}

/**
  Internal Function. Allocate a pool by specified PoolIndex.

  @param  PoolType              Type of pool to allocate.
  @param  PoolIndex             Index which indicate the Pool size.
  @param  FreePoolHdr           The returned Free pool.

  @retval EFI_OUT_OF_RESOURCES   Allocation failed.
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

  Address    = 0;
  MmPoolType = UefiMemoryTypeToMmPoolType (PoolType);

  ASSERT (PoolIndex <= MAX_POOL_INDEX);
  Status = EFI_SUCCESS;
  Hdr    = NULL;
  if (PoolIndex == MAX_POOL_INDEX) {
    Status = SyscallMmAllocatePages (
               AllocateAnyPages,
               PoolType,
               EFI_SIZE_TO_PAGES (MAX_POOL_SIZE << 1),
               &Address
               );
    if (EFI_ERROR (Status)) {
      return EFI_OUT_OF_RESOURCES;
    }

    Hdr = (FREE_POOL_HEADER *)(UINTN)Address;
  } else if (!IsListEmpty (&mMmUserPoolLists[MmPoolType][PoolIndex])) {
    Hdr = BASE_CR (GetFirstNode (&mMmUserPoolLists[MmPoolType][PoolIndex]), FREE_POOL_HEADER, Link);
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
      InsertHeadList (&mMmUserPoolLists[MmPoolType][PoolIndex], &Hdr->Link);
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
  InsertHeadList (&mMmUserPoolLists[MmPoolType][PoolIndex], &FreePoolHdr->Link);
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
    Status  = SyscallMmAllocatePages (
                AllocateAnyPages,
                PoolType,
                NoPages,
                &Address
                );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (NeedGuard) {
      // MU_CHANGE: MM_SUPV: Guard pages will be guaranteed by supervisor
      // ASSERT (VerifyMemoryGuard (Address, NoPages) == TRUE);
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
    *Buffer = &FreePoolHdr->Header + 1;
  }

  return Status;
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
MmAllocateUserPool (
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

  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE: TCBZ3488: Inspect guard page against header + buffer.
  // MemoryGuarded = IsHeapGuardEnabled () &&
  //                 IsMemoryGuarded ((EFI_PHYSICAL_ADDRESS)(UINTN)Buffer);
  // HasPoolTail   = !(MemoryGuarded &&
  //                   ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));
  // MU_CHANGE Ends: TCBZ3488

  FreePoolHdr = (FREE_POOL_HEADER *)((POOL_HEADER *)Buffer - 1);
  ASSERT (FreePoolHdr->Header.Signature == POOL_HEAD_SIGNATURE);
  ASSERT (!FreePoolHdr->Header.Available);
  if (FreePoolHdr->Header.Signature != POOL_HEAD_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE: TCBZ3488: Inspect guard page against header + buffer.
  MemoryGuarded = IsPoolGuardEnabled ();// &&
  // MU_CHANGE: MM_SUPV: Whether memory is guarded should always follow pool guard configuration.
  // IsMemoryGuarded ((EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr);
  HasPoolTail = !(MemoryGuarded &&
                  // MU_CHANGE START Update to use memory protection settings HOB
                  // ((PcdGet8 (PcdHeapGuardPropertyMask) & BIT7) == 0));
                  gMmMps.HeapGuardPolicy.Fields.Direction == HEAP_GUARD_ALIGNED_TO_TAIL);
  // MU_CHANGE END
  // MU_CHANGE Ends: TCBZ3488

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
    return SyscallMmFreePages (
             (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer,
             EFI_SIZE_TO_PAGES (FreePoolHdr->Header.Size)
             );
  }

  if (FreePoolHdr->Header.Size > MAX_POOL_SIZE) {
    ASSERT (((UINTN)FreePoolHdr & EFI_PAGE_MASK) == 0);
    ASSERT ((FreePoolHdr->Header.Size & EFI_PAGE_MASK) == 0);
    return SyscallMmFreePages (
             (EFI_PHYSICAL_ADDRESS)(UINTN)FreePoolHdr,
             EFI_SIZE_TO_PAGES (FreePoolHdr->Header.Size)
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
MmFreeUserPool (
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
