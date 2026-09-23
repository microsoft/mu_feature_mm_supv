/** @file
Construction of the MM Supervisor HOB list.

Owns every HOB the supervisor hands to the runtime: the copy of the inbound HOB
list, the module allocation HOBs, the pass down HOB, and the guided HOB
describing the final MMRAM layout (derived by walking the `gMemoryMap` list that
Page.c maintains, with allocated regions tagged EFI_ALLOCATED and gaps tagged
free).

Callers drive this through MM_SUPV_INIT_HOB_BUILDER: SupvInitHobsInit sizes and
allocates the region, the SupvInitHobsAdd* routines append to it as the data
they describe becomes available, and SupvInitHobsFinalize terminates the list.

Linked only into MmSupervisorInit: the runtime MmSupervisorCore driver consumes
this HOB list, it never builds one, so there is no _core.c counterpart.

Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Guid/SmramMemoryReserve.h>
#include <Guid/PassDown.h>
#include <Guid/DepexStruc.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/SecurePolicyLib.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"
#include "Relocate/Relocate.h"
#include "SupvInitHobs.h"

//
// Signature shared by the producers that report the bytes still available.
//
typedef
EFI_STATUS
(*MM_SUPV_HOB_PRODUCER) (
  IN     EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN OUT UINT64                *Length
  );

extern LIST_ENTRY           mDiscoveredList;
extern EFI_MM_DRIVER_ENTRY  *mMmUserDriverEntry;

//
// Every HOB is padded to an 8-byte boundary. These are the single source of
// truth for each HOB's footprint: the sizing pass and the writing pass must
// agree exactly or the cursor drifts, so neither open-codes the arithmetic.
//
#define MODULE_ALLOC_HOB_SIZE  ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8)
#define GUID_HOB_SIZE(DataSize)    ALIGN_VALUE (sizeof (EFI_HOB_GUID_TYPE) + (DataSize), 8)
#define DEPEX_HOB_SIZE(DepexSize)  GUID_HOB_SIZE (sizeof (MM_SUPV_DEPEX_HOB_DATA) + (DepexSize))

/**
  Move the builder past a HOB that consumed the given number of bytes.

  @param[in,out]  Builder   The HOB builder to advance.
  @param[in]      Consumed  Bytes written at the current cursor.
**/
STATIC
VOID
HobBuilderAdvance (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder,
  IN     UINT64                    Consumed
  )
{
  // Every HOB is padded to 8 bytes, so the cursor must stay aligned.
  ASSERT ((Consumed & 0x7) == 0);
  ASSERT (Consumed <= Builder->Remaining);

  Builder->Cursor    += Consumed;
  Builder->Remaining -= Consumed;
}

/**
  Helper function to append a GUIDed HOB at the cursor and hand back its (zeroed) data area.

  The caller is responsible for having verified there is room; this writes
  GUID_HOB_SIZE (DataSize) bytes and advances the cursor past them.

  @param[in,out]  Builder   HOB builder structure tracking the current cursor and remaining space.
  @param[in]      Name      GUID naming the HOB.
  @param[in]      DataSize  Bytes of payload to reserve after the header.

  @return  Pointer to the zeroed payload, immediately after the HOB header.
**/
STATIC
VOID *
HobAppendGuid (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder,
  IN     CONST EFI_GUID            *Name,
  IN     UINTN                     DataSize
  )
{
  EFI_HOB_GUID_TYPE  *GuidHob;
  UINTN              HobSize;
  VOID               *Data;

  if ((Builder == NULL) || (Builder->Remaining < GUID_HOB_SIZE (DataSize))) {
    return NULL;
  }

  HobSize = GUID_HOB_SIZE (DataSize);
  ASSERT (HobSize <= MAX_UINT16);

  GuidHob                   = (EFI_HOB_GUID_TYPE *)(UINTN)Builder->Cursor;
  GuidHob->Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  GuidHob->Header.HobLength = (UINT16)HobSize;
  GuidHob->Header.Reserved  = 0;
  CopyGuid (&GuidHob->Name, Name);

  // Clear the payload, including any tail padding, so nothing stale is published.
  Data = (VOID *)(GuidHob + 1);
  ZeroMem (Data, HobSize - sizeof (EFI_HOB_GUID_TYPE));

  HobBuilderAdvance (Builder, HobSize);

  return Data;
}

/**
  Helper function to append a memory allocation module HOB describing a loaded image.

  The caller is responsible for having verified there is room; this writes
  MODULE_ALLOC_HOB_SIZE bytes and advances the cursor past them.

  @param[in,out]  Cursor       Where to write. Advanced past the HOB on return.
  @param[in]      ModuleName   GUID identifying the module.
  @param[in]      DriverEntry  Entry supplying the image base, page count and entry point.
**/
STATIC
EFI_STATUS
HobAppendModuleAllocation (
  IN OUT MM_SUPV_INIT_HOB_BUILDER   *Builder,
  IN     CONST EFI_GUID             *ModuleName,
  IN     CONST EFI_MM_DRIVER_ENTRY  *DriverEntry
  )
{
  EFI_HOB_MEMORY_ALLOCATION_MODULE  *ModuleHob;

  if (Builder->Remaining < MODULE_ALLOC_HOB_SIZE) {
    return EFI_BUFFER_TOO_SMALL;
  }

  ModuleHob                   = (EFI_HOB_MEMORY_ALLOCATION_MODULE *)(UINTN)Builder->Cursor;
  ModuleHob->Header.HobType   = EFI_HOB_TYPE_MEMORY_ALLOCATION;
  ModuleHob->Header.HobLength = (UINT16)MODULE_ALLOC_HOB_SIZE;
  ModuleHob->Header.Reserved  = 0;

  CopyGuid (&ModuleHob->MemoryAllocationHeader.Name, &gMmSupervisorHobMemoryAllocModuleGuid);
  ModuleHob->MemoryAllocationHeader.MemoryBaseAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)DriverEntry->ImageBuffer;
  ModuleHob->MemoryAllocationHeader.MemoryLength      = EFI_PAGES_TO_SIZE (DriverEntry->NumberOfPage);
  ModuleHob->MemoryAllocationHeader.MemoryType        = EfiReservedMemoryType;
  ZeroMem (ModuleHob->MemoryAllocationHeader.Reserved, sizeof (ModuleHob->MemoryAllocationHeader.Reserved));

  CopyGuid (&ModuleHob->ModuleName, ModuleName);
  ModuleHob->EntryPoint = DriverEntry->ImageEntryPoint;

  HobBuilderAdvance (Builder, MODULE_ALLOC_HOB_SIZE);

  return EFI_SUCCESS;
}

/**
  Compute the total size of a HOB list, including its end-of-list header.

  @param[in]  HobStart  Start of the HOB list.

  @return  The size of the HOB list in bytes.
**/
STATIC
UINTN
GetHobListSize (
  IN VOID  *HobStart
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  ASSERT (HobStart != NULL);

  Hob.Raw = (UINT8 *)HobStart;
  while (!END_OF_HOB_LIST (Hob)) {
    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  //
  // Need plus END_OF_HOB_LIST
  //
  return (UINTN)Hob.Raw - (UINTN)HobStart + sizeof (EFI_HOB_GENERIC_HEADER);
}

/**
  Serialize the supervisor MMRAM layout into EFI_MMRAM_DESCRIPTORs.

  Walks the (already Start-sorted) supervisor memory map (gMemoryMap) against the
  MMRAM ranges (mMmramRanges), emitting one descriptor per allocated sub-region
  (runtime-services allocations, tagged EFI_ALLOCATED) and one per free gap. This
  is the shared core of PrepareRuntimeMmramHob' two passes:

    * Call with Descriptors == NULL to obtain the descriptor count (for sizing).
    * Call with a buffer sized for that count to populate it.

  The walk is deterministic, so both calls return the same count. gMemoryMap must
  already be sorted by Start address before calling.

  @param[out]  Descriptors  Optional buffer to receive the descriptors. When NULL,
                            the routine only counts and writes nothing.

  @return  The number of descriptors emitted (or that would be emitted).
**/
STATIC
UINT32
SerializeMmramDescriptors (
  OUT EFI_MMRAM_DESCRIPTOR  *Descriptors  OPTIONAL
  )
{
  LIST_ENTRY            *Link;
  MEMORY_MAP            *Entry;
  EFI_MMRAM_DESCRIPTOR  *MmramEntry;
  UINT32                Count;
  EFI_PHYSICAL_ADDRESS  Start;
  EFI_PHYSICAL_ADDRESS  End;
  EFI_PHYSICAL_ADDRESS  DescStart;
  EFI_PHYSICAL_ADDRESS  DescEnd;

  Count = 0;
  Link  = gMemoryMap.ForwardLink;

  for (UINTN Index = 0; Index < mMmramRangeCount; Index++) {
    MmramEntry = &mMmramRanges[Index];
    Start      = MmramEntry->PhysicalStart;
    End        = MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1;

    // Walk the sorted memory map entries that fall within this MMRAM region.
    while (Link != &gMemoryMap) {
      Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);

      if (Entry->Start > End) {
        // No more entries in this region
        break;
      }

      if (Entry->End < Start) {
        // The entry landed in a gap between MMRAM regions or outside MMRAM entirely.
        ASSERT (FALSE);
        Link = Link->ForwardLink;
        continue;
      }

      if (Start < Entry->Start) {
        // There is a gap before this entry, which is a free mmram region.
        if (Descriptors != NULL) {
          Descriptors[Count].CpuStart      = Start;
          Descriptors[Count].PhysicalStart = Start;
          Descriptors[Count].PhysicalSize  = Entry->Start - Start;
          Descriptors[Count].RegionState   = EFI_SMRAM_CLOSED | EFI_CACHEABLE;
        }

        Count++;
        Start = Entry->Start;
        // It is unexpected to have uncovered regions through memory map
        ASSERT (FALSE);
      }

      // The entry overlaps the current MMRAM region. A single memory map entry
      // can straddle adjacent MMRAM descriptors because the memory map merges
      // adjacent allocations of the same type, so clip it to the region bounds.
      if (Descriptors != NULL) {
        DescStart = MAX (Entry->Start, Start);
        DescEnd   = MIN (Entry->End, End);

        DEBUG ((
          DEBUG_INFO,
          "%a - Including Start: 0x%lx, End: 0x%lx, Type: 0x%x, IsSupervisorPage: %d\n",
          __func__,
          DescStart,
          DescEnd,
          Entry->Type,
          Entry->IsSupervisorPage
          ));
        Descriptors[Count].CpuStart      = DescStart;
        Descriptors[Count].PhysicalStart = DescStart;
        Descriptors[Count].PhysicalSize  = DescEnd - DescStart + 1;
        if ((Entry->Type == EfiRuntimeServicesCode) || (Entry->Type == EfiRuntimeServicesData)) {
          Descriptors[Count].RegionState = EFI_SMRAM_CLOSED | EFI_CACHEABLE | EFI_ALLOCATED;
        } else {
          // Should not happen
          Descriptors[Count].RegionState = EFI_SMRAM_CLOSED | EFI_CACHEABLE;
        }
      }

      Count++;

      if (Entry->End > End) {
        // The entry extends into the next MMRAM region. This is only valid when
        // the next region is immediately adjacent and shares the same region
        // state (ignoring EFI_ALLOCATED, which this routine derives).
        ASSERT ((Index + 1) < mMmramRangeCount);
        if ((Index + 1) < mMmramRangeCount) {
          ASSERT (mMmramRanges[Index + 1].PhysicalStart == End + 1);
          ASSERT (
            (mMmramRanges[Index + 1].RegionState & ~(UINT64)EFI_ALLOCATED) ==
            (MmramEntry->RegionState & ~(UINT64)EFI_ALLOCATED)
            );
        }

        Start = End + 1;
        break;
      }

      Start = Entry->End + 1;

      Link = Link->ForwardLink;
    }

    if (Start <= End) {
      // There is a gap at the end, which is a free mmram region.
      if (Descriptors != NULL) {
        DEBUG ((
          DEBUG_INFO,
          "%a - Including ending free entry Start: 0x%lx, End: 0x%lx within MMRAM %p - %p (State %x).\n",
          __func__,
          Start,
          End,
          MmramEntry->PhysicalStart,
          MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1,
          MmramEntry->RegionState
          ));
        Descriptors[Count].CpuStart      = Start;
        Descriptors[Count].PhysicalStart = Start;
        Descriptors[Count].PhysicalSize  = End - Start + 1;
        Descriptors[Count].RegionState   = EFI_SMRAM_CLOSED | EFI_CACHEABLE;
      }

      Count++;
      // It is unexpected to have uncovered regions through memory map
      ASSERT (FALSE);
    }
  }

  // Every memory map entry must be covered by an MMRAM region. Any entries left
  // unconsumed lie beyond the last MMRAM region (outside MMRAM).
  ASSERT (Link == &gMemoryMap);

  return Count;
}

/**
  Helper function to prepare memory HOB for the supervisor MMRAM layout.

  Specifically, it iterates over the memory map and interleaves the inbound MMRAM regions
  to construct the appropriate HOBs for the runtime supervisor environment.

  Must be called only after every supervisor allocation is complete, because the
  descriptor count is derived from a snapshot of gMemoryMap.

  @param[in,out]  Builder     Pointer to the HOB builder structure.

  @retval EFI_SUCCESS            The HOB was written.
  @retval EFI_INVALID_PARAMETER  Builder is NULL.
  @retval EFI_BUFFER_TOO_SMALL   Builder->Cursor is 0, or the buffer is too small. The required size is returned in Builder->Remaining.
**/
STATIC
EFI_STATUS
PrepareRuntimeMmramHob (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  )
{
  LIST_ENTRY                      *Link;
  MEMORY_MAP                      *CurrentEntry;
  MEMORY_MAP                      *NextEntry;
  UINTN                           TotalHobSize;
  UINTN                           PayloadSize;
  UINT32                          Count;
  EFI_SMRAM_HOB_DESCRIPTOR_BLOCK  *SmramHobBlock;
  BOOLEAN                         Swapped;

  if (Builder == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // First, insertion sort the memory map based on Start address
  do {
    Swapped = FALSE;
    Link    = gMemoryMap.ForwardLink;
    while (Link->ForwardLink != &gMemoryMap) {
      CurrentEntry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
      NextEntry    = CR (Link->ForwardLink, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
      if (CurrentEntry->Start > NextEntry->Start) {
        // swap the two entries
        // adjust the links
        RemoveEntryList (&CurrentEntry->Link);
        InsertTailList (&NextEntry->Link, &CurrentEntry->Link);
        Swapped = TRUE;
      } else {
        Link = Link->ForwardLink;
      }
    }
  } while (Swapped);

  // Now that the memory map is sorted, count the EFI_MMRAM_DESCRIPTORs required
  // to describe the MMRAM layout (allocated sub-regions plus free gaps).
  // Absolutely no more allocation here!!!!
  Count = SerializeMmramDescriptors (NULL);

  PayloadSize = OFFSET_OF (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, Descriptor)
                + (UINTN)Count * sizeof (EFI_MMRAM_DESCRIPTOR);

  TotalHobSize = GUID_HOB_SIZE (PayloadSize);

  if ((Builder->Cursor == 0) || (Builder->Remaining < TotalHobSize)) {
    Builder->Remaining = TotalHobSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  SmramHobBlock = HobAppendGuid (Builder, &gEfiSmmSmramMemoryGuid, PayloadSize);
  if (SmramHobBlock == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // Populate the descriptors now that the block is allocated. The deterministic
  // walk yields the same count as the sizing pass above.
  Count = SerializeMmramDescriptors (SmramHobBlock->Descriptor);

  SmramHobBlock->NumberOfSmmReservedRegions = Count;

  return EFI_SUCCESS;
}

/**
  Size, allocate and seed the supervisor HOB region.

  Reserves a supervisor allocation large enough for the inbound HOB list plus the
  MMRAM descriptors that get regenerated later, copies the inbound list into it,
  and leaves the builder positioned just after the copied entries. Also publishes
  the region through mMmHobStart / mMmHobSize.

  The inbound MMRAM descriptor HOBs are dropped on the way in, because
  SupvInitHobsAddMmramDescriptors rebuilds them from the final memory map once
  every supervisor allocation is done.

  Does not return if the region cannot be sized or allocated.

  @param[out]  Builder  Receives the initialized builder state.
**/
VOID
SupvInitHobsInit (
  OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  RegionBase;
  UINTN                 CopiedSize;
  EFI_PEI_HOB_POINTERS  Hob;
  EFI_GUID              *HobGuid;
  UINTN                 HobSize;

  DEBUG ((DEBUG_INFO, "gHobList - 0x%p, HobSize - 0x%x\n", gHobList, GetHobListSize (gHobList)));

  if (Builder == NULL) {
    PANIC ("Builder is NULL");
    return;
  }

  //
  // Size the region: the inbound HOB list, plus room for the MMRAM descriptors,
  // plus a page of slack to cover everything allocated while the list is being
  // built (page tables, module hobs, common buffers, ...).
  //
  ZeroMem (Builder, sizeof (*Builder));
  Status = PrepareRuntimeMmramHob (Builder);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to get MM Supervisor allocation hob size - %r\n", __func__, Status));
    ASSERT (FALSE);
    PANIC ("Failed to prepare MM Supervisor hobs");
  }

  mMmHobSize  = GetHobListSize (gHobList) + (UINTN)Builder->Remaining;
  mMmHobSize  = ALIGN_VALUE (mMmHobSize, EFI_PAGE_SIZE);
  mMmHobSize += EFI_PAGE_SIZE;  // Add an extra page of slack for allocations during HOB building

  Status = MmAllocateSupervisorPages (AllocateAnyPages, EfiRuntimeServicesData, EFI_SIZE_TO_PAGES (mMmHobSize), &RegionBase);
  if (EFI_ERROR (Status)) {
    PANIC ("Failed to allocate MM Supervisor hob memory");
  }

  DEBUG ((DEBUG_INFO, "%a Allocated MM Supervisor Hob at 0x%p with size 0x%x\n", __func__, (VOID *)(UINTN)RegionBase, mMmHobSize));

  ZeroMem ((VOID *)(UINTN)RegionBase, mMmHobSize);
  mMmHobStart = (VOID *)(UINTN)RegionBase;

  CopiedSize = 0;
  Hob.Raw    = (UINT8 *)gHobList;
  while (!END_OF_HOB_LIST (Hob)) {
    HobSize = GET_HOB_LENGTH (Hob);
    if (CopiedSize + ALIGN_VALUE (HobSize, 8) > mMmHobSize) {
      DEBUG ((DEBUG_ERROR, "%a MM Supervisor Hob size 0x%x is not enough to copy existing hob list, need at least 0x%x\n", __func__, mMmHobSize, CopiedSize + ALIGN_VALUE (HobSize, 8)));
      ASSERT (FALSE);
      PANIC ("MM Supervisor Hob size insufficient");
    }

    // Filter out the MmRam Hob as we will recreate it later
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_GUID_EXTENSION) {
      HobGuid = &((EFI_HOB_GUID_TYPE *)Hob.Raw)->Name;
      if (CompareGuid (HobGuid, &gEfiMmPeiMmramMemoryReserveGuid) ||
          CompareGuid (HobGuid, &gEfiSmmSmramMemoryGuid))
      {
        DEBUG ((DEBUG_INFO, "%a Skip Copying MmRam Hob Type 0x%x Size 0x%x\n", __func__, GET_HOB_TYPE (Hob), HobSize));
        Hob.Raw = GET_NEXT_HOB (Hob);
        continue;
      }
    }

    DEBUG ((DEBUG_INFO, "%a Copy Hob Type 0x%x Size 0x%x into offset 0x%x\n", __func__, GET_HOB_TYPE (Hob), HobSize, CopiedSize));
    CopyMem ((VOID *)((UINTN)RegionBase + CopiedSize), (VOID *)Hob.Raw, HobSize);
    CopiedSize += ALIGN_VALUE (HobSize, 8);
    Hob.Raw     = GET_NEXT_HOB (Hob);
  }

  Builder->Base      = RegionBase;
  Builder->Cursor    = RegionBase + CopiedSize;
  Builder->Remaining = mMmHobSize - CopiedSize;
}

/**
  Append the memory allocation module HOBs describing the supervisor core, the
  user module and every driver discovered for dispatch.

  Must be called after the modules have been loaded.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to append to.

  @retval EFI_SUCCESS            The module allocation HOBs were successfully appended.
  @retval EFI_BUFFER_TOO_SMALL   The HOB region is too small to hold the module allocation HOBs.
  @retval EFI_INVALID_PARAMETER  The Builder is NULL or invalid.
**/
EFI_STATUS
SupvInitHobsAddModuleAllocations (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  )
{
  LIST_ENTRY              *Link;
  EFI_MM_DRIVER_ENTRY     *DriverEntry;
  MM_SUPV_DEPEX_HOB_DATA  *DepexHobData;
  EFI_STATUS              Status;

  if ((Builder == NULL) || (Builder->Base == 0) || (Builder->Remaining == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_INFO, "%a\n", __func__));

  Status = HobAppendModuleAllocation (Builder, &gMmSupervisorCoreGuid, mMmCoreDriverEntry);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to append module allocation HOB for MM Core\n", __func__));
    return Status;
  }

  Status = HobAppendModuleAllocation (Builder, &gMmSupervisorUserGuid, mMmUserDriverEntry);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to append module allocation HOB for MM User\n", __func__));
    return Status;
  }

  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);

    Status = HobAppendModuleAllocation (Builder, &DriverEntry->FileName, DriverEntry);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: Failed to append module allocation HOB for %g\n", __func__, &DriverEntry->FileName));
      return Status;
    }

    DepexHobData = HobAppendGuid (
                     Builder,
                     &gMmSupervisorDepexHobGuid,
                     sizeof (MM_SUPV_DEPEX_HOB_DATA) + DriverEntry->DepexSize
                     );
    if (DepexHobData == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyGuid (&DepexHobData->Name, &DriverEntry->FileName);
    DepexHobData->Length = DriverEntry->DepexSize;
    if (DriverEntry->DepexSize != 0) {
      CopyMem (DepexHobData->Data, DriverEntry->Depex, DriverEntry->DepexSize);
    }
  }

  return EFI_SUCCESS;
}

/**
  Append the pass down HOB describing what the supervisor set up for the runtime.

  Must be called after the common buffers and the firmware policy are in place.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to append to.

  @retval EFI_SUCCESS           The pass down HOB was successfully appended.
  @retval EFI_INVALID_PARAMETER One or more of the input parameters are invalid.
  @retval EFI_BUFFER_TOO_SMALL  The HOB region is too small to append the pass down HOB.
**/
EFI_STATUS
SupvInitHobsAddPassDown (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  )
{
  UINTN                       NewLength;
  MM_SUPV_PASS_DOWN_HOB_DATA  *PassDownData;

  if ((Builder == NULL) || (Builder->Base == 0) || (Builder->Remaining == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  NewLength = GUID_HOB_SIZE (sizeof (MM_SUPV_PASS_DOWN_HOB_DATA));

  if (Builder->Remaining < NewLength) {
    return EFI_BUFFER_TOO_SMALL;
  }

  PassDownData = HobAppendGuid (
                   Builder,
                   &gMmSupervisorPassDownHobGuid,
                   sizeof (MM_SUPV_PASS_DOWN_HOB_DATA)
                   );
  if (PassDownData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  PassDownData->Revision = MM_SUPV_PASS_DOWN_HOB_REVISION;
  PassDownData->Reserved = 0;
  //
  // Pass the per-CPU SMBASE array pointer directly.
  //
  PassDownData->SmBase = (EFI_PHYSICAL_ADDRESS)(UINTN)mCpuHotPlugData.SmBase;

  PassDownData->MmInitializedBuffer = (EFI_PHYSICAL_ADDRESS)mSmmInitialized;

  PassDownData->MmSupervisorCpl3StackBase        = (EFI_PHYSICAL_ADDRESS)mSmmCpl3StackArrayBase;
  PassDownData->MmSupervisorCpl3PerCoreStackSize = mSmmStackSize;

  PassDownData->MmSupvFirmwarePolicyBuffer     = (EFI_PHYSICAL_ADDRESS)FirmwarePolicy;
  PassDownData->MmSupvFirmwarePolicyBufferSize = FirmwarePolicy->Size;

  PassDownData->MmiEntrypointSize = GetSmiHandlerSize ();

  return EFI_SUCCESS;
}

/**
  Append the guided HOB describing the final MMRAM layout.

  Must be called after the lock step, which is the last thing that allocates, so
  that the supervisor memory map this is derived from is final.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to append to.
**/
VOID
SupvInitHobsAddMmramDescriptors (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  )
{
  EFI_STATUS  Status;

  Status = PrepareRuntimeMmramHob (Builder);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a Failed to prepare MM Supervisor hobs, need 0x%lx have 0x%lx - %r\n",
      __func__,
      Builder->Cursor - Builder->Base,
      Builder->Remaining,
      Status
      ));
    PANIC ("Failed to prepare MM Supervisor hobs, FIMD!!!\n");
  }
}

/**
  Terminate the supervisor HOB list with an end-of-HOB marker.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to terminate.
**/
VOID
SupvInitHobsFinalize (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  )
{
  EFI_HOB_GENERIC_HEADER  *EndHob;
  UINT64                  HobLength;

  HobLength = ALIGN_VALUE (sizeof (EFI_HOB_GENERIC_HEADER), 8);
  if (Builder->Remaining < HobLength) {
    DEBUG ((DEBUG_ERROR, "%a MM Supervisor Hob size 0x%x is not enough to add end of hob list, need at least 0x%lx\n", __func__, mMmHobSize, HobLength));
    PANIC ("MM Supervisor Hob size insufficient for end hob");
  }

  EndHob            = (EFI_HOB_GENERIC_HEADER *)(UINTN)Builder->Cursor;
  EndHob->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  EndHob->HobLength = (UINT16)HobLength;
  EndHob->Reserved  = 0;

  HobBuilderAdvance (Builder, HobLength);

  // The region is deliberately over-allocated, so report the real headroom.
  DEBUG ((
    DEBUG_INFO,
    "%a MM Supervisor Hob list complete: 0x%lx bytes used of 0x%x, 0x%lx spare\n",
    __func__,
    Builder->Cursor - Builder->Base,
    mMmHobSize,
    Builder->Remaining
    ));
}
