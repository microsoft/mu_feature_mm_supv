/** @file
  Init (MmSupervisorInit) memory-map -> MMRAM HOB serialization.

  Linked only into MmSupervisorInit.  Walks the supervisor memory map (the
  `gMemoryMap` list maintained by Page.c) and the existing `mMmramRanges`
  table, then emits a guided HOB describing the resulting MMRAM layout
  (allocated regions tagged EFI_ALLOCATED, gaps tagged free).  Used by
  MmSupervisorInit.c when handing control to the runtime supervisor and by
  Init's Relocate.c when sizing/copying the HOB block.

  This routine is Init-only: the runtime MmSupervisorCore driver does not
  need to (re)serialize MMRAM, so there is no _core.c counterpart.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Guid/SmramMemoryReserve.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "PageInternal.h"

/**
  Serialize the supervisor MMRAM layout into EFI_MMRAM_DESCRIPTORs.

  Walks the (already Start-sorted) supervisor memory map (gMemoryMap) against the
  MMRAM ranges (mMmramRanges), emitting one descriptor per allocated sub-region
  (runtime-services allocations, tagged EFI_ALLOCATED) and one per free gap. This
  is the shared core of PrepareMmSupervisorHobs' two passes:

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

  Count = 0;
  Link  = gMemoryMap.ForwardLink;

  for (UINTN Index = 0; Index < mMmramRangeCount; Index++) {
    MmramEntry = &mMmramRanges[Index];

    EFI_PHYSICAL_ADDRESS  Start = MmramEntry->PhysicalStart;
    EFI_PHYSICAL_ADDRESS  End   = MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1;

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
        EFI_PHYSICAL_ADDRESS  DescStart = MAX (Entry->Start, Start);
        EFI_PHYSICAL_ADDRESS  DescEnd   = MIN (Entry->End, End);

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

EFI_STATUS
EFIAPI
PrepareMmSupervisorHobs (
  IN  EFI_PHYSICAL_ADDRESS  MmHobStart  OPTIONAL,
  OUT UINT64                *MmHobSize
  )
{
  // Loop through all the allocated pages
  // convert them into memory allocation hobs
  LIST_ENTRY            *Link;
  MEMORY_MAP            *Entry;

  UINTN                 TotalHobSize;
  EFI_HOB_GUID_TYPE     *MmramGuidedHob;

  UINT32                Count;

  EFI_SMRAM_HOB_DESCRIPTOR_BLOCK  *SmramHobBlock;

  BOOLEAN  Swapped;

  if (MmHobSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  TotalHobSize = sizeof (EFI_HOB_GUID_TYPE);
  Link         = gMemoryMap.ForwardLink;
  while (Link != &gMemoryMap) {
    Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
    Link  = Link->ForwardLink;

    if ((Entry->Type == EfiRuntimeServicesCode) || (Entry->Type == EfiRuntimeServicesData)) {
      TotalHobSize += sizeof (EFI_HOB_MEMORY_ALLOCATION);
    }
  }

  // insertion sort the memory map based on Start address
  do {
    Swapped = FALSE;
    Link    = gMemoryMap.ForwardLink;
    while (Link->ForwardLink != &gMemoryMap) {
      MEMORY_MAP  *CurrentEntry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
      MEMORY_MAP  *NextEntry    = CR (Link->ForwardLink, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);
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
  Count         = SerializeMmramDescriptors (NULL);
  TotalHobSize += (UINTN)Count * sizeof (EFI_MMRAM_DESCRIPTOR);

  TotalHobSize += OFFSET_OF (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, Descriptor);

  if (TotalHobSize == 0) {
    *MmHobSize = 0;
    return EFI_SUCCESS;
  }

  if ((MmHobStart == 0) || (*MmHobSize < TotalHobSize)) {
    *MmHobSize = TotalHobSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  *MmHobSize     = TotalHobSize;
  MmramGuidedHob = (EFI_HOB_GUID_TYPE *)(UINTN)(MmHobStart);

  MmramGuidedHob->Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  MmramGuidedHob->Header.HobLength = (UINT16)TotalHobSize;
  MmramGuidedHob->Header.Reserved  = 0;

  CopyGuid (&MmramGuidedHob->Name, &gEfiSmmSmramMemoryGuid);

  SmramHobBlock = (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK *)(MmramGuidedHob + 1);

  // Populate the descriptors now that the block is allocated. The deterministic
  // walk yields the same count as the sizing pass above.
  Count = SerializeMmramDescriptors (SmramHobBlock->Descriptor);

  SmramHobBlock->NumberOfSmmReservedRegions = Count;

  return EFI_SUCCESS;
}
