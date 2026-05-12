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

//
// MEMORY_MAP / MEMORY_MAP_SIGNATURE / gMemoryMap are file-private to Page.c.
// We mirror just enough of those declarations here to walk the list.  If the
// MEMORY_MAP layout in Page.c ever changes, this declaration must be kept in
// lock-step (we get the same coupling that Init's standalone Page.c had
// before the split, since both copies inlined the struct).
//
#define MEMORY_MAP_SIGNATURE  SIGNATURE_32 ('m', 'm', 'a', 'p')

typedef struct {
  UINTN              Signature;
  LIST_ENTRY         Link;

  BOOLEAN            FromStack;
  BOOLEAN            IsSupervisorPage;
  EFI_MEMORY_TYPE    Type;
  UINT64             Start;
  UINT64             End;
} MEMORY_MAP;

extern LIST_ENTRY  gMemoryMap;

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
  EFI_MMRAM_DESCRIPTOR  *MmramEntry;

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

  // Now the memory map is sorted, we can recreate the MmRam hobs
  // Based on existing mMmramRanges and mMmramRangeCount, we will mark the allocated
  // regions with EFI_ALLOCATED, and insert the empty regions without EFI_ALLOCATED.

  // First we figure out how many EFI_MMRAM_DESCRIPTOR we will need.
  // Absolutely no more allocation here!!!!
  Link = gMemoryMap.ForwardLink;
  for (UINTN Index = 0; Index < mMmramRangeCount; Index++) {
    MmramEntry = &mMmramRanges[Index];

    EFI_PHYSICAL_ADDRESS  Start = MmramEntry->PhysicalStart;
    EFI_PHYSICAL_ADDRESS  End   = MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1;

    // Here go through the sorted linked list, and count the allocated regions inside this region
    while (Link != &gMemoryMap) {
      Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);

      if (Entry->Start > End) {
        // No more entries in this region
        break;
      }

      if (Start < Entry->Start) {
        // There is a gap before this entry, which will be a free mmram region
        DEBUG ((
          DEBUG_INFO,
          "%a - Found starting free entry Start: 0x%lx, End: 0x%lx within MMRAM %p - %p (State %x).\n",
          __func__,
          Start,
          Entry->Start - 1,
          MmramEntry->PhysicalStart,
          MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1,
          MmramEntry->RegionState
          ));
        // Count this entry
        TotalHobSize += sizeof (EFI_MMRAM_DESCRIPTOR);
        Start         = Entry->Start;
        // It is unexpected to have uncovered regions through memory map
        ASSERT (FALSE);
      }

      if ((Entry->Start >= Start) && (Entry->End <= End)) {
        // This entry is inside the mmram region
        DEBUG ((
          DEBUG_INFO,
          "%a - Including allocated Start: 0x%lx, End: 0x%lx, Type: 0x%x, IsSupervisorPage: %d\n",
          __func__,
          Entry->Start,
          Entry->End,
          Entry->Type,
          Entry->IsSupervisorPage
          ));
        // Count this entry
        TotalHobSize += sizeof (EFI_MMRAM_DESCRIPTOR);
      }

      Start = Entry->End + 1;

      Link = Link->ForwardLink;
    }

    if (Start <= End) {
      // There is a gap at the end, which will be a free mmram region
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
      // Count this entry
      TotalHobSize += sizeof (EFI_MMRAM_DESCRIPTOR);
      // It is unexpected to have uncovered regions through memory map
      ASSERT (FALSE);
    }
  }

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
  Count         = 0;

  Link = gMemoryMap.ForwardLink;
  for (UINTN Index = 0; Index < mMmramRangeCount; Index++) {
    MmramEntry = &mMmramRanges[Index];

    EFI_PHYSICAL_ADDRESS  Start = MmramEntry->PhysicalStart;
    EFI_PHYSICAL_ADDRESS  End   = MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1;

    // Here go through the sorted linked list, and count the allocated regions inside this region
    while (Link != &gMemoryMap) {
      Entry = CR (Link, MEMORY_MAP, Link, MEMORY_MAP_SIGNATURE);

      if (Entry->Start > End) {
        // No more entries in this region
        break;
      }

      if (Start < Entry->Start) {
        // There is a gap before this entry, which will be a free mmram region
        DEBUG ((
          DEBUG_INFO,
          "%a - Including ending free entry Start: 0x%lx, End: 0x%lx within MMRAM %p - %p (State %x).\n",
          __func__,
          Start,
          Entry->Start - 1,
          MmramEntry->PhysicalStart,
          MmramEntry->PhysicalStart + MmramEntry->PhysicalSize - 1,
          MmramEntry->RegionState
          ));
        // Count this entry
        SmramHobBlock->Descriptor[Count].CpuStart      = Start;
        SmramHobBlock->Descriptor[Count].PhysicalStart = Start;
        SmramHobBlock->Descriptor[Count].PhysicalSize  = Entry->Start - Start;
        SmramHobBlock->Descriptor[Count].RegionState   = EFI_SMRAM_CLOSED | EFI_CACHEABLE;
        Count++;
        Start = Entry->Start;
        // It is unexpected to have uncovered regions through memory map
        ASSERT (FALSE);
      }

      if ((Entry->Start >= Start) && (Entry->End <= End)) {
        // This entry is inside the mmram region
        DEBUG ((
          DEBUG_INFO,
          "%a - Including Start: 0x%lx, End: 0x%lx, Type: 0x%x, IsSupervisorPage: %d\n",
          __func__,
          Entry->Start,
          Entry->End,
          Entry->Type,
          Entry->IsSupervisorPage
          ));
        // Count this entry
        // Count this entry
        SmramHobBlock->Descriptor[Count].CpuStart      = Entry->Start;
        SmramHobBlock->Descriptor[Count].PhysicalStart = Entry->Start;
        SmramHobBlock->Descriptor[Count].PhysicalSize  = Entry->End - Entry->Start + 1;
        if ((Entry->Type == EfiRuntimeServicesCode) || (Entry->Type == EfiRuntimeServicesData)) {
          SmramHobBlock->Descriptor[Count].RegionState = EFI_SMRAM_CLOSED | EFI_CACHEABLE | EFI_ALLOCATED;
        } else {
          // Should not happen
          SmramHobBlock->Descriptor[Count].RegionState = EFI_SMRAM_CLOSED | EFI_CACHEABLE;
        }

        Count++;
      }

      Start = Entry->End + 1;

      Link = Link->ForwardLink;
    }

    if (Start <= End) {
      // There is a gap at the end, which will be a free mmram region
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
      // Count this entry
      SmramHobBlock->Descriptor[Count].CpuStart      = Start;
      SmramHobBlock->Descriptor[Count].PhysicalStart = Start;
      SmramHobBlock->Descriptor[Count].PhysicalSize  = End - Start + 1;
      SmramHobBlock->Descriptor[Count].RegionState   = EFI_SMRAM_CLOSED | EFI_CACHEABLE;
      Count++;
      // It is unexpected to have uncovered regions through memory map
      ASSERT (FALSE);
    }
  }

  SmramHobBlock->NumberOfSmmReservedRegions = Count;

  return EFI_SUCCESS;
}
