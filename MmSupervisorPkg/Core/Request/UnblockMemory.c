/** @file UnblockMemory.c
  Handles requests to unblock memory regions outside if MMRAM.

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (C) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Guid/MmSupervisorRequestData.h>

#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"

typedef struct {
  LIST_ENTRY                             Link;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS    UnblockMemData;
} UNBLOCKED_MEM_LIST;

LIST_ENTRY  mUnblockedMemoryList = INITIALIZE_LIST_HEAD_VARIABLE (mUnblockedMemoryList);

//
// IsWithinUnblockedRegion is provided per-build:
//   * UnblockMemory_core.c -- Core build (MmSupervisorCore.inf)
//   * UnblockMemory_init.c -- Init build (MmSupervisorInit.inf)
// The Init flavor adds DEBUG tracing throughout; otherwise the logic is the
// same.  Both flavors operate on mUnblockedMemoryList defined above.
//

/**
  Helper function used to collect specified unblocked regions when this function
  is invoked.

  @param[in]      StartIndex    The starting index of unblocked regions that is
                                of interest to caller.
  @param[out]     Buffer        Buffer used to hold collected unblocked records.
  @param[in,out]  BufferCount   As input, the value in this pointer is used to
                                indicate how many records can fit in the supplied
                                Buffer. As output, this value reflects how many
                                records are fulfilled upon return.

  @return EFI_SUCCESS             The requested unblocked regions are filled in supplied
                                  buffer fully or partially successfully.
  @retval EFI_INVALID_PARAMETER   One or more of input pointers are NULL.

**/
EFI_STATUS
EFIAPI
CollectUnblockedRegionsFromNthNode (
  IN      UINTN                                StartIndex,
  OUT     MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *Buffer,
  IN OUT  UINTN                                *BufferCount
  )
{
  UNBLOCKED_MEM_LIST                   *UnblockedListEntry;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockedMemEntry;
  LIST_ENTRY                           *Node;
  UINT64                               Index;

  if ((Buffer == NULL) || (BufferCount == NULL)) {
    // Everything is open prior to exiting the core's main routine.
    return EFI_INVALID_PARAMETER;
  }

  Index = 0;
  BASE_LIST_FOR_EACH (Node, &mUnblockedMemoryList) {
    if (Index >= (*BufferCount + StartIndex)) {
      // Cannot fit in any more records, bail here
      break;
    }

    if (Index >= StartIndex) {
      // This is in our target
      UnblockedListEntry = BASE_CR (Node, UNBLOCKED_MEM_LIST, Link);
      CopyMem (&UnblockedMemEntry, &UnblockedListEntry->UnblockMemData, sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS));
      CopyMem (&Buffer[Index - StartIndex], &UnblockedMemEntry, sizeof (UnblockedMemEntry));
    }

    Index++;
  }

  *BufferCount = Index - StartIndex;

  return EFI_SUCCESS;
}

/**
  Check if requested memory region is already unblocked.

  @return Status Code

**/
STATIC
EFI_STATUS
VerifyUnblockRequest (
  IN CONST MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *RequestedData
  )
{
  EFI_PHYSICAL_ADDRESS                 StartAddress;
  EFI_PHYSICAL_ADDRESS                 EndAddress;
  EFI_PHYSICAL_ADDRESS                 UnblockedStartAddress;
  EFI_PHYSICAL_ADDRESS                 UnblockedEndAddress;
  UNBLOCKED_MEM_LIST                   *UnblockedListEntry;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockedMemEntry;
  LIST_ENTRY                           *Node;
  EFI_STATUS                           Status;
  UINT64                               Attributes;

  if (RequestedData == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Null pointer detected...\n", __func__));
    return EFI_INVALID_PARAMETER;
  }

  Status       = EFI_SUCCESS;
  StartAddress = RequestedData->MemoryDescriptor.PhysicalStart;
  EndAddress   = RequestedData->MemoryDescriptor.PhysicalStart +
                 EFI_PAGES_TO_SIZE (RequestedData->MemoryDescriptor.NumberOfPages);

  // First check if the requested region is duplicated.
  Node = mUnblockedMemoryList.ForwardLink;
  while (Node != &mUnblockedMemoryList) {
    UnblockedListEntry = BASE_CR (Node, UNBLOCKED_MEM_LIST, Link);
    CopyMem (&UnblockedMemEntry, &UnblockedListEntry->UnblockMemData, sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS));
    UnblockedStartAddress = UnblockedMemEntry.MemoryDescriptor.PhysicalStart;
    UnblockedEndAddress   = UnblockedStartAddress +
                            EFI_PAGES_TO_SIZE (UnblockedMemEntry.MemoryDescriptor.NumberOfPages);

    if ((StartAddress == UnblockedStartAddress) && (EndAddress == UnblockedEndAddress)) {
      if (CompareMem (
            &UnblockedMemEntry.MemoryDescriptor,
            &RequestedData->MemoryDescriptor,
            sizeof (EFI_MEMORY_DESCRIPTOR)
            ) == 0)
      {
        // We can allow a pass for a completely identical unblock request
        DEBUG ((DEBUG_INFO, "%a - Identical with the request from %g\n", __func__, &UnblockedMemEntry.IdentifierGuid));
        Status = EFI_ALREADY_STARTED;
      } else {
        // Otherwise, someone tries to unblock the memory under different attributes
        DEBUG ((
          DEBUG_INFO,
          "%a - Request clashed with %g Address: 0x%p Length: 0x%x (Pages)\n",
          __func__,
          &UnblockedMemEntry.IdentifierGuid,
          UnblockedMemEntry.MemoryDescriptor.PhysicalStart,
          UnblockedMemEntry.MemoryDescriptor.NumberOfPages
          ));
        Status = EFI_SECURITY_VIOLATION;
      }

      break;
    } else if (((StartAddress >= UnblockedStartAddress) && (StartAddress < UnblockedEndAddress)) ||
               ((EndAddress > UnblockedStartAddress) && (EndAddress <= UnblockedEndAddress)))
    {
      DEBUG ((
        DEBUG_ERROR,
        "%a - Request clashed with %g Address: 0x%p Length: 0x%x (Pages)\n",
        __func__,
        &UnblockedMemEntry.IdentifierGuid,
        UnblockedMemEntry.MemoryDescriptor.PhysicalStart,
        UnblockedMemEntry.MemoryDescriptor.NumberOfPages
        ));
      Status = EFI_SECURITY_VIOLATION;
      break;
    }

    Node = Node->ForwardLink;
  }

  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // For new requests, check if the intended region is mapped as RP and non-SP, otherwise this region itself is illegal.
  Status = SmmGetMemoryAttributes (StartAddress, EndAddress - StartAddress, &Attributes);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a Unable to get the page attribute of targeted region Start: 0x%p - End: 0x%p: %r\n",
      __func__,
      StartAddress,
      EndAddress,
      Status
      ));
    goto Done;
  }

  // Only not present pages can be unblocked. And for pages already have read only and/or supervisor ownership,
  // it cannot be touched through this method.
  if ((Attributes & (EFI_MEMORY_RO)) || !(Attributes & EFI_MEMORY_RP)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a Targeted region (Start: 0x%p - End: 0x%p) has unexpected attributes: 0x%x\n",
      __func__,
      StartAddress,
      EndAddress,
      Attributes
      ));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

Done:
  DEBUG ((DEBUG_INFO, "%a - Exit - %r\n", __func__, Status));
  return Status;
}

//
// ProcessBlockPages and ProcessUnblockPages are provided per-build:
//   * UnblockMemory_core.c -- Core build (MmSupervisorCore.inf)
//   * UnblockMemory_init.c -- Init build (MmSupervisorInit.inf)
//
// The Init build also adds an Init-only helper, MmAddUnblckedMemoryList, which
// is consumed exclusively by Init's ProcessUnblockPages.  The Core flavor of
// ProcessUnblockPages still inlines that allocation directly because Core has
// no other caller for it, and the existing mMmReadyToLockDone gate (only
// effective in Core) is left in place there.  Init's ProcessBlockPages also
// performs additional left/right split bookkeeping after a partial block.
//
// Both flavors operate on mUnblockedMemoryList defined above.
//
