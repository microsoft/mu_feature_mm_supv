/** @file UnblockMemory_core.c
  Per-build (MmSupervisorCore.inf) divergent function bodies for the unblock
  memory request handler.  See UnblockMemory.c for the file-header overview and
  the shared helpers (UNBLOCKED_MEM_LIST list management,
  CollectUnblockedRegionsFromNthNode, VerifyUnblockRequest).  The Init build
  carries its own copies of these functions in UnblockMemory_init.c.

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
#include "UnblockMemoryInternal.h"

/**
  Helper function to check if range requested is within boundary of unblocked lists.
  This routine is simple and do not merge adjacent regions from two entries into one.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @return TRUE      The queried region is within unblocked range.
  @return FALSE     The queried region is outside of unblocked range.

**/
BOOLEAN
EFIAPI
IsWithinUnblockedRegion (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  UNBLOCKED_MEM_LIST                   *UnblockedListEntry;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockedMemEntry;
  LIST_ENTRY                           *Node;
  UINT64                               StartAddress;
  UINT64                               EndAddress;

  if (!mCoreInitializationComplete) {
    // Everything is open prior to exiting the core's main routine.
    return TRUE;
  }

  if ((Length == 0) || (MAX_UINT64 - Length + 1 < Length)) {
    // Zero-length query or incoming out of 64-bit limitation
    return FALSE;
  }

  Node = mUnblockedMemoryList.ForwardLink;
  while (Node != &mUnblockedMemoryList) {
    UnblockedListEntry = BASE_CR (Node, UNBLOCKED_MEM_LIST, Link);
    UnblockedMemEntry  = UnblockedListEntry->UnblockMemData;
    StartAddress       = UnblockedMemEntry.MemoryDescriptor.PhysicalStart;
    // EndAddress cannot exceed 64-bit boundary due to paging limitation
    EndAddress = StartAddress + EFI_PAGES_TO_SIZE (UnblockedMemEntry.MemoryDescriptor.NumberOfPages);

    if ((StartAddress <= Buffer) && (Buffer + Length <= EndAddress)) {
      return TRUE;
    }

    Node = Node->ForwardLink;
  }

  return FALSE;
}

/**
  Routine used to validate and block requested region to be inaccessible in MM
  environment.

  @param[in] BlockMemDesc       Pointer to the descriptor of the region to be
                                blocked.

  @retval EFI_SUCCESS           The requested region was found and is now blocked.
  @retval EFI_INVALID_PARAMETER BlockMemDesc is a null pointer.
  @retval EFI_NOT_FOUND         The requested region is not currently in the
                                unblocked memory list.
  @retval Others                Page attribute setting routine has failed.

**/
EFI_STATUS
ProcessBlockPages (
  IN MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *BlockMemDesc
  )
{
  UNBLOCKED_MEM_LIST                   *UnblockedListEntry;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockedMemEntry;
  LIST_ENTRY                           *Node;
  EFI_STATUS                           Status;

  if (BlockMemDesc == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_NOT_FOUND;
  BASE_LIST_FOR_EACH (Node, &mUnblockedMemoryList) {
    UnblockedListEntry = BASE_CR (Node, UNBLOCKED_MEM_LIST, Link);
    UnblockedMemEntry  = UnblockedListEntry->UnblockMemData;
    if ((UnblockedMemEntry.MemoryDescriptor.PhysicalStart == BlockMemDesc->MemoryDescriptor.PhysicalStart) &&
        (UnblockedMemEntry.MemoryDescriptor.NumberOfPages == BlockMemDesc->MemoryDescriptor.NumberOfPages))
    {
      Status = EFI_SUCCESS;
      break;
    }
  }

  // If not found, then bail...
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Mark this region to be inaccessible
  Status = SmmSetMemoryAttributes (
             UnblockedMemEntry.MemoryDescriptor.PhysicalStart,
             EFI_PAGES_TO_SIZE (UnblockedMemEntry.MemoryDescriptor.NumberOfPages),
             EFI_MEMORY_RP
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to SetMemAttr to unblock memory %r!\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // For the record, instead of removing this region from the list,
  // we will set the length to 0 and update the attribute.
  RemoveEntryList (Node);
  FreePool (UnblockedListEntry);

  return EFI_SUCCESS;
}

/**
  Routine used to validate and unblock requested region to be accessible in MM
  environment. Given this routine could received untrusted data, the requested
  region must be already aligned to page boundary, since the page table
  attributes setting code only manipulates aligned regions to such granularity.

  @param[in] UnblockMemParams     Pointer to the descriptor of the region to be
                                  unblocked.

  @retval EFI_SUCCESS             The requested region properly unblocked.
  @retval EFI_ACCESS_DENIED       The request was made post lock down event.
  @retval EFI_INVALID_PARAMETER   UnblockMemParams or its ID GUID is null pointer.
  @retval EFI_ALREADY_STARTED     The requested region has illegal page attributes.
  @retval Others                  Page attribute setting/clearing routine has failed.

**/
EFI_STATUS
ProcessUnblockPages (
  IN MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *UnblockMemParams
  )
{
  EFI_STATUS          Status = EFI_SUCCESS;
  UNBLOCKED_MEM_LIST  *UnblockListEntry;
  UINT64              Attribute;

  if (mMmReadyToLockDone) {
    // Note that this flag will be set once the policy is requested
    DEBUG ((
      DEBUG_ERROR,
      "%a - Unblock requested after ready to lock, will not proceed!\n",
      __func__
      ));
    return EFI_ACCESS_DENIED;
  }

  // Some more sanity checks here
  if ((UnblockMemParams == NULL) ||
      IsZeroGuid (&UnblockMemParams->IdentifierGuid))
  {
    DEBUG ((DEBUG_ERROR, "%a - Invalid parameter detected - %p!\n", __func__, UnblockMemParams));
    return EFI_INVALID_PARAMETER;
  }

  // Make sure the requested region is not messing with MMRAM
  if (IsBufferInsideMmram (
        UnblockMemParams->MemoryDescriptor.PhysicalStart,
        EFI_PAGES_TO_SIZE (UnblockMemParams->MemoryDescriptor.NumberOfPages)
        ))
  {
    DEBUG ((
      DEBUG_ERROR,
      "%a - Invalid unblock params of address 0x%x and length %x pages!\n",
      __func__,
      UnblockMemParams->MemoryDescriptor.PhysicalStart,
      UnblockMemParams->MemoryDescriptor.NumberOfPages
      ));
    return EFI_SECURITY_VIOLATION;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a - %g requested unblocking Address: 0x%p Length: 0x%x (Pages) Attribute 0x%x\n",
    __func__,
    &UnblockMemParams->IdentifierGuid,
    UnblockMemParams->MemoryDescriptor.PhysicalStart,
    UnblockMemParams->MemoryDescriptor.NumberOfPages,
    UnblockMemParams->MemoryDescriptor.Attribute
    ));

  Status = VerifyUnblockRequest (UnblockMemParams);
  if (Status == EFI_ALREADY_STARTED) {
    DEBUG ((DEBUG_WARN, "%a - Exact match detected, will not double unblock!\n", __func__));
    return EFI_SUCCESS;
  } else if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Unblock request verification failed - %r!\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // Only honor the supervisor bit here, since all unblocked pages should only be used as data pages
  if (UnblockMemParams->MemoryDescriptor.Attribute & EFI_MEMORY_SP) {
    Attribute = EFI_MEMORY_XP | EFI_MEMORY_SP;
  } else {
    Attribute = EFI_MEMORY_XP;
  }

  // Mark this region to be Data Page
  Status = SmmClearMemoryAttributes (
             UnblockMemParams->MemoryDescriptor.PhysicalStart,
             EFI_PAGES_TO_SIZE (UnblockMemParams->MemoryDescriptor.NumberOfPages),
             EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_SP
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to ClearMemAttr to unblock memory %r!\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  Status = SmmSetMemoryAttributes (
             UnblockMemParams->MemoryDescriptor.PhysicalStart,
             EFI_PAGES_TO_SIZE (UnblockMemParams->MemoryDescriptor.NumberOfPages),
             Attribute
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to SetMemAttr to unblock memory %r!\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  UnblockListEntry = AllocatePool (sizeof (UNBLOCKED_MEM_LIST));
  if (UnblockListEntry == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to allocate pool for unblock memory list!\n", __func__));
    ASSERT (FALSE);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (&UnblockListEntry->UnblockMemData, UnblockMemParams, sizeof (*UnblockMemParams));
  InsertTailList (&mUnblockedMemoryList, &UnblockListEntry->Link);

  return Status;
} // ProcessUnblockPages()
