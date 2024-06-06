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
    DEBUG ((DEBUG_ERROR, "%a - Null pointer detected...\n", __FUNCTION__));
    return EFI_INVALID_PARAMETER;
  }

  Status       = EFI_SUCCESS;
  StartAddress = RequestedData->MemoryDescriptor.PhysicalStart;
  EndAddress   = RequestedData->MemoryDescriptor.PhysicalStart +
                 EFI_PAGES_TO_SIZE (RequestedData->MemoryDescriptor.NumberOfPages);

  // First check if the requested region is duplicated.
  Node = mUnblockedMemoryList.ForwardLink;
  while (Node != &mUnblockedMemoryList) {
    UnblockedListEntry    = BASE_CR (Node, UNBLOCKED_MEM_LIST, Link);
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
        DEBUG ((DEBUG_INFO, "%a - Identical with the request from %g\n", __FUNCTION__, &UnblockedMemEntry.IdentifierGuid));
        Status = EFI_ALREADY_STARTED;
      } else {
        // Otherwise, someone tries to unblock the memory under different attributes
        DEBUG ((
          DEBUG_INFO,
          "%a - Request clashed with %g Address: 0x%p Length: 0x%x (Pages)\n",
          __FUNCTION__,
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
        __FUNCTION__,
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
      __FUNCTION__,
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
      __FUNCTION__,
      StartAddress,
      EndAddress,
      Attributes
      ));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

Done:
  DEBUG ((DEBUG_INFO, "%a - Exit - %r\n", __FUNCTION__, Status));
  return Status;
}

/**
  Helper routine used to block requested region. The routine will loop through unblocked
  entries and try to locate the entry that matches the input based on base address and
  length. For the match entry, if the page is not already blocked, supervisor will issue
  command to block access. Once successful, the corresponding entry will be removed from
  unblocked list.

  @param[in]  BlockMemDesc        Input unblock parameters conveyed from non-MM environment

  @retval EFI_SUCCESS             The requested region properly unblocked.
  @retval EFI_ACCESS_DENIED       The request was made post lock down event.
  @retval EFI_INVALID_PARAMETER   UnblockMemParams or its ID GUID is null pointer.
  @retval EFI_ALREADY_STARTED     The requested region has illegal page attributes.
  @retval Others                  Page attribute setting/clearing routine has failed.

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
    DEBUG ((DEBUG_ERROR, "%a - Failed to SetMemAttr to unblock memory %r!\n", __FUNCTION__, Status));
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
  memory region has to be already mapped as "not present" prior to this request.
  For requests that pass security checks, the region will be marked as R/W data
  page, while the page ownership (supervisor vs. user) is determined by whether
  EFI_MEMORY_SP bit of memory descriptor's attribute is set or not.

  @param[in]  UnblockMemParams  Input unblock parameters conveyed from non-MM environment

  @retval EFI_SUCCESS             The requested region properly unblocked.
  @retval EFI_ACCESS_DENIED       The request was made post lock down event.
  @retval EFI_INVALID_PARAMETER   UnblockMemParams or its ID GUID is null pointer.
  @retval EFI_SECURITY_VIOLATION  The requested region has illegal page attributes.
  @retval EFI_OUT_OF_RESOURCES    The unblocked database failed to log new entry after
                                  processing this request.
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
      __FUNCTION__
      ));
    return EFI_ACCESS_DENIED;
  }

  // Some more sanity checks here
  if ((UnblockMemParams == NULL) ||
      IsZeroGuid (&UnblockMemParams->IdentifierGuid))
  {
    DEBUG ((DEBUG_ERROR, "%a - Invalid parameter detected - %p!\n", __FUNCTION__, UnblockMemParams));
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
      __FUNCTION__,
      UnblockMemParams->MemoryDescriptor.PhysicalStart,
      UnblockMemParams->MemoryDescriptor.NumberOfPages
      ));
    return EFI_SECURITY_VIOLATION;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a - %g requested unblocking Address: 0x%p Length: 0x%x (Pages) Attribute 0x%x\n",
    __FUNCTION__,
    &UnblockMemParams->IdentifierGuid,
    UnblockMemParams->MemoryDescriptor.PhysicalStart,
    UnblockMemParams->MemoryDescriptor.NumberOfPages,
    UnblockMemParams->MemoryDescriptor.Attribute
    ));

  Status = VerifyUnblockRequest (UnblockMemParams);
  if (Status == EFI_ALREADY_STARTED) {
    DEBUG ((DEBUG_WARN, "%a - Exact match detected, will not double unblock!\n", __FUNCTION__));
    return EFI_SUCCESS;
  } else if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Unblock request verification failed - %r!\n", __FUNCTION__, Status));
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
    DEBUG ((DEBUG_ERROR, "%a - Failed to ClearMemAttr to unblock memory %r!\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  Status = SmmSetMemoryAttributes (
             UnblockMemParams->MemoryDescriptor.PhysicalStart,
             EFI_PAGES_TO_SIZE (UnblockMemParams->MemoryDescriptor.NumberOfPages),
             Attribute
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to SetMemAttr to unblock memory %r!\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  UnblockListEntry = AllocatePool (sizeof (UNBLOCKED_MEM_LIST));
  if (UnblockListEntry == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to allocate pool for unblock memory list!\n", __FUNCTION__));
    ASSERT (FALSE);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (&UnblockListEntry->UnblockMemData, UnblockMemParams, sizeof (*UnblockMemParams));
  InsertTailList (&mUnblockedMemoryList, &UnblockListEntry->Link);

  return Status;
} // ProcessUnblockPages()
