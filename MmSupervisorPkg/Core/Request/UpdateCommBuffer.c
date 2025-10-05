/** @file UpdateCommBuffer.c
  Handles requests to update MM communication buffer.

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (C) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>

#include <Guid/MmSupervisorRequestData.h>

#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>

#include "MmSupervisorCore.h"
#include "Request.h"
#include "Mem/Mem.h"

BOOLEAN  mAlreadyMoved = FALSE;

EFI_STATUS
ProcessBlockPages (
  IN MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *BlockMemDesc
  );

/**
  Check if old memory region is already unblocked and whether the new memory
  block has the only difference of base address. If all checks pass, the system
  will unblock the new region and block the old one.

  @retval EFI_SUCCESS             The requested region properly moved.
  @retval EFI_SECURITY_VIOLATION  The requested memory descriptor does not match.
  @retval EFI_INVALID_PARAMETER   Either input is null.
  @retval Others                  Errors from block/unblock processes.

**/
EFI_STATUS
VerifyandMoveUnblockedPages (
  IN MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *NewMemParam,
  IN MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *OldMemParam
  )
{
  EFI_STATUS  Status;

  if ((NewMemParam == NULL) || (OldMemParam == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a - Incoming buffers are NULL - %p and %p!\n", __func__, NewMemParam, OldMemParam));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (NewMemParam->MemoryDescriptor.NumberOfPages != OldMemParam->MemoryDescriptor.NumberOfPages) {
    DEBUG ((DEBUG_ERROR, "%a - Incoming buffers are of different sizes, this is not allowed!\n", __func__));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  if (NewMemParam->MemoryDescriptor.Attribute != OldMemParam->MemoryDescriptor.Attribute) {
    DEBUG ((DEBUG_ERROR, "%a - Incoming buffers are of different attributes, this is not allowed!\n", __func__));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  if (NewMemParam->MemoryDescriptor.Type != OldMemParam->MemoryDescriptor.Type) {
    DEBUG ((DEBUG_ERROR, "%a - Incoming buffers are of different types, this is not allowed!\n", __func__));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  // Okay, again, enough complaints, now get to work.
  Status = ProcessUnblockPages (NewMemParam);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to unblock the requested new communicate buffers - %r!\n", __func__, Status));
    goto Done;
  }

  Status = ProcessBlockPages (OldMemParam);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to block memory %r!\n", __func__, Status));
    goto Done;
  }

Done:
  return Status;
}

/**
  Routine used to update communication buffers and core private mailbox region
  to the updated location. Given this routine could receive untrusted data, the
  old memory region has to be already properly unblocked prior to this request and
  the received new buffer has to persist exactly the same memory length and attribute
  as before. For requests that pass security checks, the new region will be marked
  as R/W supervisor data page. The old buffers will be blocked after this routine,
  and new return status will be populated to the new address. The caller should be
  prepared to check data from newly supplied region upon returning.

  @param[in]  UpdateCommBuffer  Input new comm buffer parameters conveyed from non-MM environment

  @retval EFI_SUCCESS             The requested region properly unblocked.
  @retval EFI_ACCESS_DENIED       The request was made post lock down event.
  @retval EFI_INVALID_PARAMETER   UnblockMemParams or its ID GUID is null pointer.
  @retval EFI_SECURITY_VIOLATION  The requested region has illegal page attributes.
  @retval EFI_OUT_OF_RESOURCES    The unblocked database failed to log new entry after
                                  processing this request.
  @retval Others                  Page attribute setting/clearing routine has failed.

**/
EFI_STATUS
ProcessUpdateCommBufferRequest (
  IN MM_SUPERVISOR_COMM_UPDATE_BUFFER  *UpdateCommBuffer
  )
{
  EFI_STATUS                           Status = EFI_SUCCESS;
  UINTN                                Index;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  MmCoreDataDesc;

  if ((mMmReadyToLockDone) || (mAlreadyMoved)) {
    // Note that this flag will be set once the policy is requested
    DEBUG ((
      DEBUG_ERROR,
      "%a - Comm buffer update requested after ready to lock, will not proceed!\n",
      __func__
      ));
    return EFI_ACCESS_DENIED;
  }

  // Some more sanity checks here
  if (UpdateCommBuffer == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid parameter detected - %p!\n", __func__, UpdateCommBuffer));
    return EFI_INVALID_PARAMETER;
  }

  // Prepare the playground...
  ZeroMem (&MmCoreDataDesc, sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS));

  // Now attempt to move the old pages to the newly supplied buffers
  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    CopyMem (&(MmCoreDataDesc.MemoryDescriptor), &(mMmSupervisorAccessBuffer[Index]), sizeof (MmCoreDataDesc.MemoryDescriptor));
    Status = VerifyandMoveUnblockedPages (&UpdateCommBuffer->NewCommBuffers[Index], &MmCoreDataDesc);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - Failed to moved unblocked buffer (%d) - %r!\n", __func__, Index, Status));
      goto Done;
    }

    // Then update the cached global variables.
    CopyMem (&mMmSupervisorAccessBuffer[Index], &(UpdateCommBuffer->NewCommBuffers[Index].MemoryDescriptor), sizeof (mMmSupervisorAccessBuffer[0]));
  }

  // Next deal with the mMmCommMailboxBufferStatus
  // Craft a temp block for the existing buffer
  MmCoreDataDesc.MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommMailboxBufferStatus;
  MmCoreDataDesc.MemoryDescriptor.NumberOfPages = EFI_SIZE_TO_PAGES ((sizeof (MM_COMM_BUFFER_STATUS) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK));
  MmCoreDataDesc.MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  Status                                        = VerifyandMoveUnblockedPages (&UpdateCommBuffer->NewMmCoreData, &MmCoreDataDesc);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to moved unblocked buffer (%d) - %r!\n", __func__, Index, Status));
    goto Done;
  }

  // Then update the cached global variable and prepare for the content fix up.
  mMmCommMailboxBufferStatus = (MM_COMM_BUFFER_STATUS *)(UINTN)UpdateCommBuffer->NewMmCoreData.MemoryDescriptor.PhysicalStart;
  DEBUG ((DEBUG_ERROR, "%a - Updated mMmCommMailboxBufferStatus to new location - %p!\n", __func__, mMmCommMailboxBufferStatus));

  // Note: The content on the original communicate buffer and mMmCommMailboxBufferStatus will be restored to the new buffer,
  // so no need to worry about copy contents here.

  mAlreadyMoved = TRUE;

Done:
  return Status;
} // ProcessUpdateCommBufferRequest()
