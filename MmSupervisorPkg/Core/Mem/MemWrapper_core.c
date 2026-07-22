/** @file
  Core (MmSupervisorCore) communicate-buffer validation helpers.

  Linked only into the runtime MmSupervisorCore driver.  These routines verify
  that an incoming MMI communicate buffer falls within the supervisor- or
  user-owned internal copy.  MmSupervisorInit does not validate communicate
  buffers (it has no MMI handlers to dispatch into), so it provides its own
  abridged VerifyRequestSupvCommBuffer in MemWrapper_init.c.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include "MmSupervisorCore.h"
#include "Mem.h"

/**
  Helper function to validate legitimacy for incoming communcate buffer for MMI handler.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.
  @param  CommBufferType  Type of the CommBuffer being evaluated, i.e. MM_SUPERVISOR_BUFFER_T or
                          MM_USER_BUFFER_T.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize,
  IN  UINTN  CommBufferType
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  CommBuffStart;
  EFI_PHYSICAL_ADDRESS  CommBuffEnd;
  EFI_PHYSICAL_ADDRESS  InternalBuffSize;
  EFI_PHYSICAL_ADDRESS  InternalBuffEnd;

  if (CommBufferType >= MM_OPEN_BUFFER_CNT) {
    DEBUG ((DEBUG_ERROR, "%a Unrecognized buffer type requested - %x!!!\n", __func__, CommBufferType));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  CommBuffStart = (EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer;
  Status        = SafeUint64Add (CommBuffStart, CommBufferSize, &CommBuffEnd);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Buffer end calculation failed - %r!!!\n", __func__, Status));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Status = SafeUint64Mult (mMmSupervisorAccessBuffer[CommBufferType].NumberOfPages, EFI_PAGE_SIZE, &InternalBuffSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Supervisor buffer size calculation failed - %r!!!\n", __func__, Status));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Status = SafeUint64Add ((UINTN)mInternalCommBufferCopy[CommBufferType], InternalBuffSize, &InternalBuffEnd);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Supervisor buffer end calculation failed - %r!!!\n", __func__, Status));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if ((CommBuffStart < (EFI_PHYSICAL_ADDRESS)(UINTN)mInternalCommBufferCopy[CommBufferType]) ||
      (CommBuffEnd > InternalBuffEnd))
  {
    Status = EFI_SECURITY_VIOLATION;
    DEBUG ((
      DEBUG_ERROR,
      "%a Input argument %p - %p does not reside in designated communication buffer %p - %p\n",
      __func__,
      CommBuffer,
      CommBuffEnd,
      mInternalCommBufferCopy[CommBufferType],
      InternalBuffEnd
      ));
    goto Exit;
  }

Exit:
  return Status;
}

/**
  Helper function to validate legitimacy for incoming supervisor communcate buffer for MMI handlers.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestSupvCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize
  )
{
  return VerifyRequestCommBuffer (
           CommBuffer,
           CommBufferSize,
           MM_SUPERVISOR_BUFFER_T
           );
}

/**
  Helper function to validate legitimacy for incoming user communcate buffer for MMI handlers.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestUserCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize
  )
{
  return VerifyRequestCommBuffer (
           CommBuffer,
           CommBufferSize,
           MM_USER_BUFFER_T
           );
}
