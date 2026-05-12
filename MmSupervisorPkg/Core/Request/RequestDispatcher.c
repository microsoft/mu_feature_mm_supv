/** @file  RequestDispatcher.c
  Dispatchs supervisor requests to specific handlers.

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
#include <Library/PcdLib.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"
#include "Request.h"

/**
  Software MMI handler that is called when a supervisor service is requested.
  See Guid/MmSupervisorRequestData.h for the supported capabilities of this routine

  @param  DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmSupvRequestHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  EFI_STATUS                    Status = EFI_SUCCESS;
  MM_SUPERVISOR_REQUEST_HEADER  *MmSupvRequestHeader;
  UINTN                         ExpectedSize;

  //
  // Validate some input parameters.
  //
  // If either of the pointers are NULL, we can't proceed.
  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer pointers!\n", __func__));
    return EFI_INVALID_PARAMETER;
  }

  Status = VerifyRequestSupvCommBuffer (CommBuffer, *CommBufferSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Input buffer %p is illegal - %r!!!\n", __func__, CommBuffer, Status));
    return Status;
  }

  // If the size does not meet a minimum threshold, we cannot proceed.
  ExpectedSize = sizeof (MM_SUPERVISOR_REQUEST_HEADER);
  if (*CommBufferSize < ExpectedSize) {
    DEBUG ((DEBUG_ERROR, "%a - Bad comm buffer size! %d < %d\n", __func__, *CommBufferSize, ExpectedSize));
    return EFI_INVALID_PARAMETER;
  }

  // Check the revision and the signature of the comm header.
  MmSupvRequestHeader = CommBuffer;
  if ((MmSupvRequestHeader->Signature != MM_SUPERVISOR_REQUEST_SIG) ||
      (MmSupvRequestHeader->Revision != MM_SUPERVISOR_REQUEST_REVISION))
  {
    DEBUG ((DEBUG_ERROR, "%a - Signature or revision are incorrect!\n", __func__));
    // We have verified the buffer is not null and have enough size to hold Result field.
    MmSupvRequestHeader->Result = EFI_INVALID_PARAMETER;
    return EFI_SUCCESS;
  }

  //
  // Now we can process the command as it was sent.
  //
  MmSupvRequestHeader->Result = EFI_ABORTED;    // Set a default return for incomplete commands.
  switch (MmSupvRequestHeader->Request) {
    case MM_SUPERVISOR_REQUEST_UNBLOCK_MEM:
      ExpectedSize += sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS);
      if (*CommBufferSize < ExpectedSize) {
        DEBUG ((
          DEBUG_ERROR,
          "%a - Unblock param block has bad comm buffer size! %d < %d\n",
          __func__,
          *CommBufferSize,
          ExpectedSize
          ));
        return EFI_INVALID_PARAMETER;
      }

      MmSupvRequestHeader->Result = ProcessUnblockPages ((MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS *)(MmSupvRequestHeader + 1));
      break;

    case MM_SUPERVISOR_REQUEST_FETCH_POLICY:
      // Use the common buffer to host policy data, and indicate the maximal data allowed
      ExpectedSize                = *CommBufferSize - ExpectedSize;
      MmSupvRequestHeader->Result = FetchNUpdateSecurityPolicy ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(MmSupvRequestHeader + 1), ExpectedSize);
      if (!EFI_ERROR (MmSupvRequestHeader->Result)) {
        *CommBufferSize = sizeof (MM_SUPERVISOR_REQUEST_HEADER) + ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(MmSupvRequestHeader + 1))->Size;
      }

      break;

    case MM_SUPERVISOR_REQUEST_VERSION_INFO:
      ExpectedSize += sizeof (MM_SUPERVISOR_VERSION_INFO_BUFFER);
      if (*CommBufferSize < ExpectedSize) {
        DEBUG ((
          DEBUG_ERROR,
          "%a - Version info query has bad comm buffer size! %d < %d\n",
          __func__,
          *CommBufferSize,
          ExpectedSize
          ));
        return EFI_INVALID_PARAMETER;
      }

      MmSupvRequestHeader->Result = ProcessVersionInfoRequest (
                                      (MM_SUPERVISOR_VERSION_INFO_BUFFER *)(MmSupvRequestHeader + 1)
                                      );
      break;

    case MM_SUPERVISOR_REQUEST_COMM_UPDATE:
      ExpectedSize += sizeof (MM_SUPERVISOR_COMM_UPDATE_BUFFER);
      if (*CommBufferSize < ExpectedSize) {
        DEBUG ((
          DEBUG_ERROR,
          "%a - Communication buffer update has bad buffer size! %d < %d\n",
          __func__,
          *CommBufferSize,
          ExpectedSize
          ));
        return EFI_INVALID_PARAMETER;
      }

      MmSupvRequestHeader->Result = ProcessUpdateCommBufferRequest (
                                      (MM_SUPERVISOR_COMM_UPDATE_BUFFER *)(MmSupvRequestHeader + 1)
                                      );
      break;

    default:
      // Mark unknown requested command as EFI_UNSUPPORTED.
      DEBUG ((DEBUG_ERROR, "%a - Invalid command requested! %d\n", __func__, MmSupvRequestHeader->Request));
      MmSupvRequestHeader->Result = EFI_UNSUPPORTED;
      break;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a - Request %d returning %r.\n",
    __func__,
    MmSupvRequestHeader->Request,
    MmSupvRequestHeader->Result
    ));

  return Status;
} // MmSupvRequestHandler()
