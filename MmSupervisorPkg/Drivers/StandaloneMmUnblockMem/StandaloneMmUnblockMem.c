/** @file
  A function that publishes gMmSupervisorUnblockMemoryProtocolGuid that communicates
  unblock memory request to MM Core.

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Guid/MmSupervisorRequestData.h>

#include <Protocol/MmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/MmSupervisorUnblockMemoryProtocol.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PerformanceLib.h>

BOOLEAN                               mReadyToLockOccurred    = FALSE;
MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *mMmCommunicateProtocol = NULL;

EFI_STATUS
EFIAPI
MmIplRequestUnblockPages (
  IN EFI_PHYSICAL_ADDRESS  UnblockAddress,
  IN UINT64                NumberOfPages,
  IN CONST EFI_GUID        *IdentifierGuid
  );

MM_SUPERVISOR_UNBLOCK_MEMORY_PROTOCOL  mMmUnblockMemProtocol = {
  .Version             = MM_UNBLOCK_REQUEST_PROTOCOL_VERSION,
  .RequestUnblockPages = MmIplRequestUnblockPages
};

/**
  This interface provides a way to requested data pages to be legit to access inside MM environment.

  @param  UnblockAddress          The address of buffer caller requests to unblock, the address
                                  has to be page aligned.
  @param  NumberOfPages           The number of pages requested to be unblocked from MM
                                  environment.

  @return EFI_SUCCESS             The request passes evaluation successfully.
  @return EFI_NO_MAPPING          The requested address region is not found from memory map.
  @return EFI_ACCESS_DENIED       The request is rejected due to memory type incorrect.
 */
STATIC
EFI_STATUS
EvaluateRequestedRegion (
  IN EFI_PHYSICAL_ADDRESS  UnblockAddress,
  IN UINT64                NumberOfPages
  )
{
  EFI_STATUS             Status;
  UINTN                  EfiMemoryMapSize;
  UINTN                  EfiMapKey;
  UINTN                  EfiDescriptorSize;
  UINT32                 EfiDescriptorVersion;
  EFI_MEMORY_DESCRIPTOR  *EfiMemoryMap;
  EFI_MEMORY_DESCRIPTOR  *EfiMemoryMapEnd;
  EFI_MEMORY_DESCRIPTOR  *EfiMemNext;
  EFI_PHYSICAL_ADDRESS   TestAddress;
  UINT64                 TestRange;

  PERF_FUNCTION_BEGIN ();

  DEBUG_CODE_BEGIN ();

  DEBUG ((
    DEBUG_INFO,
    "%a Checking against address 0x%p - 0x%p %d\n",
    __func__,
    UnblockAddress,
    UnblockAddress + EFI_PAGES_TO_SIZE (NumberOfPages),
    NumberOfPages
    ));

  DEBUG_CODE_END ();

  //
  // Get the EFI memory map.
  //
  EfiMemoryMapSize = 0;
  EfiMemoryMap     = NULL;
  Status           = gBS->GetMemoryMap (
                            &EfiMemoryMapSize,
                            EfiMemoryMap,
                            &EfiMapKey,
                            &EfiDescriptorSize,
                            &EfiDescriptorVersion
                            );
  //
  // Loop to allocate space for the memory map and then copy it in.
  //
  do {
    EfiMemoryMap = (EFI_MEMORY_DESCRIPTOR *)AllocateZeroPool (EfiMemoryMapSize);
    ASSERT (EfiMemoryMap != NULL);
    Status = gBS->GetMemoryMap (
                    &EfiMemoryMapSize,
                    EfiMemoryMap,
                    &EfiMapKey,
                    &EfiDescriptorSize,
                    &EfiDescriptorVersion
                    );
    if (EFI_ERROR (Status)) {
      FreePool (EfiMemoryMap);
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  EfiMemoryMapEnd = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)EfiMemoryMap + EfiMemoryMapSize);
  EfiMemNext      = EfiMemoryMap;

  TestAddress = UnblockAddress;
  TestRange   = NumberOfPages;
  Status      = EFI_NO_MAPPING;
  while (EfiMemNext < EfiMemoryMapEnd && TestRange > 0) {
    if ((EfiMemNext->PhysicalStart <= TestAddress) &&
        (TestAddress < (EfiMemNext->PhysicalStart + EFI_PAGES_TO_SIZE (EfiMemNext->NumberOfPages))))
    {
      if ((EfiMemNext->Type != EfiReservedMemoryType) &&
          (EfiMemNext->Type != EfiRuntimeServicesCode) &&
          (EfiMemNext->Type != EfiRuntimeServicesData) &&
          (EfiMemNext->Type != EfiACPIMemoryNVS))
      {
        DEBUG ((DEBUG_INFO, "%a Evaluation failed due to memory type is unexpected %x\n", __func__, EfiMemNext->Type));
        Status = EFI_ACCESS_DENIED;
        break;
      } else if (((EfiMemNext->Type == EfiRuntimeServicesCode) || (EfiMemNext->Type == EfiRuntimeServicesData)) &&
                 ((EfiMemNext->Attribute & EFI_MEMORY_RO) != 0))
      {
        DEBUG ((DEBUG_INFO, "%a Evaluation failed due to runtime memory region is marked as read only\n", __func__));
        Status = EFI_ACCESS_DENIED;
        break;
      } else {
        if (TestRange > (EfiMemNext->PhysicalStart + EFI_PAGES_TO_SIZE (EfiMemNext->NumberOfPages) - TestAddress)) {
          TestAddress = EfiMemNext->PhysicalStart + EFI_PAGES_TO_SIZE (EfiMemNext->NumberOfPages);
          TestRange  -= EFI_SIZE_TO_PAGES (EfiMemNext->PhysicalStart + EFI_PAGES_TO_SIZE (EfiMemNext->NumberOfPages) - TestAddress);
        } else {
          // Mark the validate range to be 0 and it should bail on the next iteration
          TestRange = 0;
        }
      }
    }

    EfiMemNext = NEXT_MEMORY_DESCRIPTOR (EfiMemNext, EfiDescriptorSize);
  }

  if (TestRange == 0) {
    Status = EFI_SUCCESS;
  }

  if (EfiMemoryMap) {
    FreePool (EfiMemoryMap);
  }

  PERF_FUNCTION_END ();

  return Status;
}

/**
  This API provides a way to unblock certain data pages to be accessible inside MM environment.

  The requested buffer needs to be page size aligned and mapped as data pages. The unblocked
  buffer will labeled as CPL3 data pages accessible by user mode drivers. MM supervisor will
  reject the unblock request after Ready-To-Lock event.

  @param  UnblockAddress          The address of buffer caller requests to unblock, the address
                                  has to be page aligned.
  @param  NumberOfPages           The number of pages requested to be unblocked from MM
                                  environment.
  @param  IdentifierGuid          The unique caller ID from requester.

  @return EFI_SUCCESS             The request goes through successfully.
  @return EFI_SECURITY_VIOLATION  The requested address failed to pass security check for
                                  unblocking.
  @return EFI_INVALID_PARAMETER   Input address or caller ID is either NULL pointer or not aligned.
  @return EFI_ACCESS_DENIED       The request is rejected by MM supervisor due to memory map is
                                  locked down.
  @return EFI_NOT_READY           The request cannot be processed due to the MM communicate
                                  foundation is not ready.
  @return EFI_OUT_OF_RESOURCES    Cannot prepare enough memory resource for communication.

**/
EFI_STATUS
EFIAPI
MmIplRequestUnblockPages (
  IN EFI_PHYSICAL_ADDRESS  UnblockAddress,
  IN UINT64                NumberOfPages,
  IN CONST EFI_GUID        *IdentifierGuid
  )
{
  EFI_STATUS                           Status;
  EFI_MM_COMMUNICATE_HEADER            *CommHeader;
  MM_SUPERVISOR_REQUEST_HEADER         *RequestBuffer;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *UnblockBuffer;
  UINTN                                CommBufferSize;

  // Step 1: Basic sanity check
  if ((IdentifierGuid == NULL) ||
      (UnblockAddress == 0) ||
      UnblockAddress & (EFI_PAGE_SIZE - 1))
  {
    DEBUG ((
      DEBUG_ERROR,
      "%a Input argument of address %p or identifier GUID %p is invalid!\n",
      __func__,
      UnblockAddress,
      IdentifierGuid
      ));
    return EFI_INVALID_PARAMETER;
  }

  if (NumberOfPages == 0) {
    // This is dumb...
    DEBUG ((DEBUG_WARN, "%a Requesting to unblock 0 pages, return here!\n", __func__));
    return EFI_SUCCESS;
  }

  if (mReadyToLockOccurred) {
    // Someone must have done something terrible...
    DEBUG ((DEBUG_ERROR, "%a Request is blocked after exit boot services, how did you get here?\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  if (mMmCommunicateProtocol == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Communicate protocol is not in place, cannot process the request\n", __func__));
    return EFI_NOT_READY;
  }

  Status = EvaluateRequestedRegion (UnblockAddress, NumberOfPages);
  if (EFI_ERROR (Status)) {
    // Someone must have done something terrible...
    DEBUG ((DEBUG_ERROR, "%a Requested address did not pass evaluation %r\n", __func__, Status));
    return EFI_ACCESS_DENIED;
  }

  // Step 2: Start to populate contents

  // Step 2.1: MM Communication common header
  CommBufferSize = sizeof (MM_SUPERVISOR_REQUEST_HEADER) +
                   sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS) +
                   OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  CommHeader = (EFI_MM_COMMUNICATE_HEADER *)AllocatePool (CommBufferSize);
  ASSERT (CommHeader != NULL);
  if (CommHeader == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (CommHeader, CommBufferSize);
  CopyGuid (&CommHeader->HeaderGuid, &gMmSupervisorRequestHandlerGuid);
  CommHeader->MessageLength = sizeof (MM_SUPERVISOR_REQUEST_HEADER) +
                              sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS);

  // Step 2.2: MM_SUPERVISOR_REQUEST_HEADER content per our needs
  RequestBuffer            = (MM_SUPERVISOR_REQUEST_HEADER *)(CommHeader->Data);
  RequestBuffer->Signature = MM_SUPERVISOR_REQUEST_SIG;
  RequestBuffer->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  RequestBuffer->Request   = MM_SUPERVISOR_REQUEST_UNBLOCK_MEM;
  RequestBuffer->Result    = EFI_SUCCESS;

  // Step 2.3: MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS content per our needs
  UnblockBuffer = (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS *)(RequestBuffer + 1);
  CopyGuid (&UnblockBuffer->IdentifierGuid, IdentifierGuid);
  UnblockBuffer->MemoryDescriptor.Type          = EfiRuntimeServicesData;
  UnblockBuffer->MemoryDescriptor.PhysicalStart = UnblockAddress;
  UnblockBuffer->MemoryDescriptor.VirtualStart  = 0;
  UnblockBuffer->MemoryDescriptor.NumberOfPages = NumberOfPages;
  UnblockBuffer->MemoryDescriptor.Attribute     = 0;

  // Step 3: Ready to signal Mmi.
  Status = mMmCommunicateProtocol->Communicate (mMmCommunicateProtocol, CommHeader, &CommBufferSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed from MmCommunication protocol - %r\n", __func__, Status));
    return Status;
  }

  // Step 4: Just print the error here
  if (EFI_ERROR (RequestBuffer->Result)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed from MmCommunication protocol - %r\n", __func__, RequestBuffer->Result));
  }

  return RequestBuffer->Result;
}

/**
Callback of exit boot event. This will unregister RSC handler in this module.

@param[in]  Event                     Event whose notification function is being invoked.
@param[in]  Context                   The pointer to the notification function's context, which is
                                      implementation-dependent.
**/
STATIC
VOID
EFIAPI
MmUnblockMemReadyToLockNotify (
  IN  EFI_EVENT  Event,
  IN  VOID       *Context
  )
{
  DEBUG ((DEBUG_INFO, "%a: enter...\n", __func__));

  mReadyToLockOccurred = TRUE;
}

/**
Register Exit Boot callback and process previous errors when variable service is ready

@param[in]  Event                 Event whose notification function is being invoked.
@param[in]  Context               The pointer to the notification function's context, which is
                                  implementation-dependent.
**/
STATIC
VOID
EFIAPI
SetupUnblockMemProtocol (
  IN  EFI_EVENT  Event,
  IN  VOID       *Context
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  UnusedHandle = NULL;
  EFI_EVENT   TempEvent;

  if (mMmCommunicateProtocol == NULL) {
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&mMmCommunicateProtocol);
    if (EFI_ERROR (Status)) {
      // Should not happen
      DEBUG ((DEBUG_ERROR, "%a Failed to locate Mm communicate protocol - %r!\n", __func__, Status));
      goto Done;
    }
  }

  Status = gBS->InstallProtocolInterface (
                  &UnusedHandle,
                  &gMmSupervisorUnblockMemoryProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMmUnblockMemProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to publish Mm unblock memory protocol - %r!\n", __func__, Status));
    goto Done;
  }

  // register for the exit boot event
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  MmUnblockMemReadyToLockNotify,
                  NULL,
                  &gEfiDxeSmmReadyToLockProtocolGuid,
                  &TempEvent
                  );
  if (EFI_ERROR (Status) != FALSE) {
    DEBUG ((DEBUG_ERROR, "%a failed to register ready to lock for unblock memory (%r)\n", __func__, Status));
    goto Done;
  }

Done:
  if (EFI_ERROR (Status) && (TempEvent != NULL)) {
    gBS->CloseEvent (TempEvent);
  }
}

/**
  Routine to initialize MM Supervisor unblock memory protocol

  @param[in] ImageHandle  Image handle of this driver.
  @param[in] SystemTable  A Pointer to the EFI System Table.

  @retval EFI_SUCCESS
  @return Others          Some error occurs.
**/
EFI_STATUS
EFIAPI
MmSupervisorUnblockMemProtocolInit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status = EFI_NOT_FOUND;
  EFI_EVENT   Event;
  VOID        *UnusedRegistration;

  // Check if MM Communicate is available yet
  Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&mMmCommunicateProtocol);
  if (EFI_ERROR (Status)) {
    // Create notify if not already published
    Status = gBS->CreateEvent (
                    EVT_NOTIFY_SIGNAL,
                    TPL_NOTIFY,
                    SetupUnblockMemProtocol,
                    NULL,
                    &Event
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a failed to create event for unblock memory (%r)\n", __func__, Status));
      goto Done;
    }

    //
    // Register for protocol notifications on this event
    //
    Status = gBS->RegisterProtocolNotify (
                    &gMmSupervisorCommunicationProtocolGuid,
                    Event,
                    &UnusedRegistration
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a failed to register mm communication callback (%r)\n", __func__, Status));
      goto Done;
    }
  } else {
    SetupUnblockMemProtocol (NULL, NULL);
  }

Done:
  if (EFI_ERROR (Status) && (Event != NULL)) {
    gBS->CloseEvent (Event);
  }

  return Status;
}
