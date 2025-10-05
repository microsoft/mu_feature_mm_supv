/** @file
  MM IPL in DXE phase that produces MM related runtime protocols.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>

#include <Protocol/SmmBase2.h>
#include <Protocol/SmmCommunication.h>
#include <Protocol/MmCommunication2.h>
#include <Protocol/SmmControl2.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/MmSupervisorCommunication.h>

#include <Guid/EventGroup.h>
#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmSupervisorRequestData.h> // MU_CHANGE: MM_SUPV: Added MM Supervisor request data structure

#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/MemoryAllocationLib.h>

#include "Common/MmIplCommon.h"

//
// Function prototypes from produced protocols
//

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication Protocol that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] This                The EFI_SMM_COMMUNICATION_PROTOCOL instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into SMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SmmCommunicationCommunicate (
  IN CONST EFI_SMM_COMMUNICATION_PROTOCOL  *This,
  IN OUT VOID                              *CommBuffer,
  IN OUT UINTN                             *CommSize OPTIONAL
  );

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The EFI_MM_COMMUNICATION_PROTOCOL instance.
  @param[in] CommBufferPhysical  Physical address of the MM communication buffer
  @param[in] CommBufferVirtual   Virtual address of the MM communication buffer
  @param[in] CommSize            The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SmmCommunicationMmCommunicate2 (
  IN CONST EFI_MM_COMMUNICATION2_PROTOCOL  *This,
  IN OUT VOID                              *CommBufferPhysical,
  IN OUT VOID                              *CommBufferVirtual,
  IN OUT UINTN                             *CommSize OPTIONAL
  );

// MU_CHANGE: MM_SUPV: Supervisor communication function prototype

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication Protocol that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PROTOCOL instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into SMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SupvCommunicationCommunicate (
  IN CONST MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *This,
  IN OUT VOID                                    *CommBuffer,
  IN OUT UINTN                                   *CommSize OPTIONAL
  );

/**
  Event notification that is fired every time a DxeSmmReadyToLock protocol is added
  or if gEfiEventReadyToBootGuid is signalled.

  @param  Event                 The Event that is being processed, not used.
  @param  Context               Event Context, not used.

**/
VOID
EFIAPI
SmmIplReadyToLockEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  );

/**
  Event notification that is fired when a GUIDed Event Group is signaled.

  @param  Event                 The Event that is being processed, not used.
  @param  Context               Event Context, not used.

**/
VOID
EFIAPI
SmmIplGuidedEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  );

/**
  Event notification that is fired when EndOfDxe Event Group is signaled.

  @param  Event                 The Event that is being processed, not used.
  @param  Context               Event Context, not used.

**/
VOID
EFIAPI
SmmIplEndOfDxeEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  );

/**
  Notification function of EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE.

  This is a notification function registered on EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE event.
  It convers pointer to new virtual address.

  @param  Event        Event whose notification function is being invoked.
  @param  Context      Pointer to the notification function's context.

**/
VOID
EFIAPI
SmmIplSetVirtualAddressNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  );

//
// Data structure used to declare a table of protocol notifications and event
// notifications required by the SMM IPL
//
typedef struct {
  BOOLEAN             Protocol;
  BOOLEAN             CloseOnLock;
  EFI_GUID            *Guid;
  EFI_EVENT_NOTIFY    NotifyFunction;
  VOID                *NotifyContext;
  EFI_TPL             NotifyTpl;
  EFI_EVENT           Event;
} SMM_IPL_EVENT_NOTIFICATION;

//
// Handle to install the SMM Base2 Protocol and the SMM Communication Protocol
//
EFI_HANDLE  mSmmIplHandle = NULL;

//
// SMM Communication Protocol instance
//
EFI_SMM_COMMUNICATION_PROTOCOL  mSmmCommunication = {
  SmmCommunicationCommunicate
};

//
// PI 1.7 MM Communication Protocol 2 instance
//
EFI_MM_COMMUNICATION2_PROTOCOL  mMmCommunication2 = {
  SmmCommunicationMmCommunicate2
};

// MU_CHANGE: MM_SUPV: Supervisor communication protocol instance
//
// PI 1.7 MM Communication Protocol 2 instance
//
MM_SUPERVISOR_COMMUNICATION_PROTOCOL  mMmSupvCommunication = {
  .Signature   = MM_SUPERVISOR_COMM_PROTOCOL_SIG,
  .Version     = MM_SUPERVISOR_COMM_PROTOCOL_VER,
  .Communicate = SupvCommunicationCommunicate
};

//
// SMM IPL global variables
//
EFI_SMM_CONTROL2_PROTOCOL  *mSmmControl2;
EFI_SMRAM_DESCRIPTOR       *mCurrentSmramRange;
BOOLEAN                    mSmmLocked = FALSE;
BOOLEAN                    mEndOfDxe  = FALSE;

// MU_CHANGE: Compared to PiSmmIpl from BASECORE, this array removed:
//            gEfiSmmConfigurationProtocolGuid  // MM_SUPV: This will never exist since it is published by MM driver
//            gEfiEventLegacyBootGuid           // Unsupported
//            gEfiEventDxeDispatchGuid          // Moved to PEI phase and replaced by gMmSupervisorDriverDispatchGuid
//
// Table of Protocol notification and GUIDed Event notifications that the SMM IPL requires
//
SMM_IPL_EVENT_NOTIFICATION  mSmmIplEvents[] = {
  //
  // Declare protocol notification on DxeSmmReadyToLock protocols.  When this notification is established,
  // the associated event is immediately signalled, so the notification function will be executed and the
  // DXE SMM Ready To Lock Protocol will be found if it is already in the handle database.
  //
  { TRUE,  TRUE,  &gEfiDxeSmmReadyToLockProtocolGuid, SmmIplReadyToLockEventNotify,  &gEfiDxeSmmReadyToLockProtocolGuid, TPL_CALLBACK, NULL },
  //
  // Declare event notification on EndOfDxe event.  When this notification is established,
  // the associated event is immediately signalled, so the notification function will be executed and the
  // SMM End Of Dxe Protocol will be found if it is already in the handle database.
  //
  { FALSE, TRUE,  &gEfiEndOfDxeEventGroupGuid,        SmmIplGuidedEventNotify,       &gEfiEndOfDxeEventGroupGuid,        TPL_CALLBACK, NULL },
  //
  // Declare event notification on EndOfDxe event.  This is used to set EndOfDxe event signaled flag.
  //
  { FALSE, TRUE,  &gEfiEndOfDxeEventGroupGuid,        SmmIplEndOfDxeEventNotify,     &gEfiEndOfDxeEventGroupGuid,        TPL_CALLBACK, NULL },
  //
  // Declare event notification on Ready To Boot Event Group.  This is an extra event notification that is
  // used to make sure SMRAM is locked before any boot options are processed.
  //
  { FALSE, TRUE,  &gEfiEventReadyToBootGuid,          SmmIplReadyToLockEventNotify,  &gEfiEventReadyToBootGuid,          TPL_CALLBACK, NULL },
  //
  // Declare event notification on Exit Boot Services Event Group.  This is used to inform the SMM Core
  // to notify SMM driver that system enter exit boot services.
  //
  { FALSE, FALSE, &gEfiEventExitBootServicesGuid,     SmmIplGuidedEventNotify,       &gEfiEventExitBootServicesGuid,     TPL_CALLBACK, NULL },
  //
  // Declare event notification on Ready To Boot Event Group.  This is used to inform the SMM Core
  // to notify SMM driver that system enter ready to boot.
  //
  { FALSE, FALSE, &gEfiEventReadyToBootGuid,          SmmIplGuidedEventNotify,       &gEfiEventReadyToBootGuid,          TPL_CALLBACK, NULL },
  //
  // Declare event notification on SetVirtualAddressMap() Event Group.  This is used to convert mMmCommBufferStatus
  // and mSmmControl2 from physical addresses to virtual addresses.
  //
  { FALSE, FALSE, &gEfiEventVirtualAddressChangeGuid, SmmIplSetVirtualAddressNotify, NULL,                               TPL_CALLBACK, NULL },
  //
  // Terminate the table of event notifications
  //
  { FALSE, FALSE, NULL,                               NULL,                          NULL,                               TPL_CALLBACK, NULL }
};

// MU_CHANGE: Abstracted function implementation of MmControl->Trigger for PEI

/**
  Abstraction layer for MM Control Trigger under various environments (PEI & DXE).
  The IPL driver will implement this functionality to be used by MM Communication
  routine.

  @retval Other             See definition of EFI_MM_ACTIVATE.

 **/
EFI_STATUS
InternalMmControlTrigger (
  VOID
  )
{
  return mSmmControl2->Trigger (mSmmControl2, NULL, NULL, FALSE, 0);
}

// MU_CHANGE: MM_SUPV: Added interface for MM Supervisor communication

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication Protocol that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PROTOCOL instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into SMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SupvCommunicationCommunicate (
  IN CONST MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *This,
  IN OUT VOID                                    *CommBuffer,
  IN OUT UINTN                                   *CommSize OPTIONAL
  )
{
  if ((This == NULL) ||
      (This->Signature != MM_SUPERVISOR_COMM_PROTOCOL_SIG) ||
      (This->Version != MM_SUPERVISOR_COMM_PROTOCOL_VER))
  {
    return EFI_INVALID_PARAMETER;
  }

  return SmmCommunicationCommunicateWorker (
           TRUE, // We are talking to supervisor here
           CommBuffer,
           CommSize
           );
}

// MU_CHANGE: Abstracted MM communicate routine to common file for both PEI and DXE file

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication Protocol that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] This                The EFI_SMM_COMMUNICATION_PROTOCOL instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into SMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SmmCommunicationCommunicate (
  IN CONST EFI_SMM_COMMUNICATION_PROTOCOL  *This,
  IN OUT VOID                              *CommBuffer,
  IN OUT UINTN                             *CommSize OPTIONAL
  )
{
  // MU_CHANGE: MM_SUPV: Abstracted implementation to SmmCommunicationCommunicateWorker for
  // DXE and PEI, Supervisor and User.
  return SmmCommunicationCommunicateWorker (FALSE, CommBuffer, CommSize);
}

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The EFI_MM_COMMUNICATION_PROTOCOL instance.
  @param[in] CommBufferPhysical  Physical address of the MM communication buffer
  @param[in] CommBufferVirtual   Virtual address of the MM communication buffer
  @param[in] CommSize            The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SmmCommunicationMmCommunicate2 (
  IN CONST EFI_MM_COMMUNICATION2_PROTOCOL  *This,
  IN OUT VOID                              *CommBufferPhysical,
  IN OUT VOID                              *CommBufferVirtual,
  IN OUT UINTN                             *CommSize OPTIONAL
  )
{
  return SmmCommunicationCommunicate (
           &mSmmCommunication,
           CommBufferVirtual,
           CommSize
           );
}

/**
  Event notification that is fired when GUIDed Event Group is signaled.

  @param  Event                 The Event that is being processed, not used.
  @param  Context               Event Context, not used.

**/
VOID
EFIAPI
SmmIplGuidedEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  SmmIplGuidedEventNotifyWorker ((EFI_GUID *)Context);
}

/**
  Event notification that is fired when EndOfDxe Event Group is signaled.

  @param  Event                 The Event that is being processed, not used.
  @param  Context               Event Context, not used.

**/
VOID
EFIAPI
SmmIplEndOfDxeEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  mEndOfDxe = TRUE;
}

/**
  Event notification that is fired every time a DxeSmmReadyToLock protocol is added
  or if gEfiEventReadyToBootGuid is signaled.

  @param  Event                 The Event that is being processed, not used.
  @param  Context               Event Context, not used.

**/
VOID
EFIAPI
SmmIplReadyToLockEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  VOID        *Interface;
  UINTN       Index;
  UINTN       Size;

  //
  // See if we are already locked
  //
  if (mSmmLocked) {
    return;
  }

  //
  // Make sure this notification is for this handler
  //
  if (CompareGuid ((EFI_GUID *)Context, &gEfiDxeSmmReadyToLockProtocolGuid)) {
    Status = gBS->LocateProtocol (&gEfiDxeSmmReadyToLockProtocolGuid, NULL, &Interface);
    if (EFI_ERROR (Status)) {
      return;
    }
  } else {
    //
    // If SMM is not locked yet and we got here from gEfiEventReadyToBootGuid being
    // signaled, then gEfiDxeSmmReadyToLockProtocolGuid was not installed as expected.
    // Print a warning on debug builds.
    //
    DEBUG ((DEBUG_WARN, "SMM IPL!  DXE SMM Ready To Lock Protocol not installed before Ready To Boot signal\n"));
  }

  if (!mEndOfDxe) {
    DEBUG ((DEBUG_ERROR, "EndOfDxe Event must be signaled before DxeSmmReadyToLock Protocol installation!\n"));
    REPORT_STATUS_CODE (
      EFI_ERROR_CODE | EFI_ERROR_UNRECOVERED,
      (EFI_SOFTWARE_SMM_DRIVER | EFI_SW_EC_ILLEGAL_SOFTWARE_STATE)
      );
    ASSERT (FALSE);
  }

  //
  // Close protocol and event notification events that do not apply after the
  // DXE SMM Ready To Lock Protocol has been installed or the Ready To Boot
  // event has been signalled.
  //
  for (Index = 0; mSmmIplEvents[Index].NotifyFunction != NULL; Index++) {
    if (mSmmIplEvents[Index].CloseOnLock) {
      gBS->CloseEvent (mSmmIplEvents[Index].Event);
    }
  }

  //
  // Inform SMM User drivers that the DxeSmmReadyToLock protocol was installed
  //
  SmmIplGuidedEventNotify (Event, (VOID *)&gEfiDxeSmmReadyToLockProtocolGuid);

  // MU_CHANGE: MM_SUPV: Specifically send ready to lock to supervisor after users
  //
  // Finally, we inform SMM Core that the DxeSmmReadyToLock protocol was installed
  //
  mCommunicateHeader = (EFI_SMM_COMMUNICATE_HEADER *)mMmSupvCommonBuffer;

  //
  // Use Guid to initialize EFI_SMM_COMMUNICATE_HEADER structure
  //
  CopyGuid (&mCommunicateHeader->HeaderGuid, (EFI_GUID *)Context);
  mCommunicateHeader->MessageLength = 1;
  mCommunicateHeader->Data[0]       = 0;

  //
  // Generate the Software SMI and return the result
  //
  Size = sizeof (EFI_SMM_COMMUNICATE_HEADER);
  SupvCommunicationCommunicate (&mMmSupvCommunication, mCommunicateHeader, &Size);

  //
  // Set flag so this operation will not be performed again
  //
  mSmmLocked = TRUE;
}

/**
  Notification function of EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE.

  This is a notification function registered on EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE event.
  It convers pointer to new virtual address.

  @param  Event        Event whose notification function is being invoked.
  @param  Context      Pointer to the notification function's context.

**/
VOID
EFIAPI
SmmIplSetVirtualAddressNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EfiConvertPointer (0x0, (VOID **)&mSmmControl2);
  // MU_CHANGE: These "external "entries need update since used in MM Communication routine
  EfiConvertPointer (0x0, (VOID **)&mMmSupvCommonBuffer);
  EfiConvertPointer (0x0, (VOID **)&mMmUserCommonBuffer);
  EfiConvertPointer (0x0, (VOID **)&mMmCommBufferStatus);
  EfiConvertPointer (0x0, (VOID **)&mMmSupvCommunication.CommunicationRegion.VirtualStart);
}

// MM_SUPV: Update communicate buffer when entering DXE.

/**
  Communicate to MmSupervisor to update the buffer to runtime pages allocated in DXE.

  @param[out] VersionInfo        Pointer to hold current version information from supervisor.
  @param[out] UpdatedCommBuffer  Pointer to hold returned comm buffer information structure.

  @retval EFI_SUCCESS            The version information was successfully queried.
  @retval EFI_INVALID_PARAMETER  The VersionInfo was NULL.
  @retval EFI_SECURITY_VIOLATION The Version returned by supervisor is invalid.
  @retval Others                 Other error status returned during communication to supervisor.

**/
EFI_STATUS
UpdateDxeCommunicateBuffer (
  IN MM_SUPERVISOR_VERSION_INFO_BUFFER  *VersionInfo,
  OUT MM_SUPERVISOR_COMM_UPDATE_BUFFER  *UpdatedCommBuffer
  )
{
  UINTN                             Size;
  EFI_STATUS                        Status;
  MM_SUPERVISOR_REQUEST_HEADER      *RequestHeader;
  MM_SUPERVISOR_COMM_UPDATE_BUFFER  *NewCommBuffer;
  VOID                              *NewUserCommBuffer;
  VOID                              *NewSupvCommBuffer;
  VOID                              *NewMmCommBufferStatus;

  if ((VersionInfo == NULL) || (UpdatedCommBuffer == NULL)) {
    ASSERT (VersionInfo != NULL);
    ASSERT (UpdatedCommBuffer != NULL);
    return EFI_INVALID_PARAMETER;
  }

  if (VersionInfo->MaxSupervisorRequestLevel < MM_SUPERVISOR_REQUEST_COMM_UPDATE) {
    // This means the supervisor is too old, cannot do such operation
    return EFI_UNSUPPORTED;
  }

  // Now we are in the real deal, start with allocating new buffers
  NewUserCommBuffer = AllocateAlignedRuntimePages (mMmUserCommonBufferPages, EFI_PAGE_SIZE);
  NewSupvCommBuffer = AllocateAlignedRuntimePages (mMmSupvCommonBufferPages, EFI_PAGE_SIZE);
  NewMmCommBufferStatus   = AllocateAlignedRuntimePages (EFI_SIZE_TO_PAGES (sizeof (MM_COMM_BUFFER_STATUS)), EFI_PAGE_SIZE);

  if ((NewUserCommBuffer == NULL) || (NewSupvCommBuffer == NULL) || (NewMmCommBufferStatus == NULL)) {
    ASSERT (NewUserCommBuffer != NULL);
    ASSERT (NewSupvCommBuffer != NULL);
    ASSERT (NewMmCommBufferStatus != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  mCommunicateHeader = (EFI_SMM_COMMUNICATE_HEADER *)mMmSupvCommonBuffer;

  // The size of supervisor communication buffer should be much larger than this value below
  Size = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
         sizeof (MM_SUPERVISOR_REQUEST_HEADER) +
         sizeof (MM_SUPERVISOR_COMM_UPDATE_BUFFER);

  // Clear up the playground first
  ZeroMem ((VOID *)(UINTN)mCommunicateHeader, Size);

  CopyGuid (&(mCommunicateHeader->HeaderGuid), &gMmSupervisorRequestHandlerGuid);
  mCommunicateHeader->MessageLength = sizeof (MM_SUPERVISOR_REQUEST_HEADER) +
                                      sizeof (MM_SUPERVISOR_COMM_UPDATE_BUFFER);

  RequestHeader            = (MM_SUPERVISOR_REQUEST_HEADER *)mCommunicateHeader->Data;
  RequestHeader->Signature = MM_SUPERVISOR_REQUEST_SIG;
  RequestHeader->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  RequestHeader->Request   = MM_SUPERVISOR_REQUEST_COMM_UPDATE;

  NewCommBuffer = (MM_SUPERVISOR_COMM_UPDATE_BUFFER *)(RequestHeader + 1);
  CopyMem (&(NewCommBuffer->NewMmCoreData.IdentifierGuid), &gEfiCallerIdGuid, sizeof (EFI_GUID));
  NewCommBuffer->NewMmCoreData.MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  NewCommBuffer->NewMmCoreData.MemoryDescriptor.Type          = EfiRuntimeServicesData;
  NewCommBuffer->NewMmCoreData.MemoryDescriptor.NumberOfPages = EFI_SIZE_TO_PAGES ((sizeof (MM_COMM_BUFFER_STATUS) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK));
  NewCommBuffer->NewMmCoreData.MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)NewMmCommBufferStatus;
  NewCommBuffer->NewMmCoreData.MemoryDescriptor.VirtualStart  = (EFI_PHYSICAL_ADDRESS)(UINTN)NewMmCommBufferStatus;

  CopyMem (&(NewCommBuffer->NewCommBuffers[MM_SUPERVISOR_BUFFER_T].IdentifierGuid), &gEfiCallerIdGuid, sizeof (EFI_GUID));
  NewCommBuffer->NewCommBuffers[MM_SUPERVISOR_BUFFER_T].MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  NewCommBuffer->NewCommBuffers[MM_SUPERVISOR_BUFFER_T].MemoryDescriptor.Type          = EfiRuntimeServicesData;
  NewCommBuffer->NewCommBuffers[MM_SUPERVISOR_BUFFER_T].MemoryDescriptor.NumberOfPages = mMmSupvCommonBufferPages;
  NewCommBuffer->NewCommBuffers[MM_SUPERVISOR_BUFFER_T].MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)NewSupvCommBuffer;
  NewCommBuffer->NewCommBuffers[MM_SUPERVISOR_BUFFER_T].MemoryDescriptor.VirtualStart  = (EFI_PHYSICAL_ADDRESS)(UINTN)NewSupvCommBuffer;

  CopyMem (&(NewCommBuffer->NewCommBuffers[MM_USER_BUFFER_T].IdentifierGuid), &gEfiCallerIdGuid, sizeof (EFI_GUID));
  NewCommBuffer->NewCommBuffers[MM_USER_BUFFER_T].MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  NewCommBuffer->NewCommBuffers[MM_USER_BUFFER_T].MemoryDescriptor.Type          = EfiRuntimeServicesData;
  NewCommBuffer->NewCommBuffers[MM_USER_BUFFER_T].MemoryDescriptor.NumberOfPages = mMmUserCommonBufferPages;
  NewCommBuffer->NewCommBuffers[MM_USER_BUFFER_T].MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)NewUserCommBuffer;
  NewCommBuffer->NewCommBuffers[MM_USER_BUFFER_T].MemoryDescriptor.VirtualStart  = (EFI_PHYSICAL_ADDRESS)(UINTN)NewUserCommBuffer;

  //
  // Generate the Software SMI and return the result
  //
  Status = SupvCommunicationCommunicate (&mMmSupvCommunication, mCommunicateHeader, &Size);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to communicate to MM through supervisor channel - %r!!\n", __FUNCTION__, Status));
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  // Re-check the return status on the new buffers.
  mMmCommBufferStatus = (MM_COMM_BUFFER_STATUS *)NewMmCommBufferStatus;
  DEBUG ((DEBUG_ERROR, "%a - Updated mMmCommMailboxBufferStatus to new location - %p!\n", __func__, mMmCommBufferStatus));
  if ((UINTN)mMmCommBufferStatus->ReturnStatus != 0) {
    Status = mMmCommBufferStatus->ReturnStatus;
    DEBUG ((DEBUG_ERROR, "%a Failed to communicate to MM to switch core mailbox - %r!!\n", __FUNCTION__, Status));
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  mCommunicateHeader = (EFI_SMM_COMMUNICATE_HEADER *)NewSupvCommBuffer;
  RequestHeader      = (MM_SUPERVISOR_REQUEST_HEADER *)mCommunicateHeader->Data;
  if ((UINTN)RequestHeader->Result != 0) {
    Status = ENCODE_ERROR ((UINTN)RequestHeader->Result);
    DEBUG ((DEBUG_ERROR, "%a Failed to switch communication channel - %r!!\n", __FUNCTION__, Status));
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  // Populate the returned buffer
  CopyMem (UpdatedCommBuffer, NewCommBuffer, sizeof (*UpdatedCommBuffer));

  // Update the global variables
  mMmUserCommonBuffer         = NewUserCommBuffer;
  mMmSupvCommonBuffer         = NewSupvCommBuffer;
  mMmUserCommonBufferPhysical = NewUserCommBuffer;
  mMmSupvCommonBufferPhysical = NewSupvCommBuffer;

  // Update supervisor communicate protocol communicate regions
  mMmSupvCommunication.CommunicationRegion.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)NewSupvCommBuffer;
  mMmSupvCommunication.CommunicationRegion.VirtualStart  = (EFI_PHYSICAL_ADDRESS)(UINTN)NewSupvCommBuffer;

Done:
  return Status;
}

/**
  Publish EFI MM communication region tables for both user and supervisor with updated buffer
  addresses.

  @param[in] UpdatedCommBuffer  Pointer to hold the updated comm buffer information structure.

  @retval EFI_SUCCESS
  @return Others          Some error occurs.
**/
EFI_STATUS
EFIAPI
PublishMmCommunicationBuffer (
  IN MM_SUPERVISOR_COMM_UPDATE_BUFFER  *UpdatedCommBuffer
  )
{
  EFI_STATUS                               Status = EFI_NOT_FOUND;
  UINT32                                   DescriptorSize;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
  EFI_MEMORY_DESCRIPTOR                    *Entry;
  // MU_CHANGE Starts: MM_SUPV: Fetch allocated communication buffer from HOBs.
  EFI_GUID                          *ConfTableGuid;
  EFI_PEI_HOB_POINTERS              GuidHob;
  MM_COMM_REGION_HOB                *CommRegionHob;
  MM_SUPERVISOR_COMM_UPDATE_BUFFER  TempCommBuffer;
  UINTN                             Index;

  PiSmmCommunicationRegionTable = NULL;

  if (UpdatedCommBuffer != NULL) {
    CopyMem (&TempCommBuffer, UpdatedCommBuffer, sizeof (*UpdatedCommBuffer));
  } else {
    ZeroMem (&TempCommBuffer, sizeof (TempCommBuffer));
    GuidHob.Guid = GetFirstGuidHob (&gMmCommonRegionHobGuid);
    // Get the information from the HOBs as before
    while (GuidHob.Guid != NULL) {
      CommRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);
      if ((CommRegionHob->MmCommonRegionType >= MM_OPEN_BUFFER_CNT)) {
        // Unrecognized buffer type, do not proceed with comm buffer table installation
        DEBUG ((DEBUG_ERROR, "%a Unsupported communication region type discovered (0x%x), the communication buffer could be misconfigured!!!\n", __FUNCTION__, CommRegionHob->MmCommonRegionType));
        Status = EFI_UNSUPPORTED;
        ASSERT (FALSE);
        goto Done;
      }

      TempCommBuffer.NewCommBuffers[CommRegionHob->MmCommonRegionType].MemoryDescriptor.NumberOfPages = CommRegionHob->MmCommonRegionPages;
      TempCommBuffer.NewCommBuffers[CommRegionHob->MmCommonRegionType].MemoryDescriptor.PhysicalStart = CommRegionHob->MmCommonRegionAddr;

      // MU_CHANGE Starts: MM_SUPV: Fetch allocated communication buffer from HOBs
      //                   And publish notification when the table is installed.
      GuidHob.Guid = GET_NEXT_HOB (GuidHob);
      GuidHob.Guid = GetNextGuidHob (&gMmCommonRegionHobGuid, GuidHob.Guid);
    }
  }

  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    PiSmmCommunicationRegionTable = NULL;
    if (Index == MM_USER_BUFFER_T) {
      ConfTableGuid = &gEdkiiPiSmmCommunicationRegionTableGuid;
    } else if (Index == MM_SUPERVISOR_BUFFER_T) {
      ConfTableGuid = &gMmSupervisorCommunicationRegionTableGuid;
    }

    DescriptorSize = sizeof (EFI_MEMORY_DESCRIPTOR);
    //
    // Make sure Size != sizeof(EFI_MEMORY_DESCRIPTOR). This will
    // prevent people from having pointer math bugs in their code.
    // now you have to use *DescriptorSize to make things work.
    //
    DescriptorSize += sizeof (UINT64) - (DescriptorSize % sizeof (UINT64));

    //
    // Allocate and fill PiSmmCommunicationRegionTable
    //
    PiSmmCommunicationRegionTable = AllocateReservedPool (sizeof (EDKII_PI_SMM_COMMUNICATION_REGION_TABLE) + DescriptorSize);
    ASSERT (PiSmmCommunicationRegionTable != NULL);
    // MU_CHANGE: MM_SUPV: Exit loop if allocation failed.
    if (PiSmmCommunicationRegionTable == NULL) {
      DEBUG ((DEBUG_ERROR, "%a Failed to allocate buffer for communication buffer table!!!\n", __FUNCTION__));
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    ZeroMem (PiSmmCommunicationRegionTable, sizeof (EDKII_PI_SMM_COMMUNICATION_REGION_TABLE) + DescriptorSize);

    PiSmmCommunicationRegionTable->Version         = EDKII_PI_SMM_COMMUNICATION_REGION_TABLE_VERSION;
    PiSmmCommunicationRegionTable->NumberOfEntries = 1;
    PiSmmCommunicationRegionTable->DescriptorSize  = DescriptorSize;
    Entry                                          = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Entry->Type                                    = EfiConventionalMemory;
    Entry->PhysicalStart                           = (EFI_PHYSICAL_ADDRESS)(UINTN)TempCommBuffer.NewCommBuffers[Index].MemoryDescriptor.PhysicalStart; // MU_CHANGE: MM_SUPV: BAR from HOB
    ASSERT (Entry->PhysicalStart != 0);
    // MU_CHANGE: MM_SUPV: Exit loop if PhysicalStart is null pointer.
    if (Entry->PhysicalStart == 0) {
      DEBUG ((
        DEBUG_ERROR,
        "%a Target HOB does not contain valid communication buffer data: type: 0x%x, addr: 0x%p, pages: 0x%x!!!\n",
        __FUNCTION__,
        Index,
        TempCommBuffer.NewCommBuffers[Index].MemoryDescriptor.PhysicalStart,
        TempCommBuffer.NewCommBuffers[Index].MemoryDescriptor.NumberOfPages
        ));
      Status = EFI_NOT_STARTED;
      goto Done;
    }

    Entry->VirtualStart  = 0;
    Entry->NumberOfPages = TempCommBuffer.NewCommBuffers[Index].MemoryDescriptor.NumberOfPages; // MU_CHANGE: MM_SUPV: Buffer size from HOB
    Entry->Attribute     = 0;

    DEBUG ((DEBUG_INFO, "PiSmmCommunicationRegionTable:(0x%x)\n", PiSmmCommunicationRegionTable));
    DEBUG ((DEBUG_INFO, "  Version         - 0x%x\n", PiSmmCommunicationRegionTable->Version));
    DEBUG ((DEBUG_INFO, "  NumberOfEntries - 0x%x\n", PiSmmCommunicationRegionTable->NumberOfEntries));
    DEBUG ((DEBUG_INFO, "  DescriptorSize  - 0x%x\n", PiSmmCommunicationRegionTable->DescriptorSize));
    DEBUG ((DEBUG_INFO, "Entry:(0x%x)\n", Entry));
    DEBUG ((DEBUG_INFO, "  Type            - 0x%x\n", Entry->Type));
    DEBUG ((DEBUG_INFO, "  PhysicalStart   - 0x%lx\n", Entry->PhysicalStart));
    DEBUG ((DEBUG_INFO, "  VirtualStart    - 0x%lx\n", Entry->VirtualStart));
    DEBUG ((DEBUG_INFO, "  NumberOfPages   - 0x%lx\n", Entry->NumberOfPages));
    DEBUG ((DEBUG_INFO, "  Attribute       - 0x%lx\n", Entry->Attribute));

    //
    // Publish this table, so that other driver can use the buffer.
    //
    Status = gBS->InstallConfigurationTable (ConfTableGuid, PiSmmCommunicationRegionTable);
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  }

Done:
  if (EFI_ERROR (Status) && (PiSmmCommunicationRegionTable != NULL)) {
    // We failed.. At least clean up the mass.
    FreePool (PiSmmCommunicationRegionTable);
  }

  // MU_CHANGE Ends: MM_SUPV.
  return Status;
}

/**
  The Entry Point for MM IPL in DXE

  Load MM Core into SMRAM, register MM Core entry point for SMIs, install
  MM Base 2 Protocol and MM Communication Protocol, and register for the
  critical events required to coordinate between DXE and MM environments.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmDxeSupportEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS             Status;
  UINTN                  Index;
  VOID                   *Registration;
  // MU_CHANGE: MM_SUPV: Test supervisor communication before publishing protocol
  MM_SUPERVISOR_VERSION_INFO_BUFFER  VersionInfo;
  MM_SUPERVISOR_COMM_UPDATE_BUFFER   NewCommBuffer;

  // MU_CHANGE: MM_SUPV: Initialize Comm buffer from HOBs first
  Status = InitializeCommunicationBufferFromHob (
             &mMmSupvCommunication.CommunicationRegion
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Failed to initialize communication buffer from HOBs - %r\n", __FUNCTION__, Status));
    return Status;
  }

  //
  // Get SMM Control2 Protocol
  //
  Status = gBS->LocateProtocol (&gEfiSmmControl2ProtocolGuid, NULL, (VOID **)&mSmmControl2);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // MU_CHANGE: MM_SUPV: We are just making sure this communication to supervisor does not fail.
  Status = QuerySupervisorVersion (&VersionInfo);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // MU_CHANGE: MM_SUPV: We are just making sure this communication to supervisor does not fail.
  Status = UpdateDxeCommunicateBuffer (&VersionInfo, &NewCommBuffer);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to switch communication channel - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // Needs clean up
  Status = PublishMmCommunicationBuffer (&NewCommBuffer);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to publish communicate buffer configuration tables - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // Query it another time to make sure the change took effect
  Status = QuerySupervisorVersion (&VersionInfo);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  // MU_CHANGE: Since we already set up everything, directly move to protocol installation.
  //
  // Install SMM Base2 Protocol and SMM Communication Protocol
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mSmmIplHandle,
                  &gEfiSmmCommunicationProtocolGuid,
                  &mSmmCommunication,
                  &gEfiMmCommunication2ProtocolGuid,
                  &mMmCommunication2,
                  &gMmSupervisorCommunicationProtocolGuid,
                  &mMmSupvCommunication,                                          // MU_CHANGE: MM_SUPV
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Create the set of protocol and event notifications that the SMM IPL requires
  //
  for (Index = 0; mSmmIplEvents[Index].NotifyFunction != NULL; Index++) {
    if (mSmmIplEvents[Index].Protocol) {
      mSmmIplEvents[Index].Event = EfiCreateProtocolNotifyEvent (
                                     mSmmIplEvents[Index].Guid,
                                     mSmmIplEvents[Index].NotifyTpl,
                                     mSmmIplEvents[Index].NotifyFunction,
                                     mSmmIplEvents[Index].NotifyContext,
                                     &Registration
                                     );
    } else {
      Status = gBS->CreateEventEx (
                      EVT_NOTIFY_SIGNAL,
                      mSmmIplEvents[Index].NotifyTpl,
                      mSmmIplEvents[Index].NotifyFunction,
                      mSmmIplEvents[Index].NotifyContext,
                      mSmmIplEvents[Index].Guid,
                      &mSmmIplEvents[Index].Event
                      );
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }
  }

  return EFI_SUCCESS;
}
