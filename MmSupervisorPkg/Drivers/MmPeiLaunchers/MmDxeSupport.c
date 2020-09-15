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
#include <Guid/MmCoreData.h>
#include <Guid/MmSupervisorRequestData.h> // MU_CHANGE: MM_SUPV: Added MM Supervisor request data structure

#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/ReportStatusCodeLib.h>

#include "Common/MmIplCommon.h"

//
// Function prototypes from produced protocols
//

/**
  Indicate whether the driver is currently executing in the SMM Initialization phase.

  @param   This                    The EFI_MM_BASE_PROTOCOL instance.
  @param   InSmram                 Pointer to a Boolean which, on return, indicates that the driver is currently executing
                                   inside of SMRAM (TRUE) or outside of SMRAM (FALSE).

  @retval  EFI_INVALID_PARAMETER   InSmram was NULL.
  @retval  EFI_SUCCESS             The call returned successfully.

**/
EFI_STATUS
EFIAPI
SmmBase2InSmram (
  IN CONST EFI_MM_BASE_PROTOCOL  *This,
  OUT      BOOLEAN               *InSmram
  );

/**
  Retrieves the location of the System Management System Table (Mmst).

  @param   This                    The EFI_MM_BASE_PROTOCOL instance.
  @param   Mmst                    On return, points to a pointer to the System Management Service Table (MMST).

  @retval  EFI_INVALID_PARAMETER   Mmst or This was invalid.
  @retval  EFI_SUCCESS             The memory was returned to the system.
  @retval  EFI_UNSUPPORTED         Not in SMM.

**/
EFI_STATUS
EFIAPI
SmmBase2GetSmstLocation (
  IN CONST EFI_MM_BASE_PROTOCOL  *This,
  OUT      EFI_MM_SYSTEM_TABLE   **Mmst
  );

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
// SMM Base 2 Protocol instance
//
EFI_MM_BASE_PROTOCOL  mSmmBase2 = {
  SmmBase2InSmram,
  SmmBase2GetSmstLocation
};

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

// MU_CHANGE: MM_SUPV: Designated a pointer for core private data as it is allocated runtime
//
// Global pointer used to access mSmmCorePrivateData from outside and inside SMM
//
MM_CORE_PRIVATE_DATA  *gMmCorePrivate = NULL;

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
  // Declare event notification on SetVirtualAddressMap() Event Group.  This is used to convert gMmCorePrivate
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

/**
  Indicate whether the driver is currently executing in the SMM Initialization phase.

  @param   This                    The EFI_MM_BASE_PROTOCOL instance.
  @param   InSmram                 Pointer to a Boolean which, on return, indicates that the driver is currently executing
                                   inside of SMRAM (TRUE) or outside of SMRAM (FALSE).

  @retval  EFI_INVALID_PARAMETER   InSmram was NULL.
  @retval  EFI_SUCCESS             The call returned successfully.

**/
EFI_STATUS
EFIAPI
SmmBase2InSmram (
  IN CONST EFI_MM_BASE_PROTOCOL  *This,
  OUT      BOOLEAN               *InSmram
  )
{
  if (InSmram == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *InSmram = gMmCorePrivate->InMm;

  return EFI_SUCCESS;
}

/**
  Retrieves the location of the System Management System Table (SMST).

  @param   This                    The EFI_MM_BASE_PROTOCOL instance.
  @param   Smst                    On return, points to a pointer to the System Management Service Table (SMST).

  @retval  EFI_INVALID_PARAMETER   Smst or This was invalid.
  @retval  EFI_SUCCESS             The memory was returned to the system.
  @retval  EFI_UNSUPPORTED         Not in SMM.

**/
EFI_STATUS
EFIAPI
SmmBase2GetSmstLocation (
  IN CONST EFI_MM_BASE_PROTOCOL  *This,
  OUT      EFI_MM_SYSTEM_TABLE   **Mmst
  )
{
  if ((This == NULL) || (Mmst == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (!gMmCorePrivate->InMm) {
    return EFI_UNSUPPORTED;
  }

  *Mmst = (EFI_MM_SYSTEM_TABLE *)(UINTN)gMmCorePrivate->Mmst;

  return EFI_SUCCESS;
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
  EfiConvertPointer (0x0, (VOID **)&gMmCorePrivate);
  EfiConvertPointer (0x0, (VOID **)&mMmSupvCommunication.CommunicationRegion.VirtualStart);
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
  MM_CORE_DATA_HOB_DATA  *DataInHob;
  EFI_PEI_HOB_POINTERS   HobPointer;
  // MU_CHANGE: MM_SUPV: Test supervisor communication before publishing protocol
  MM_SUPERVISOR_VERSION_INFO_BUFFER  VersionInfo;

  // MU_CHANGE: MM_SUPV: Initialize Comm buffer from HOBs first
  Status = InitializeCommunicationBufferFromHob (
             &mMmSupvCommunication.CommunicationRegion
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Failed to initialize communication buffer from HOBs - %r\n", __FUNCTION__, Status));
    return Status;
  }

  // MU_CHANGE: Fetch allocated gMmCorePrivate address from HOB data
  // Here we allocate the core private data and copy the data
  HobPointer.Guid = GetFirstGuidHob (&gMmCoreDataHobGuid);
  if (HobPointer.Guid == NULL) {
    return EFI_DEVICE_ERROR;
  }

  DataInHob      = GET_GUID_HOB_DATA (HobPointer.Guid);
  gMmCorePrivate = (MM_CORE_PRIVATE_DATA *)(UINTN)DataInHob->Address;

  //
  // Get SMM Control2 Protocol
  //
  Status = gBS->LocateProtocol (&gEfiSmmControl2ProtocolGuid, NULL, (VOID **)&mSmmControl2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // MU_CHANGE: MM_SUPV: We are just making sure this communication to supervisor does not fail.
  Status = QuerySupervisorVersion (&VersionInfo);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // MU_CHANGE: Since we already set up everything, directly move to protocol installation.
  //
  // Install SMM Base2 Protocol and SMM Communication Protocol
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mSmmIplHandle,
                  &gEfiSmmBase2ProtocolGuid,
                  &mSmmBase2,
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
