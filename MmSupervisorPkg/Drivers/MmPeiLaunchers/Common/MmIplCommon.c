/** @file
  Common internal routines shared by MM IPL in both PEI and DXE phases.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>

#include <Protocol/SmmCommunication.h>
#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/MmSupervisorRequestData.h>

#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SafeIntLib.h>

#include "MmIplCommon.h"

//
// SMM IPL global variables
//
UINT64  mMmSupvCommonBufferPages     = 0;
UINT64  mMmUserCommonBufferPages     = 0;
VOID    *mMmSupvCommonBuffer         = NULL;
VOID    *mMmUserCommonBuffer         = NULL;
VOID    *mMmSupvCommonBufferPhysical = NULL;
VOID    *mMmUserCommonBufferPhysical = NULL;

EFI_MM_COMMUNICATE_HEADER  *mCommunicateHeader  = NULL;
MM_COMM_BUFFER_STATUS      *mMmCommBufferStatus = NULL;

/**
  Helper function for MM Communication protocol or PPI.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication Protocol that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] TalkToSupervisor    Flag to indicate if this transaction will be
                                 interfacing supervisor or users.
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
SmmCommunicationCommunicateWorker (
  IN     BOOLEAN  TalkToSupervisor,
  IN OUT VOID     *CommBuffer,
  IN OUT UINTN    *CommSize OPTIONAL
  )
{
  EFI_STATUS                  Status;
  EFI_SMM_COMMUNICATE_HEADER  *CommunicateHeader;
  EFI_SMM_COMMUNICATE_HEADER  *CommunicateBufferPhysical;
  UINT64                      LongCommSize; // MU_CHANGE: BZ3398
  UINTN                       TempCommSize;

  //
  // Check parameters
  //
  if (CommBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CommunicateHeader = (EFI_SMM_COMMUNICATE_HEADER *)CommBuffer;

  if (CommSize == NULL) {
    // MU_CHANGE Starts: BZ3398 Make MessageLength the same size in EFI_MM_COMMUNICATE_HEADER for both IA32 and X64.
    Status = SafeUint64Add (OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data), CommunicateHeader->MessageLength, &LongCommSize);
    if (EFI_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }

    Status = SafeUint64ToUintn (LongCommSize, &TempCommSize);
    if (EFI_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }

    // MU_CHANGE Ends: BZ3398
  } else {
    TempCommSize = *CommSize;
    //
    // CommSize must hold HeaderGuid and MessageLength
    //
    if (TempCommSize < OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)) {
      return EFI_INVALID_PARAMETER;
    }
  }

  // MU_CHANGE Starts: MM_SUPV: Only allow MM communication data shared through buffer allocated by this IPL
  if (TalkToSupervisor) {
    CommunicateHeader         = mMmSupvCommonBuffer;
    CommunicateBufferPhysical = mMmSupvCommonBufferPhysical;
    if (EFI_SIZE_TO_PAGES (TempCommSize) > mMmSupvCommonBufferPages) {
      if (CommSize != NULL) {
        // Cannot print the error here since it could be runtime error, system might triple fault
        Status = SafeUint64ToUintn (EFI_PAGES_TO_SIZE (mMmSupvCommonBufferPages), CommSize);
        ASSERT_EFI_ERROR (Status);
      }

      return EFI_BAD_BUFFER_SIZE;
    }
    DEBUG ((DEBUG_INFO, "SmmCommunicationCommunicateWorker: Using Supervisor Communicate Buffer - %p, %p, %x\n", CommunicateHeader, CommunicateBufferPhysical, TempCommSize));
    mMmCommBufferStatus->CommunicateChannel = MM_SUPERVISOR_BUFFER_T;
  } else {
    CommunicateHeader         = mMmUserCommonBuffer;
    CommunicateBufferPhysical = mMmUserCommonBufferPhysical;
    if (EFI_SIZE_TO_PAGES (TempCommSize) > mMmUserCommonBufferPages) {
      if (CommSize != NULL) {
        // Cannot print the error here since it could be runtime error, system might triple fault
        Status = SafeUint64ToUintn (EFI_PAGES_TO_SIZE (mMmUserCommonBufferPages), CommSize);
        ASSERT_EFI_ERROR (Status);
      }

      return EFI_BAD_BUFFER_SIZE;
    }
    mMmCommBufferStatus->CommunicateChannel = MM_USER_BUFFER_T;
    DEBUG ((DEBUG_INFO, "SmmCommunicationCommunicateWorker: Using User Communicate Buffer - %p, %p, %x\n", CommunicateHeader, CommunicateBufferPhysical, TempCommSize));
  }

  if (CommunicateHeader != CommBuffer) {
    CopyMem (CommunicateHeader, CommBuffer, TempCommSize);
  }

  // MU_CHANGE Ends: MM_SUPV

  //
  // Standalone version will not have the scenario when communication protocol is ready but MM foundation is not set.
  // Thus this function should always be invoked from non-MM environment to trigger a MMI to communicate to MM core
  //
  if (mMmCommBufferStatus->IsCommBufferValid) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  //
  // Put arguments for Software SMI in mMmCommBufferStatus
  //
  mMmCommBufferStatus->IsCommBufferValid = TRUE;

  // MU_CHANGE: Use abstracted routine to trigger MM, where PEI and DXE will invoke their own MmControl->Trigger, respectively.
  //
  // Generate Software SMI
  //
  Status = InternalMmControlTrigger ();
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  // MU_CHANGE Starts: Covert UINT64 to UINTN using SafeInt routine, and use them for further operations
  Status = SafeUint64ToUintn (mMmCommBufferStatus->ReturnBufferSize, &TempCommSize);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return EFI_BAD_BUFFER_SIZE;
  }

  //
  // Return status from software SMI
  //
  if (CommSize != NULL) {
    *CommSize = TempCommSize;
  }

  if (CommunicateHeader != CommBuffer) {
    CopyMem (CommBuffer, CommunicateHeader, TempCommSize);
  }

  //
  // Convert to 32-bit Status and return
  //
  Status = EFI_SUCCESS;
  if ((UINTN)mMmCommBufferStatus->ReturnStatus != 0) {
    Status = ENCODE_ERROR ((UINTN)mMmCommBufferStatus->ReturnStatus);
  }

  return Status;
  // MU_CHANGE Ends
}

/**
  Entry point of the notification callback function itself within the PEIM.

  @param  PeiServices      Indirect reference to the PEI Services Table.
  @param  NotifyDescriptor Address of the notification descriptor data structure.
  @param  Ppi              Address of the PPI that was installed.

  @return Status of the notification.
          The status code returned from this function is ignored.
**/
EFI_STATUS
EFIAPI
SmmIplGuidedEventNotifyWorker (
  IN EFI_GUID  *NotifierGuid
  )
{
  UINTN       Size;
  EFI_STATUS  Status;

  if (NotifierGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE: Set the communication buffer to point to User buffer for this transaction
  mCommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *)mMmUserCommonBuffer;

  //
  // Use Guid to initialize EFI_MM_COMMUNICATE_HEADER structure
  //
  CopyGuid (&mCommunicateHeader->HeaderGuid, NotifierGuid);
  mCommunicateHeader->MessageLength = 1;
  mCommunicateHeader->Data[0]       = 0;

  //
  // Generate the Software SMI and return the result
  //
  Size   = sizeof (EFI_MM_COMMUNICATE_HEADER);
  Status = SmmCommunicationCommunicateWorker (FALSE, mCommunicateHeader, &Size);

  return Status;
}

// MU_CHANGE Starts: MM_SUPV: Fetch allocated communication buffer from HOBs

/**
  Helper function that iterates each HOB of gMmCommonRegionHobGuid to cache
  designated communication buffer for later use.

  @param[out]  SupvCommonRegionDesc     Holder of detailed information about
                                        Supervisor communication protocol/PPI.

  @retval EFI_SUCCESS                   The entry point is executed successfully.
  @retval EFI_INVALID_PARAMETER         Input parameter is NULL.
  @retval EFI_NOT_FOUND                 One or more of the expected communication
                                        buffers are not discovered or with NULL
                                        values.

**/
EFI_STATUS
EFIAPI
InitializeCommunicationBufferFromHob (
  OUT EFI_MEMORY_DESCRIPTOR  *SupvCommonRegionDesc
  )
{
  EFI_STATUS            Status;
  EFI_PEI_HOB_POINTERS  GuidHob;
  MM_COMM_REGION_HOB    *CommRegionHob;
  MM_COMM_BUFFER        *CommBuffer;

  if (SupvCommonRegionDesc == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Incoming memory descriptor cannot be NULL!!!\n", __func__));
    return EFI_INVALID_PARAMETER;
  }

  GuidHob.Guid = GetFirstGuidHob (&gMmCommonRegionHobGuid);
  if (GuidHob.Guid == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Did not locate any published hob to create communication buffer table!!!\n", __func__));
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }

  Status = EFI_SUCCESS;
  CommRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);
  if (CommRegionHob->MmCommonRegionType == MM_SUPERVISOR_BUFFER_T) {
    if ((mMmSupvCommonBufferPages != 0) || (mMmSupvCommonBuffer != NULL)) {
      Status = EFI_ALREADY_STARTED;
    }

    mMmSupvCommonBufferPages    = CommRegionHob->MmCommonRegionPages;
    mMmSupvCommonBuffer         = (VOID *)(UINTN)CommRegionHob->MmCommonRegionAddr;
    mMmSupvCommonBufferPhysical = mMmSupvCommonBuffer;

    SupvCommonRegionDesc->Type          = EfiRuntimeServicesData;
    SupvCommonRegionDesc->PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)mMmSupvCommonBuffer;
    SupvCommonRegionDesc->VirtualStart  = (EFI_PHYSICAL_ADDRESS)(UINTN)mMmSupvCommonBuffer;
    SupvCommonRegionDesc->NumberOfPages = mMmSupvCommonBufferPages;
    SupvCommonRegionDesc->Attribute     = 0;
  } else {
    DEBUG ((DEBUG_ERROR, "%a - Invalid common buffer type %x."
      "Please make sure the user buffer is published through gMmCommBufferHobGuid!!\n", __func__, CommRegionHob->MmCommonRegionType));
    Status = EFI_UNSUPPORTED;
  }

  // Cover the user level buffer, through the EDK2 way...
  if ((mMmUserCommonBufferPages == 0) && (mMmUserCommonBuffer == NULL)) {
    GuidHob.Guid = GetFirstGuidHob (&gMmCommBufferHobGuid);
    if (GuidHob.Guid == NULL) {
      DEBUG ((DEBUG_ERROR, "Failed to find MM Communication Buffer HOB\n"));
      DEBUG ((DEBUG_ERROR, "Only Root MMI Handlers will be supported!\n"));
      return Status;
    }
    CommBuffer = (MM_COMM_BUFFER *)GET_GUID_HOB_DATA (GuidHob.Guid);
    mMmUserCommonBufferPages    = CommBuffer->NumberOfPages;
    mMmUserCommonBuffer         = (VOID *)(UINTN)CommBuffer->PhysicalStart;
    mMmUserCommonBufferPhysical = mMmUserCommonBuffer;
    mMmCommBufferStatus         = (MM_COMM_BUFFER_STATUS*)(UINTN)CommBuffer->Status;
  } else {
    Status = EFI_ALREADY_STARTED;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Error occurred during locating communication buffer from HOBs - %r\n", Status));
  } else if ((mMmUserCommonBufferPages == 0) || (mMmUserCommonBuffer == NULL)) {
    DEBUG ((DEBUG_ERROR, "Did not find User communication buffer from HOBs\n"));
    Status = EFI_NOT_FOUND;
  } else if ((mMmSupvCommonBufferPages == 0) || (mMmSupvCommonBuffer == NULL)) {
    DEBUG ((DEBUG_ERROR, "Did not find Supervisor communication buffer from HOBs\n"));
    Status = EFI_NOT_FOUND;
  }

  return Status;
}

// MU_CHANGE Ends: MM_SUPV

// MU_CHANGE Starts: MM_SUPV: Test supervisor communication before publishing protocol

/**
  Communicate to MmSupervisor to query version information, as defined in
  MM_SUPERVISOR_VERSION_INFO_BUFFER.

  @param[out] VersionInfo        Pointer to hold returned version information structure.

  @retval EFI_SUCCESS            The version information was successfully queried.
  @retval EFI_INVALID_PARAMETER  The VersionInfo was NULL.
  @retval EFI_SECURITY_VIOLATION The Version returned by supervisor is invalid.
  @retval Others                 Other error status returned during communication to supervisor.

**/
EFI_STATUS
QuerySupervisorVersion (
  OUT MM_SUPERVISOR_VERSION_INFO_BUFFER  *VersionInfo
  )
{
  UINTN                         Size;
  EFI_STATUS                    Status;
  MM_SUPERVISOR_REQUEST_HEADER  *RequestHeader;

  if (VersionInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mCommunicateHeader = (EFI_SMM_COMMUNICATE_HEADER *)mMmSupvCommonBuffer;

  // The size of supervisor communication buffer should be much larger than this value below
  Size = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
         sizeof (MM_SUPERVISOR_REQUEST_HEADER) +
         sizeof (MM_SUPERVISOR_VERSION_INFO_BUFFER);

  // Clear up the playground first
  ZeroMem ((VOID *)(UINTN)mCommunicateHeader, Size);

  CopyGuid (&(mCommunicateHeader->HeaderGuid), &gMmSupervisorRequestHandlerGuid);
  mCommunicateHeader->MessageLength = sizeof (MM_SUPERVISOR_REQUEST_HEADER) + sizeof (MM_SUPERVISOR_VERSION_INFO_BUFFER);

  RequestHeader            = (MM_SUPERVISOR_REQUEST_HEADER *)mCommunicateHeader->Data;
  RequestHeader->Signature = MM_SUPERVISOR_REQUEST_SIG;
  RequestHeader->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  RequestHeader->Request   = MM_SUPERVISOR_REQUEST_VERSION_INFO;

  //
  // Generate the Software SMI and return the result
  //
  Status = SmmCommunicationCommunicateWorker (TRUE, mCommunicateHeader, &Size);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to communicate to MM through supervisor channel - %r!!\n", __func__, Status));
    return Status;
  }

  Status = EFI_SUCCESS;
  if ((UINTN)RequestHeader->Result != 0) {
    Status = ENCODE_ERROR ((UINTN)RequestHeader->Result);
  }

  CopyMem (
    VersionInfo,
    (MM_SUPERVISOR_VERSION_INFO_BUFFER *)(RequestHeader + 1),
    sizeof (MM_SUPERVISOR_VERSION_INFO_BUFFER)
    );

  DEBUG ((
    DEBUG_INFO,
    "%a Supervisor version is 0x%x, patch level is 0x%x, maximal request level is 0x%x!!\n",
    __func__,
    VersionInfo->Version,
    VersionInfo->PatchLevel,
    VersionInfo->MaxSupervisorRequestLevel
    ));

  if (VersionInfo->Version == 0) {
 #ifdef __GNUC__
    DEBUG ((DEBUG_WARN, "%a Unable to get supervisor version under GCC compiler!!\n", __func__));
 #else
    // This means the supervisor version is 0, something must be wrong...
    return EFI_SECURITY_VIOLATION;
 #endif
  }

  return EFI_SUCCESS;
}

// MU_CHANGE Ends: MM_SUPV
