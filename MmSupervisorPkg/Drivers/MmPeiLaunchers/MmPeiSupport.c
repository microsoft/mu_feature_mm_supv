/** @file
  MM IPL in PEI that produces MM related PPIs and load the MM Core into MMRAM

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>
#include <PiPei.h>

#include <Protocol/SmmCommunication.h>
#include <Ppi/MmAccess.h>
#include <Ppi/MmControl.h>
#include <Ppi/SmmCommunication.h>
#include <Ppi/EndOfPeiPhase.h>
#include <Ppi/MmSupervisorCommunication.h>

#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/MmSupervisorRequestData.h> // MU_CHANGE: MM_SUPV: Added MM Supervisor request data structure
#include <Guid/MmramMemoryReserve.h>

#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PanicLib.h>

#include <Library/SafeIntLib.h>           // MU_CHANGE: BZ3398
#include <Library/SecurityLockAuditLib.h> // MSCHANGE

#include "Common/CommonHeader.h"
#include "Common/MmIplCommon.h"
#ifdef MDE_CPU_IA32
  #include "IA32/X64Loader.h"
#endif

#define SMRAM_CAPABILITIES  (EFI_MEMORY_WB | EFI_MEMORY_UC)

//
// Function prototypes from produced PPIs
//

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The EFI_PEI_SMM_COMMUNICATION_PPI instance.
  @param[in] CommBuffer          A pointer to the buffer to convey into SMRAM.
  @param[in] CommSize            The size of the data buffer being passed in.On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
**/
EFI_STATUS
EFIAPI
SmmCommunicationCommunicate (
  IN CONST EFI_PEI_SMM_COMMUNICATION_PPI  *This,
  IN OUT VOID                             *CommBuffer,
  IN OUT UINTN                            *CommSize
  );

// MU_CHANGE: MM_SUPV: Supervisor communication function prototype

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PPI instance.
  @param[in] CommBuffer          A pointer to the buffer to convey into SMRAM.
  @param[in] CommSize            The size of the data buffer being passed in.On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
**/
EFI_STATUS
EFIAPI
SupvCommunicationCommunicate (
  IN CONST MM_SUPERVISOR_COMMUNICATION_PPI  *This,
  IN OUT VOID                               *CommBuffer,
  IN OUT UINTN                              *CommSize OPTIONAL
  );

// MU_CHANGE: MM_SUPV: Supervisor communication PPI instance
//
// Supervisor MM Communication PPI instance
//
MM_SUPERVISOR_COMMUNICATION_PPI  mMmSupvCommunication = {
  .Signature   = MM_SUPERVISOR_COMM_PPI_SIG,
  .Version     = MM_SUPERVISOR_COMM_PPI_VER,
  .Communicate = SupvCommunicationCommunicate
};

//
// List of PPIs to be installed at the success of MM foundation setup
//
STATIC EFI_PEI_PPI_DESCRIPTOR  mPeiMmIplPpiList[] =
{
  {
    (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
    &gPeiMmSupervisorCommunicationPpiGuid,
    &mMmSupvCommunication
  }
};

//
// SMM IPL global variables
//
EFI_PEI_MM_CONTROL_PPI  *mSmmControl;
EFI_PHYSICAL_ADDRESS    mMmramCacheBase;
UINT64                  mMmramCacheSize;

// MU_CHANGE: Abstracted function implementation of MmControl->Trigger for PEI

/**
  Abstraction layer for MM Control Trigger under various environments (PEI & DXE).
  The IPL driver will implement this functionality to be used by MM Communication
  routine.

  @retval Others            See definition of EFI_MM_ACTIVATE.

 **/
EFI_STATUS
InternalMmControlTrigger (
  VOID
  )
{
  return mSmmControl->Trigger ((EFI_PEI_SERVICES **)GetPeiServicesTablePointer (), mSmmControl, NULL, NULL, FALSE, 0);
}

// MU_CHANGE: MM_SUPV: MM Supervisor communication protocol, used to query MM policy,
//            region unblock, driver dispatching

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PPI instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into MMRAM.
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
  IN CONST MM_SUPERVISOR_COMMUNICATION_PPI  *This,
  IN OUT VOID                               *CommBuffer,
  IN OUT UINTN                              *CommSize OPTIONAL
  )
{
  if ((This == NULL) ||
      (This->Signature != MM_SUPERVISOR_COMM_PPI_SIG) ||
      (This->Version != MM_SUPERVISOR_COMM_PPI_VER))
  {
    return EFI_INVALID_PARAMETER;
  }

  return SmmCommunicationCommunicateWorker (
           TRUE,
           CommBuffer,
           CommSize
           );
}

// MU_CHANGE Starts: MM_SUPV: Will immediately signal MM core to dispatch MM drivers

/**
  Invokes the MM core to dispatch drivers from inside MM environment. This
  function will only be called after MM foundation is successfully set.

  @return Status of the notification.
          The status code returned from this function is ignored.
**/
EFI_STATUS
EFIAPI
MmDriverDispatchNotify (
  VOID
  )
{
  UINTN       Size;
  EFI_STATUS  Status;

  // MU_CHANGE: MM_SUPV: Driver dispatcher command only deals with supervisor
  mCommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *)mMmSupvCommonBuffer;

  //
  // This is actually an empty payload command, but the EFI_MM_COMMUNICATE_HEADER structure
  // comes with a payload of at least one byte. So we set the MessageLength to 1 and
  // the first byte to 0.
  //
  CopyGuid (&(mCommunicateHeader->HeaderGuid), &gMmSupervisorDriverDispatchGuid);
  mCommunicateHeader->MessageLength = 1;
  mCommunicateHeader->Data[0]       = 0;

  //
  // Generate the Software SMI and return the result
  //
  Size   = sizeof (EFI_MM_COMMUNICATE_HEADER);
  Status = SupvCommunicationCommunicate (&mMmSupvCommunication, mCommunicateHeader, &Size);

  //
  // Return if there is no request to restart the MM Core Dispatcher
  //
  if (Status != EFI_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "MM Driver Dispatch failed (%r)\n", Status));
    return Status;
  }

  //
  // Get the status returned from the MM Core Dispatcher
  //
  if (Size >= sizeof (EFI_STATUS)) {
    Status = *(EFI_STATUS *)mCommunicateHeader->Data;
  } else {
    Status = EFI_DEVICE_ERROR;
  }

  return Status;
}

// MU_CHANGE Ends: MM_SUPV

/**
  The Entry Point for PEI MM IPL

  Load MM Core into MMRAM, register MM Core entry point for SMIs, install
  MM Communication PPI (both for user and supervisor), and register for the
  critical events required to coordinate between PEI and MM environments.

  @param[in]  FileHandle    Not used.
  @param[in]  PeiServices   General purpose services available to every PEIM.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval Other             Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmPeiSupportEntry (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS                         Status;
  MM_SUPERVISOR_VERSION_INFO_BUFFER  VersionInfo;

  Status = PeiServicesRegisterForShadow (FileHandle);

  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // MU_CHANGE: MM_SUPV: Initialize Comm buffer from HOBs first
  Status = InitializeCommunicationBufferFromHob (
             &mMmSupvCommunication.CommunicationRegion
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Failed to initialize communication buffer from HOBs - %r\n", __func__, Status));
    return Status;
  }

  //
  // Get SMM Control PPI
  //
  Status = (*PeiServices)->LocatePpi (
                             PeiServices,
                             &gEfiPeiMmControlPpiGuid,
                             0,
                             NULL,
                             (VOID **)&mSmmControl
                             );
  ASSERT_EFI_ERROR (Status);

  // MU_CHANGE: MM_SUPV: We are just making sure this communication to supervisor does not fail after setup.
  Status = QuerySupervisorVersion (&VersionInfo);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // MU_CHANGE: MM_SUPV: Added a forced trigger to load all drivers in MM
  //
  // Trigger to dispatch MM drivers from inside MM
  //
  if (!EFI_ERROR (Status)) {
    Status = MmDriverDispatchNotify ();
    DEBUG ((DEBUG_INFO, "MM driver dispatching returned - %r\n", Status));
  }

  //
  // Install MM Communication and Supervisor MM Communication PPI
  //
  Status = (*PeiServices)->InstallPpi (PeiServices, mPeiMmIplPpiList);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
