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

/**
  Event notification that is fired when a GUIDed Event Group is signaled.

  @param  PeiServices      Indirect reference to the PEI Services Table.
  @param  NotifyDescriptor Address of the notification descriptor data structure.
  @param  Ppi              Address of the PPI that was installed.

  @return Status of the notification.
          The status code returned from this function is ignored.

**/
EFI_STATUS
EFIAPI
SmmIplGuidedEventNotify (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
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
EFI_PEI_MM_ACCESS_PPI   *mSmmAccess;
EFI_MMRAM_DESCRIPTOR    *mCurrentMmramRange;
EFI_PHYSICAL_ADDRESS    mMmramCacheBase;
UINT64                  mMmramCacheSize;

// MU_CHANGE: Loaded Fixed Address information is unsupported
// EFI_LOAD_FIXED_ADDRESS_CONFIGURATION_TABLE    *mLMFAConfigurationTable = NULL;

//
// Table of PPI notification and GUIDed Event notifications that the SMM IPL requires
//
STATIC EFI_PEI_NOTIFY_DESCRIPTOR  mPeiMmIplNotifyList =
{
  //
  // Declare event notification on Exit Boot Services Event Group.  This is used to inform the SMM Core
  // to notify SMM driver that system enter exit boot services.
  //
  (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiEndOfPeiSignalPpiGuid,
  SmmIplGuidedEventNotify
};

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
  // Use Guid to initialize EFI_MM_COMMUNICATE_HEADER structure
  // Clear the buffer passed into the Software SMI.  This buffer will return
  // the status of the SMM Core Dispatcher.
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
    Status = *(EFI_STATUS*)mCommunicateHeader->Data;
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
MmIplPeiEntry (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINT64      MaxSize;
  UINTN       Size;
  UINTN       MmramRangeCount;
  EFI_MMRAM_DESCRIPTOR  *MmramRanges;
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
  // Get SMM Access PPI
  //
  Status = (*PeiServices)->LocatePpi (
                             PeiServices,
                             &gEfiPeiMmAccessPpiGuid,
                             0,
                             NULL,
                             (VOID **)&mSmmAccess
                             );
  ASSERT_EFI_ERROR (Status);

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

  //
  // Open all SMRAM ranges
  //
  // MU_CHANGE Starts: Need to iterate through all MMRAMs to open one at a time for PPI interface
  Size   = 0;
  Status = mSmmAccess->GetCapabilities ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, &Size, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    // This is not right...
    ASSERT (FALSE);
    return EFI_DEVICE_ERROR;
  }

  MmramRanges = AllocatePool (Size);
  if (MmramRanges == NULL) {
    ASSERT (MmramRanges != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = mSmmAccess->GetCapabilities ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, &Size, MmramRanges);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SMM IPL failed to get SMRAM capabilities - %r\n", Status));
    ASSERT (FALSE);
    return Status;
  }

  MmramRangeCount = Size / sizeof (EFI_MMRAM_DESCRIPTOR);
  // MU_CHANGE Ends

  //
  // Find the largest SMRAM range between 1MB and 4GB that is at least 256KB - 4K in size
  //
  mCurrentMmramRange = NULL;
  for (Index = 0, MaxSize = SIZE_256KB - EFI_PAGE_SIZE; (UINT64)Index < MmramRangeCount; Index++) {
    //
    // Skip any SMRAM region that is already allocated, needs testing, or needs ECC initialization
    //
    if ((MmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    if (MmramRanges[Index].CpuStart >= BASE_1MB) {
      if ((MmramRanges[Index].CpuStart + MmramRanges[Index].PhysicalSize - 1) <= MAX_ADDRESS) {
        if (MmramRanges[Index].PhysicalSize >= MaxSize) {
          MaxSize            = MmramRanges[Index].PhysicalSize;
          mCurrentMmramRange = &MmramRanges[Index];
        }
      }
    }
  }

  //
  // Close all SMRAM ranges
  //
  // MU_CHANGE: Iterate through each MMRAM for PPI instance
  for (Index = 0; Index < MmramRangeCount; Index++) {
    Status = mSmmAccess->Close ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, Index);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SMM IPL failed to close SMRAM windows index %d - %r\n", Index, Status));
      ASSERT (FALSE);
      return Status;
    }

    //
    // Print debug message that the SMRAM window is now closed.
    //
    DEBUG ((DEBUG_INFO, "MM IPL closed SMRAM window index %d\n", Index));
  }

  // MU_CHANGE: MM_SUPV: Locked immediately after closing instead of waiting for ready to lock event
  //
  // Lock the SMRAM (Note: Locking SMRAM may not be supported on all platforms)
  //
  for (Index = 0; Index < MmramRangeCount; Index++) {
    Status = mSmmAccess->Lock ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, Index);
    if (EFI_ERROR (Status)) {
      //
      // Print error message that the SMRAM failed to lock...
      //
      DEBUG ((DEBUG_ERROR, "MM IPL could not lock MMRAM (Index %d) after executing MM Core %r\n", Index, Status));
      ASSERT (FALSE);
      return Status;
    }

    //
    // Print debug message that the SMRAM window is now closed.
    //
    DEBUG ((DEBUG_INFO, "MM IPL locked SMRAM window index %d\n", Index));
  }

  SECURITY_LOCK_REPORT_EVENT ("Lock MMRAM", HARDWARE_LOCK); // MSCHANGE

  //
  // Print debug message that the SMRAM window is now locked.
  //
  DEBUG ((DEBUG_INFO, "SMM IPL locked SMRAM window\n"));

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
  // If the SMM Core could not be loaded then close SMRAM window, free allocated
  // resources, and return an error so SMM IPL will be unloaded.
  //
  if ((mCurrentMmramRange == NULL) || EFI_ERROR (Status)) {
    //
    // Free all allocated resources
    //
    FreePool ((VOID *)MmramRanges);

    return EFI_UNSUPPORTED;
  }

  //
  // Install MM Communication and Supervisor MM Communication PPI
  //
  Status = (*PeiServices)->InstallPpi (PeiServices, mPeiMmIplPpiList);
  ASSERT_EFI_ERROR (Status);

  //
  // Create the set of ppi and event notifications that the SMM IPL requires
  //
  Status = (*PeiServices)->NotifyPpi (PeiServices, &mPeiMmIplNotifyList);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
