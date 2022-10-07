/** @file
Implementation of SMM CPU Services Protocol.

Copyright (c) 2011 - 2022, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Protocol/SmmConfiguration.h>

#include <Library/LocalApicLib.h>

#include "MmSupervisorCore.h"
#include "CpuService.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"

//
// SMM CPU Service Protocol instance
//
EFI_SMM_CPU_SERVICE_PROTOCOL  mSmmCpuService = {
  SmmGetProcessorInfo,
  NULL,
  NULL,
  NULL,
  SmmWhoAmI,
  NULL,
};

/**
  Gets processor information on the requested processor at the instant this call is made.

  @param[in]  This                 A pointer to the EFI_SMM_CPU_SERVICE_PROTOCOL instance.
  @param[in]  ProcessorNumber      The handle number of processor.
  @param[out] ProcessorInfoBuffer  A pointer to the buffer where information for
                                   the requested processor is deposited.

  @retval EFI_SUCCESS             Processor information was returned.
  @retval EFI_INVALID_PARAMETER   ProcessorInfoBuffer is NULL.
  @retval EFI_INVALID_PARAMETER   ProcessorNumber is invalid.
  @retval EFI_NOT_FOUND           The processor with the handle specified by
                                  ProcessorNumber does not exist in the platform.

**/
EFI_STATUS
EFIAPI
SmmGetProcessorInfo (
  IN CONST EFI_SMM_CPU_SERVICE_PROTOCOL  *This,
  IN       UINTN                         ProcessorNumber,
  OUT      EFI_PROCESSOR_INFORMATION     *ProcessorInfoBuffer
  )
{
  //
  // Check parameter
  //
  if ((ProcessorNumber >= mMaxNumberOfCpus) || (ProcessorInfoBuffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (gSmmCpuPrivate->ProcessorInfo[ProcessorNumber].ProcessorId == INVALID_APIC_ID) {
    return EFI_NOT_FOUND;
  }

  //
  // Fill in processor information
  //
  CopyMem (ProcessorInfoBuffer, &gSmmCpuPrivate->ProcessorInfo[ProcessorNumber], sizeof (EFI_PROCESSOR_INFORMATION));
  return EFI_SUCCESS;
}

/**
  This return the handle number for the calling processor.

  @param[in] This                 A pointer to the EFI_SMM_CPU_SERVICE_PROTOCOL instance.
  @param[out] ProcessorNumber      The handle number of currently executing processor.

  @retval EFI_SUCCESS             The current processor handle number was returned
                                  in ProcessorNumber.
  @retval EFI_INVALID_PARAMETER   ProcessorNumber is NULL.

**/
EFI_STATUS
EFIAPI
SmmWhoAmI (
  IN CONST EFI_SMM_CPU_SERVICE_PROTOCOL  *This,
  OUT      UINTN                         *ProcessorNumber
  )
{
  UINTN   Index;
  UINT64  ApicId;

  //
  // Check parameter
  //
  if (ProcessorNumber == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ApicId = GetApicId ();

  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId == ApicId) {
      *ProcessorNumber = Index;
      return EFI_SUCCESS;
    }
  }

  //
  // This should not happen
  //
  ASSERT (FALSE);
  return EFI_NOT_FOUND;
}

/**
  Update the SMM CPU list per the pending operation.

  This function is called after return from SMI handlers.
**/
VOID
SmmCpuUpdate (
  VOID
  )
{
  UINTN  Index;

  //
  // Handle pending BSP switch operations
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->Operation[Index] == SmmCpuSwitchBsp) {
      gSmmCpuPrivate->Operation[Index]    = SmmCpuNone;
      mSmmMpSyncData->SwitchBsp           = TRUE;
      mSmmMpSyncData->CandidateBsp[Index] = TRUE;
    }
  }

  //
  // Handle pending hot-add operations
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->Operation[Index] == SmmCpuAdd) {
      gSmmCpuPrivate->Operation[Index] = SmmCpuNone;
      mNumberOfCpus++;
    }
  }

  //
  // Handle pending hot-remove operations
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->Operation[Index] == SmmCpuRemove) {
      gSmmCpuPrivate->Operation[Index] = SmmCpuNone;
      mNumberOfCpus--;
    }
  }
}

/**
  Register exception handler.

  @param  This                  A pointer to the SMM_CPU_SERVICE_PROTOCOL instance.
  @param  ExceptionType         Defines which interrupt or exception to hook. Type EFI_EXCEPTION_TYPE and
                                the valid values for this parameter are defined in EFI_DEBUG_SUPPORT_PROTOCOL
                                of the UEFI 2.0 specification.
  @param  InterruptHandler      A pointer to a function of type EFI_CPU_INTERRUPT_HANDLER
                                that is called when a processor interrupt occurs.
                                If this parameter is NULL, then the handler will be uninstalled.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval EFI_ALREADY_STARTED   InterruptHandler is not NULL, and a handler for InterruptType was previously installed.
  @retval EFI_INVALID_PARAMETER InterruptHandler is NULL, and a handler for InterruptType was not previously installed.
  @retval EFI_UNSUPPORTED       The interrupt specified by InterruptType is not supported.

**/
EFI_STATUS
EFIAPI
SmmRegisterExceptionHandler (
  IN EFI_SMM_CPU_SERVICE_PROTOCOL  *This,
  IN EFI_EXCEPTION_TYPE            ExceptionType,
  IN EFI_CPU_INTERRUPT_HANDLER     InterruptHandler
  )
{
  return RegisterCpuInterruptHandler (ExceptionType, InterruptHandler);
}

/**
  Wait for all processors enterring SMM until all CPUs are already synchronized or not.
  If BlockingMode is False, timeout value is zero.
  @param This          A pointer to the EDKII_SMM_CPU_RENDEZVOUS_PROTOCOL instance.
  @param BlockingMode  Blocking mode or non-blocking mode.
  @retval EFI_SUCCESS  All avaiable APs arrived.
  @retval EFI_TIMEOUT  Wait for all APs until timeout.
**/
EFI_STATUS
EFIAPI
SmmCpuRendezvous (
  IN EDKII_SMM_CPU_RENDEZVOUS_PROTOCOL  *This,
  IN BOOLEAN                            BlockingMode
  )
{
  EFI_STATUS  Status;

  //
  // Return success immediately if all CPUs are already synchronized.
  //
  if (mSmmMpSyncData->AllApArrivedWithException) {
    Status = EFI_SUCCESS;
    goto ON_EXIT;
  }

  if (!BlockingMode) {
    Status = EFI_TIMEOUT;
    goto ON_EXIT;
  }

  //
  // There are some APs outside SMM, Wait for all avaiable APs to arrive.
  //
  SmmWaitForApArrival ();
  Status = mSmmMpSyncData->AllApArrivedWithException ? EFI_SUCCESS : EFI_TIMEOUT;

ON_EXIT:
  if (!mSmmMpSyncData->AllApArrivedWithException) {
    DEBUG ((DEBUG_INFO, "EdkiiSmmWaitForAllApArrival: Timeout to wait all APs arrival\n"));
  }

  return Status;
}
