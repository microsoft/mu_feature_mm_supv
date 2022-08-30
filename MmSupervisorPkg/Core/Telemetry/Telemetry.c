/** @file
Implementation of SMM CPU Services Protocol.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <MmSupvTelemetryData.h>

#include <Library/ResetSystemLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/CpuExceptionHandlerLib.h>

#include "MmSupervisorCore.h"
#include "Relocate/Relocate.h"
#include "Services/CpuService/CpuService.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"
#include "Mem/Mem.h"
#include "Services/MpService/MpService.h"

#define          MM_SUPV_RETRY_CNT  1

SPIN_LOCK  *mCpuExceptionToken       = NULL;
UINT8      *mCpuExceptionCountBuffer = NULL;

/**
  Routine for error reporting inside supervisor exception handlers.

  Note: This routine should be called atomically.

  @param  InterruptType         Defines which interrupt or exception to hook. Type EFI_EXCEPTION_TYPE and
                                the valid values for this parameter are defined in EFI_DEBUG_SUPPORT_PROTOCOL
                                of the UEFI 2.0 specification.
  @param  SystemContext         Pointer to EFI_SYSTEM_CONTEXT, inherited from register exception handlers.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval EFI_OUT_OF_RESOURCES  Telemetry data cannot fit in the user page supervisor allocated.
  @retval EFI_NOT_READY         There is no error reporting handler registered at the point of exception.
  @retval EFI Errors            Other errors from other routines inside this function.

**/
EFI_STATUS
EFIAPI
PrepareNReportError (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  EFI_STATUS            Status;
  EFI_GUID              DriverGuid;
  EFI_PHYSICAL_ADDRESS  DriverAddr;
  UINT64                FaultRIP;
  UINTN                 CpuIndex;

  MM_SUPV_TELEMETRY_DATA  *TelemtryData;

  // NOTE: This routine should be called after grabbing spinlock for this thread!!!

  // Return if there is no CPL3 report registration
  if (RegErrorReportJumpPointer == 0) {
    Status = EFI_NOT_READY;
    goto Done;
  }

  // First populate data in our playground
  TelemtryData = (MM_SUPV_TELEMETRY_DATA *)(SupervisorToUserDataBuffer + 1);
  ZeroMem (TelemtryData, sizeof (MM_SUPV_TELEMETRY_DATA));

  TelemtryData->Signature     = MM_SUPV_TELEMETRY_SIGNATURE;
  TelemtryData->TelemetrySize = sizeof (MM_SUPV_TELEMETRY_DATA);
  if (EFI_SIZE_TO_PAGES (TelemtryData->TelemetrySize + sizeof (MM_SUPV_TELEMETRY_DATA)) >
      DEFAULT_SUPV_TO_USER_BUFFER_PAGE)
  {
    // Cannot fit in the pages we allocated for supervisor to fill in data
    DEBUG ((DEBUG_INFO, "%a Cannot fit in supervisor allocated user pages:\n", __FUNCTION__));
    DEBUG ((DEBUG_INFO, "\t Common data size: %x\n", sizeof (MM_SUPV_TELEMETRY_DATA)));
    DEBUG ((DEBUG_INFO, "\t Telemetry data size: %x\n", TelemtryData->TelemetrySize));
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  } else {
  }

  TelemtryData->ExceptionType = InterruptType;

  // TODO: Check if there are errors placed from syscall dispatcher, use that rIP if so
  FaultRIP                   = SystemContext.SystemContextX64->Rip;
  TelemtryData->ExceptionRIP = FaultRIP;
  if (IsBufferInsideMmram (FaultRIP & ~(EFI_PAGE_MASK), EFI_PAGE_SIZE)) {
    // Attempting to execute code outside of MMRAM, do not run driver look up routines
    DriverAddr                      = PeCoffSearchImageBase (FaultRIP);
    TelemtryData->DriverLoadAddress = DriverAddr;
    DEBUG ((DEBUG_INFO, "%a Loaded image is calculated to be: %p from caller address: %p\n", __FUNCTION__, DriverAddr, FaultRIP));

    Status = FindFileNameFromDiscoveredList (DriverAddr, &DriverGuid);
    if (!EFI_ERROR (Status)) {
      CopyMem (&TelemtryData->DriverId, &DriverGuid, sizeof (EFI_GUID));
    } else {
      DEBUG ((DEBUG_ERROR, "%a Cannot locate the file name from loaded image address: %p... - %r\n", __FUNCTION__, DriverAddr, Status));
      goto Done;
    }
  } else {
    TelemtryData->DriverLoadAddress = FaultRIP;
    ZeroMem (&TelemtryData->DriverId, sizeof (EFI_GUID));
  }

  // Then figure out the CpuIndex
  Status = SmmWhoAmI (&mSmmCpuService, &CpuIndex);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Cannot locate the CpuIndex, bail here... - %r\n", __FUNCTION__, Status));
    goto Done;
  }

  // Demote to CPL3 to report errors
  Status = InvokeDemotedErrorReport (
             CpuIndex,
             SupervisorToUserDataBuffer + 1
             );
  DEBUG ((DEBUG_INFO, "%a Error report returned... - %r\n", __FUNCTION__, Status));

Done:
  // This is the end of it.
  return Status;
}

/**
  This function is for GpException handler from SMM supervisor.

  @param ExceptionType  Exception type.
  @param SystemContext  Pointer to EFI_SYSTEM_CONTEXT.

**/
STATIC
VOID
SmmSupervisorMiscExceptionHandler (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  EFI_STATUS  Status;
  UINTN       CpuIndex;

  Status = SmmWhoAmI (NULL, &CpuIndex);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Don't even know who I am... Can't continue...\n", __FUNCTION__));
    goto HaltOrReboot;
  }

  // Query exception token to avoid resource overstepping, if this processor "double fault", retry logging
  if (!AcquireSpinLockOrFail (mCpuExceptionToken)) {
    if (mCpuExceptionCountBuffer[CpuIndex] > MM_SUPV_RETRY_CNT) {
      goto HaltOrReboot;
    } else if (mCpuExceptionCountBuffer[CpuIndex] == 0) {
      // Otherwise, first time getting here, blocking wait...
      while (!AcquireSpinLockOrFail (mCpuExceptionToken)) {
        CpuPause ();
      }
    } else {
      // Plain retry...
    }
  }

  mCpuExceptionCountBuffer[CpuIndex] = mCpuExceptionCountBuffer[CpuIndex] + 1;

  DumpCpuContext (InterruptType, SystemContext);
  DEBUG ((DEBUG_INFO, "%a MM Supervisor fault here\n", __FUNCTION__));
  DEBUG_CODE (
    DumpModuleInfoByIp ((UINTN)SystemContext.SystemContextX64->Rip);
    );

  if (InterruptType == EXCEPT_IA32_PAGE_FAULT) {
    // Hand it over to page fault handler
    SmiPFHandler (InterruptType, SystemContext);
    goto HaltOrReboot;
  }

  Status = PrepareNReportError (InterruptType, SystemContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a MM Supervisor error reporting failed - %r!!!\n", __FUNCTION__, Status));
  }

  ReleaseSpinLock (mCpuExceptionToken);

  TriggerFailFast (CpuIndex);

HaltOrReboot:
  if (mSmmRebootOnException) {
    DEBUG ((DEBUG_ERROR, "%a - Reboot here in test mode.\n", __FUNCTION__));
    ResetWarm ();
  }

  DEBUG ((DEBUG_ERROR, "%a - The platform elects to hard hang here...\n", __FUNCTION__));
  CpuDeadLoop ();
}

/**
  Initialize spin lock for exception handler.
**/
STATIC
EFI_STATUS
InitExceptionHandlerSpinLock (
  VOID
  )
{
  UINTN       SpinLockSize;
  EFI_STATUS  Status;

  if ((mCpuExceptionToken != NULL) || (mCpuExceptionCountBuffer != NULL)) {
    Status = EFI_ALREADY_STARTED;
    goto Exit;
  }

  SpinLockSize       = GetSpinLockProperties ();
  mCpuExceptionToken = AllocatePool (SpinLockSize);

  if (mCpuExceptionToken == NULL) {
    ASSERT (mCpuExceptionToken != NULL);
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  InitializeSpinLock (mCpuExceptionToken);

  mCpuExceptionCountBuffer = AllocateZeroPool (sizeof (*mCpuExceptionCountBuffer) * mNumberOfCpus);
  if (mCpuExceptionCountBuffer == NULL) {
    ASSERT (mCpuExceptionCountBuffer != NULL);
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:
  return Status;
}

/**
  Initialize exception handler for all unregistered types.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed.
  @retval EFI Errors            Other errors from other routines inside this function.
**/
EFI_STATUS
CoalesceLooseExceptionHandlers (
  VOID
  )
{
  UINTN       Index;
  UINTN       NumberOfHandlers;
  EFI_STATUS  Status;

  Status = InitExceptionHandlerSpinLock ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Initialize exception handler spin lock failed %r!\n", __FUNCTION__, Status));
    goto Exit;
  }

  NumberOfHandlers = (gcSmiIdtr.Limit + 1) / sizeof (IA32_IDT_GATE_DESCRIPTOR);

  for (Index = 0; Index < NumberOfHandlers; Index++) {
    // Here is to fill in all the empty exception handlers with supervisor version
    Status = SmmRegisterExceptionHandler (&mSmmCpuService, Index, (EFI_CPU_INTERRUPT_HANDLER)SmmSupervisorMiscExceptionHandler);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Registering failed with error %r!\n", __FUNCTION__, Status));
      ASSERT (FALSE);
      break;
    } else {
      DEBUG ((DEBUG_INFO, "%a Registering returned %r.\n", __FUNCTION__, Status));
    }
  }

Exit:
  return Status;
}
