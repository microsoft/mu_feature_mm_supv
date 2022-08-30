/** @file -- MmSupervisorErrorReport.c

This Smm driver will register error reporter to Smm supervisor.

When error occurs, SyscallDispatcher will sysret to this registered
jump point for error handling.

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <MmSupvTelemetryData.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/SysCallLib.h>
#include <Library/MuTelemetryHelperLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/MsWheaEarlyStorageLib.h>

EFI_STATUS
EFIAPI
RegErrorReportJumpPointer (
  IN UINTN  CpuIndex,
  IN VOID   *ErrorInfoBuffer,
  IN UINTN  ErrorInforSize
  );

/**
  Error reporting routine that will report status code.

  @param  ErrorInfoBuffer Pointer to error information buffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmSupvErrorReportWorker (
  IN  UINTN                   CpuIndex,
  IN  MM_SUPV_TELEMETRY_DATA  *ErrorInfoBuffer
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;

  DEBUG ((DEBUG_INFO, "%a: Enters... CpuIndex 0x%x\n", __FUNCTION__, CpuIndex));

  if ((ErrorInfoBuffer != NULL) &&
      (ErrorInfoBuffer->Signature == MM_SUPV_TELEMETRY_SIGNATURE))
  {
    if (NeedSysCall ()) {
      // Need to add the module name/guid and load address
      Status = MsWheaESAddRecordV0 (
                 (EFI_STATUS_CODE_VALUE)(EFI_SOFTWARE_SMM_DRIVER | ErrorInfoBuffer->ExceptionType),
                 ErrorInfoBuffer->ExceptionRIP,
                 ErrorInfoBuffer->DriverLoadAddress,
                 NULL,
                 &ErrorInfoBuffer->DriverId
                 );
    } else {
      // Why are we even here?
      DEBUG ((DEBUG_ERROR, "%a: This should not happen...\n", __FUNCTION__));
      ASSERT (FALSE);
    }
  }

  DEBUG ((DEBUG_INFO, "%a: Exits...\n", __FUNCTION__));
  return Status;
}

/**
  Entry to SmmSupvErrorReport, register SMM error reporter and callback functions

  @param[in] ImageHandle                The image handle.
  @param[in] SystemTable                The system table.

  @retval Status                        From internal routine or boot object, should not fail
**/
EFI_STATUS
EFIAPI
SmmSupvErrorReportEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  // Register with MM Core with handler jump point
  Status = SysCall (SMM_ERR_RPT_JMP, (UINTN)RegErrorReportJumpPointer, 0, 0);

  DEBUG ((DEBUG_INFO, "%a: exit (%r)\n", __FUNCTION__, Status));
  return Status;
}
