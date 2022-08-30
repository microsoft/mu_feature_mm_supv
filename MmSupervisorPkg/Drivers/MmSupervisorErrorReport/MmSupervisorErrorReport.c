/** @file -- MmSupervisorErrorReport.c

This Smm driver will register error reporter to Smm supervisor.

When error occurs, SyscallDispatcher will sysret to this registered
jump point for error handling.

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <MmSupvTelemetryData.h>

#include <Guid/MuTelemetryCperSection.h>
#include <Guid/Cper.h>

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

  Add Error Block to HEST table's Generic Errr

  @param  ExceptionType         Exception type that triggered this exception handler routine.
  @param  DriverGuid            GUID of the driver that tripped this exception.
  @param  ExceptionRIP          Execution instruction pointer that triggered this exception.
  @param  DriverLoadAddress     Driver loading address corresponding to the faulting instruction.

  @return EFI_SUCCESS           If the data population is successful.
  @return EFI_INVALID_PARAMETER If the data buffer is not initialized properly.
  @return EFI_BUFFER_TOO_SMALL  If the data buffer is too small to fit in all error data.

**/
EFI_STATUS
GenericErrorBlockAddErrorData (
  IN EFI_EXCEPTION_TYPE     ExceptionType,
  IN EFI_GUID               *DriverGuid,
  IN EFI_PHYSICAL_ADDRESS   ExceptionRIP,
  IN EFI_PHYSICAL_ADDRESS   DriverLoadAddress
  )
{
  MU_TELEMETRY_CPER_SECTION_DATA                   *GenericErrorDataFollowEntry;
  EFI_ACPI_6_4_ERROR_BLOCK_STATUS                  *BlockStatus;
  EFI_ACPI_6_4_GENERIC_ERROR_STATUS_STRUCTURE      *BlockHeader;
  EFI_ACPI_6_4_GENERIC_ERROR_DATA_ENTRY_STRUCTURE  *Entry;
  UINTN                                            MaxBlockLength;


  BlockHeader = (EFI_ACPI_6_4_GENERIC_ERROR_STATUS_STRUCTURE*)mMmSupervisorAccessBuffer[MM_GHES_BUFFER_T].PhysicalStart;
  MaxBlockLength = EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_GHES_BUFFER_T].NumberOfPages);

  if ((BlockHeader == NULL) || (MaxBlockLength == 0)) {
    DEBUG ((DEBUG_ERROR, "%a - %d: Invalid Param \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  // Setup GHES structures
  ZeroMem (BlockHeader, MaxBlockLength);
  BlockHeader->ErrorSeverity = EFI_ACPI_6_4_ERROR_SEVERITY_FATAL;
  BlockStatus = &BlockHeader->BlockStatus;

  // Calculate length of GHES error region (including new entry)
  UINT32  ExpectedNewDataLength = BlockHeader->DataLength +
                                  sizeof (EFI_ACPI_6_4_GENERIC_ERROR_DATA_ENTRY_STRUCTURE) +
                                  sizeof (MU_TELEMETRY_CPER_SECTION_DATA);

  // Fail if we don't have room
  if (sizeof (EFI_ACPI_6_4_GENERIC_ERROR_STATUS_STRUCTURE) + ExpectedNewDataLength > MaxBlockLength) {
    return EFI_BUFFER_TOO_SMALL;
  }

  // Set BlockStatus Correctable/Uncorrectable fields
  if (BlockStatus->UncorrectableErrorValid == 0) {
    BlockStatus->UncorrectableErrorValid = 1;
  } else {
    BlockStatus->MultipleUncorrectableErrors = 1;
  }

  // Setup Generic Error Data Entry with the values that were passed in
  BlockStatus->ErrorDataEntryCount++;
  Entry = (EFI_ACPI_6_4_GENERIC_ERROR_DATA_ENTRY_STRUCTURE *)(((UINT8 *)BlockHeader) +
                                                              sizeof (EFI_ACPI_6_4_GENERIC_ERROR_STATUS_STRUCTURE) +
                                                              BlockHeader->DataLength);

  // Setup Entry header
  ZeroMem (Entry, sizeof (EFI_ACPI_6_4_GENERIC_ERROR_DATA_ENTRY_STRUCTURE));
  CopyMem (&Entry->SectionType, &gMuTelemetrySectionTypeGuid, sizeof (EFI_GUID));
  Entry->ErrorSeverity   = EFI_GENERIC_ERROR_FATAL;
  Entry->Revision        = EFI_ACPI_6_4_GENERIC_ERROR_DATA_ENTRY_REVISION;
  Entry->ErrorDataLength = sizeof (MU_TELEMETRY_CPER_SECTION_DATA);

  // Copy data right after header
  GenericErrorDataFollowEntry = (MU_TELEMETRY_CPER_SECTION_DATA *)(Entry + 1);
  CopyMem (&GenericErrorDataFollowEntry->ComponentID, DriverGuid, sizeof (EFI_GUID));
  GenericErrorDataFollowEntry->ErrorStatusValue = (EFI_SOFTWARE_SMM_DRIVER | (EFI_STATUS_CODE_VALUE)ExceptionType);
  GenericErrorDataFollowEntry->AdditionalInfo1 = ExceptionRIP;
  GenericErrorDataFollowEntry->AdditionalInfo2 = DriverLoadAddress;

  // Setup the header with the new size
  BlockHeader->DataLength = ExpectedNewDataLength;

  return EFI_SUCCESS;
}

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

    // Try to populate the GHES information here as well.
    Status = GenericErrorBlockAddErrorData (
               ErrorInfoBuffer->ExceptionType,
               &ErrorInfoBuffer->DriverId,
               ErrorInfoBuffer->ExceptionRIP,
               ErrorInfoBuffer->DriverLoadAddress
               );
    if (EFI_ERROR (Status)) {
      // This is not likely since this is only populating data in the allocated space...
      DEBUG ((DEBUG_ERROR, "%a Cannot populate the GHES information, continue to try HwErrRec... - %r\n", __FUNCTION__, Status));
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
