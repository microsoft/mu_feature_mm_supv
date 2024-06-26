/** @file -- MmSupervisorErrorReport.c

This Smm driver will register error reporter to Smm supervisor.

When error occurs, SyscallDispatcher will sysret to this registered
jump point for error handling.

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <MmSupvTelemetryData.h>

#include <IndustryStandard/Acpi.h>
#include <Guid/Cper.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/MuTelemetryCperSection.h>
#include <Guid/MmGhesTableRegion.h>
#include <Protocol/MmReadyToLock.h>
#include <Protocol/MmCommunication.h>

#include <Library/BaseLib.h>
#include <Library/SafeIntLib.h>
#include <Library/DebugLib.h>
#include <Library/SysCallLib.h>
#include <Library/MuTelemetryHelperLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/StandaloneMmMemLib.h>
#include <Library/MsWheaEarlyStorageLib.h>

EFI_PHYSICAL_ADDRESS  mGhesReportAddress        = 0;
UINTN                 mGhesReportNumberOfPages  = 0;
EFI_HANDLE            mDispatchHandle           = NULL;

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

  if (((VOID*)(UINTN)mGhesReportAddress == NULL) || (mGhesReportNumberOfPages == 0)) {
    DEBUG ((DEBUG_ERROR, "%a: The GHES is not initialized address: %p and size: 0x%x\n", __func__, mGhesReportAddress, mGhesReportNumberOfPages));
    return EFI_NOT_STARTED;
  }

  BlockHeader = (EFI_ACPI_6_4_GENERIC_ERROR_STATUS_STRUCTURE*)mGhesReportAddress;
  MaxBlockLength = EFI_PAGES_TO_SIZE (mGhesReportNumberOfPages);

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
    DEBUG ((DEBUG_ERROR, "%a: The GHES region is too small for the usage: maximum 0x%x and has: 0x%x\n", __func__, MaxBlockLength, sizeof (EFI_ACPI_6_4_GENERIC_ERROR_STATUS_STRUCTURE) + ExpectedNewDataLength));
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

  DEBUG ((DEBUG_INFO, "%a: Enters... CpuIndex 0x%x\n", __func__, CpuIndex));

  if ((ErrorInfoBuffer != NULL) &&
      (ErrorInfoBuffer->Signature == MM_SUPV_TELEMETRY_SIGNATURE))
  {
    if (NeedSysCall ()) {
      // Try to populate the GHES information here.
      Status = GenericErrorBlockAddErrorData (
                ErrorInfoBuffer->ExceptionType,
                &ErrorInfoBuffer->DriverId,
                ErrorInfoBuffer->ExceptionRIP,
                ErrorInfoBuffer->DriverLoadAddress
                );
      if (EFI_ERROR (Status)) {
        // This is not likely since this is only populating data in the allocated space...
        DEBUG ((DEBUG_ERROR, "%a Cannot populate the GHES information, continue to try HwErrRec... - %r\n", __func__, Status));
      }

      // Need to add the module name/guid and load address.
      Status = MsWheaESAddRecordV0 (
                 (EFI_STATUS_CODE_VALUE)(EFI_SOFTWARE_SMM_DRIVER | ErrorInfoBuffer->ExceptionType),
                 ErrorInfoBuffer->ExceptionRIP,
                 ErrorInfoBuffer->DriverLoadAddress,
                 NULL,
                 &ErrorInfoBuffer->DriverId
                 );
    } else {
      // Why are we even here?
      DEBUG ((DEBUG_ERROR, "%a: This should not happen...\n", __func__));
      ASSERT (FALSE);
    }
  }

  DEBUG ((DEBUG_INFO, "%a: Exits... - %r\n", __func__, Status));
  return Status;
}

/**
  Communication service MMI Handler entry.

  This handler takes requests to receive GHES table resource through Mmi channel.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param[in]      DispatchHandle    The unique handle assigned to this handler by SmiHandlerRegister().
  @param[in]      RegisterContext   Points to an optional handler context which was specified when the
                                    handler was registered.
  @param[in, out] CommBuffer        A pointer to a collection of data in memory that will
                                    be conveyed from a non-SMM environment into an SMM environment.
  @param[in, out] CommBufferSize    The size of the CommBuffer.

  @retval EFI_SUCCESS               The interrupt was handled and quiesced. No other handlers
                                    should still be called.
  @retval EFI_UNSUPPORTED           An unknown test function was requested.
  @retval EFI_ACCESS_DENIED         Part of the communication buffer lies in an invalid region.

**/
EFI_STATUS
EFIAPI
GhesTableRegionMmiHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *RegisterContext,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  EFI_STATUS              Status;
  UINTN                   TempCommBufferSize;
  MM_GHES_TABLE_REGION    *CommParams;
  UINT64                  GhesBufferSize;
  UINT64                  GhesBufferEnd;

  DEBUG ((DEBUG_INFO, "%a()\n", __func__));

  //
  // If input is invalid, stop processing this SMI
  //
  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    return EFI_SUCCESS;
  }

  if ((mGhesReportAddress != 0) || (mGhesReportNumberOfPages != 0)) {
    DEBUG ((DEBUG_ERROR, "[%a] MM has already set up the GHES table!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize != sizeof (MM_GHES_TABLE_REGION)) {
    DEBUG ((DEBUG_ERROR, "[%a] MM Communication buffer size is invalid for this handler!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  if (!MmCommBufferValid ((UINTN)CommBuffer, TempCommBufferSize)) {
    DEBUG ((DEBUG_ERROR, "[%a] - MM Communication buffer in invalid location!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  CommParams = (MM_GHES_TABLE_REGION *)(UINTN)CommBuffer;
  // At least we have a valid buffer, let's see what we can do with it
  if ((CommParams->MmGhesTableRegion.NumberOfPages == 0) ||
      (CommParams->MmGhesTableRegion.PhysicalStart == 0) ||
      (CommParams->MmGhesTableRegion.Type != EfiACPIMemoryNVS) ||
      ((CommParams->MmGhesTableRegion.Attribute & EFI_MEMORY_XP) == 0)) {
    DEBUG ((DEBUG_ERROR, "[%a] - MM Communication buffer has invalid GHES table region!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  // Check if the buffer page value is valid
  Status = SafeUint64Mult (CommParams->MmGhesTableRegion.NumberOfPages, EFI_PAGE_SIZE, &GhesBufferSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - MM Communication buffer has invalid GHES region size!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  // Check if the buffer range is valid
  Status = SafeUint64Add (CommParams->MmGhesTableRegion.PhysicalStart, GhesBufferSize, &GhesBufferEnd);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - MM Communication buffer has invalid GHES region range!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  if (!MmIsBufferOutsideMmValid ((UINTN)CommParams->MmGhesTableRegion.PhysicalStart, TempCommBufferSize)) {
    DEBUG ((DEBUG_ERROR, "[%a] - MM Communication buffer in invalid location!\n", __func__));
    return EFI_ACCESS_DENIED;
  }

  // Enough validation, we can accept the buffer now
  mGhesReportAddress        = CommParams->MmGhesTableRegion.PhysicalStart;
  mGhesReportNumberOfPages  = CommParams->MmGhesTableRegion.NumberOfPages;

  // Finally, we can set the return code
  CommParams->ReturnStatus = EFI_SUCCESS;

  return EFI_SUCCESS;
}

/**
  Notification for SMM ReadyToLock protocol.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification runs successfully.

**/
EFI_STATUS
EFIAPI
ErrorReportMmReadyToLock (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;

  if (mDispatchHandle != NULL) {
    Status             = gMmst->MmiHandlerUnRegister (mDispatchHandle);
    mDispatchHandle = NULL;
  }

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
  EFI_HANDLE  NotifyHandle;

  mDispatchHandle  = NULL; 
  NotifyHandle     = NULL;

  // Register with MM Core with handler jump point
  Status = SysCall (SMM_ERR_RPT_JMP, (UINTN)RegErrorReportJumpPointer, 0, 0);

  // Register the callback function for SMM error reporting
  Status = gMmst->MmiHandlerRegister (
                    GhesTableRegionMmiHandler,
                    &gMmGhesTableRegionGuid,
                    &mDispatchHandle
                    );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a MMI handler registration failed with status : %r\n",
      __func__,
      Status
      ));
    return Status;
  }

  // Turn off the light before leaving the room...
  Status = gMmst->MmRegisterProtocolNotify (&gEfiMmReadyToLockProtocolGuid, ErrorReportMmReadyToLock, &NotifyHandle);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to register ready to lock notification - %r!\n", __func__, Status));
  }

  DEBUG ((DEBUG_INFO, "%a: exit (%r)\n", __func__, Status));
  return Status;
}
