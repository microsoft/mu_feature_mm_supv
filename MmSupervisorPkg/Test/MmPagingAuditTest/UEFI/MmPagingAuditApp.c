/** @file -- MmPagingAuditApp.c
This user-facing application collects information from the SMM page tables and
writes it to files.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>

#include <Protocol/SmmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>

#include <Register/Msr.h>
#include <Register/Cpuid.h>

#include <Guid/DebugImageInfoTable.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MmPagingAudit.h>

#include "MmPagingAuditApp.h"

#define MEM_INFO_DATABASE_REALLOC_CHUNK    0x1000
#define MEM_INFO_DATABASE_MAX_STRING_SIZE  0x400

EFI_FILE  *mFs_Handle;
VOID      *mPiSmmCommonCommBufferAddress = NULL;
UINTN     mPiSmmCommonCommBufferSize;
CHAR8     *mMemoryInfoDatabaseBuffer   = NULL;
UINTN     mMemoryInfoDatabaseSize      = 0;
UINTN     mMemoryInfoDatabaseAllocSize = 0;

/**

  Opens the SFS volume and if successful, returns a FS handle to the opened volume.

  @param    mFs_Handle       Handle to the opened volume.

  @retval   EFI_SUCCESS     The FS volume was opened successfully.
  @retval   Others          The operation failed.

**/
EFI_STATUS
OpenVolumeSFS (
  OUT EFI_FILE  **Fs_Handle
  );

/**
  This helper function will flush the MemoryInfoDatabase to its corresponding
  file and free all resources currently associated with it.

  @param[in]  FileName    Name of the file to be flushed to.

  @retval     EFI_SUCCESS     Database has been flushed to file.

**/
EFI_STATUS
FlushAndClearMemoryInfoDatabase (
  IN CONST CHAR16  *FileName
  );

/**
  This helper function will call to the SMM agent to retrieve the entire contents of the
  SMM Loaded Image protocol list. It will then dump this data to the Memory Info Database.

  Will do nothing if all inputs are not provided.

  @param[in]  SmmCommunication    A pointer to the SmmCommunication protocol.
  @param[in]  CommBufferBase      A pointer to the base of the buffer that should be used
                                  for SMM communication.
  @param[in]  CommBufferSize      The size of the buffer.

**/
STATIC
VOID
SmmLoadedImageTableDump (
  IN MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication,
  IN VOID                                  *CommBufferBase,
  IN UINTN                                 CommBufferSize
  )
{
  EFI_STATUS                            Status;
  EFI_SMM_COMMUNICATE_HEADER            *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER            *AuditCommHeader;
  SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *AuditCommData;
  UINTN                                 MinBufferSize, BufferSize;
  UINTN                                 Index;
  CHAR8                                 TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Check to make sure we have what we need.
  //
  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
                  sizeof (SMM_PAGE_AUDIT_COMM_HEADER) +
                  sizeof (SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER);
  if ((SmmCommunication == NULL) || (CommBufferBase == NULL) || (CommBufferSize < MinBufferSize)) {
    DEBUG ((DEBUG_ERROR, "%a - Bad parameters. This shouldn't happen.\n", __FUNCTION__));
    return;
  }

  //
  // Prep the buffer for sending the required commands to SMM.
  //
  ZeroMem (CommBufferBase, CommBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_MISC_DATA_REQUEST;
  AuditCommHeader->RequestIndex = 0;

  //
  // Repeatedly call to SMM and copy the data, if present.
  //
  do {
    AuditCommData->HasMore = FALSE;
    BufferSize             = CommBufferSize;

    //
    // Signal trip to SMM.
    //
    Status = SmmCommunication->Communicate (
                                 SmmCommunication,
                                 CommBufferBase,
                                 &BufferSize
                                 );
    ASSERT_EFI_ERROR (Status);

    //
    // Get the data out of the comm buffer.
    //
    for (Index = 0; Index < AuditCommData->SmmImageCount; Index++) {
      AsciiSPrint (
        &TempString[0],
        MAX_STRING_SIZE,
        "SmmLoadedImage,0x%016lx,0x%016lx,%a,%g\n",
        AuditCommData->SmmImage[Index].ImageBase,
        AuditCommData->SmmImage[Index].ImageSize,
        &AuditCommData->SmmImage[Index].ImageName[0],
        &AuditCommData->SmmImage[Index].ImageGuid
        );
      AppendToMemoryInfoDatabase (&TempString[0]);
    }

    AuditCommHeader->RequestIndex++;
  } while (AuditCommData->HasMore);

  return;
} // SmmLoadedImageTableDump()

/**
  This helper function will call to the SMM agent to retrieve information regarding where the
  SMI entry for each CPU thread is loaded by the SMM core.

  @param[in]  SmmCommunication    A pointer to the SmmCommunication protocol.
  @param[in]  CommBufferBase      A pointer to the base of the buffer that should be used
                                  for SMM communication.
  @param[in]  CommBufferSize      The size of the buffer.

**/
STATIC
VOID
SmmSmiEntryDump (
  IN MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication,
  IN VOID                                  *CommBufferBase,
  IN UINTN                                 CommBufferSize
  )
{
  EFI_STATUS                            Status;
  EFI_SMM_COMMUNICATE_HEADER            *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER            *AuditCommHeader;
  SMM_PAGE_AUDIT_SMI_ENTRY_COMM_BUFFER  *AuditCommData;
  UINTN                                 MinBufferSize, BufferSize;
  UINTN                                 Index;
  CHAR8                                 TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Check to make sure we have what we need.
  //
  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
                  sizeof (SMM_PAGE_AUDIT_COMM_HEADER) +
                  sizeof (SMM_PAGE_AUDIT_SMI_ENTRY_COMM_BUFFER);
  if ((SmmCommunication == NULL) || (CommBufferBase == NULL) || (CommBufferSize < MinBufferSize)) {
    DEBUG ((DEBUG_ERROR, "%a - Bad parameters. This shouldn't happen.\n", __FUNCTION__));
    return;
  }

  //
  // Prep the buffer for sending the required commands to SMM.
  //
  ZeroMem (CommBufferBase, CommBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_SMI_ENTRY_REQUEST;
  AuditCommHeader->RequestIndex = 0;

  //
  // Repeatedly call to SMM and copy the data, if present.
  //
  do {
    AuditCommData->HasMore = FALSE;
    BufferSize             = CommBufferSize;

    //
    // Signal trip to SMM.
    //
    Status = SmmCommunication->Communicate (
                                 SmmCommunication,
                                 CommBufferBase,
                                 &BufferSize
                                 );
    ASSERT_EFI_ERROR (Status);

    //
    // Get the data out of the comm buffer.
    //
    for (Index = 0; Index < AuditCommData->SmiEntryCount; Index++) {
      AsciiSPrint (
        &TempString[0],
        MAX_STRING_SIZE,
        "SmiEntry,0x%016lx,0x%016lx,0x%04x\n",
        AuditCommData->SmiEntryBase[Index],
        AuditCommData->SmiEntrySize,
        AuditCommHeader->RequestIndex * BUFFER_COUNT_CORES + Index
        );
      AppendToMemoryInfoDatabase (&TempString[0]);

      //
      // Add save state mapping region.
      //
      AsciiSPrint (
        &TempString[0],
        MAX_STRING_SIZE,
        "SmmSaveState,0x%016lx,0x%016lx,0x%04x\n",
        AuditCommData->SmiSaveStateBase[Index],
        AuditCommData->SmiSaveStateSize,
        AuditCommHeader->RequestIndex * BUFFER_COUNT_CORES + Index
        );
      AppendToMemoryInfoDatabase (&TempString[0]);

      //
      // Add per core GDT base and limit.
      //
      AsciiSPrint (
        &TempString[0],
        MAX_STRING_SIZE,
        "GDT,0x%016lx,0x%016lx,0x%04x\n",
        AuditCommData->Gdtr[Index].Base,
        (UINT64)AuditCommData->Gdtr[Index].Limit,
        AuditCommHeader->RequestIndex * BUFFER_COUNT_CORES + Index
        );
      AppendToMemoryInfoDatabase (&TempString[0]);
    }

    AuditCommHeader->RequestIndex++;
  } while (AuditCommData->HasMore);

  return;
} // SmmSmiEntryDump()

/**
  This helper function will call to the SMM agent to retrieve information to retreive all accessible
  memory regions that are outside of TSEG.

  @param[in]  SmmCommunication    A pointer to the SmmCommunication protocol.
  @param[in]  CommBufferBase      A pointer to the base of the buffer that should be used
                                  for SMM communication.
  @param[in]  CommBufferSize      The size of the buffer.

**/
STATIC
VOID
SmmUnblockedRegionsDump (
  IN MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication,
  IN VOID                                  *CommBufferBase,
  IN UINTN                                 CommBufferSize
  )
{
  EFI_STATUS                                 Status;
  EFI_SMM_COMMUNICATE_HEADER                 *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER                 *AuditCommHeader;
  SMM_PAGE_AUDIT_UNBLOCK_REGION_COMM_BUFFER  *AuditCommData;
  UINTN                                      MinBufferSize, BufferSize;
  UINTN                                      Index;
  CHAR8                                      TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Check to make sure we have what we need.
  //
  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
                  sizeof (SMM_PAGE_AUDIT_COMM_HEADER) +
                  sizeof (SMM_PAGE_AUDIT_UNBLOCK_REGION_COMM_BUFFER);
  if ((SmmCommunication == NULL) || (CommBufferBase == NULL) || (CommBufferSize < MinBufferSize)) {
    DEBUG ((DEBUG_ERROR, "%a - Bad parameters. This shouldn't happen.\n", __FUNCTION__));
    return;
  }

  //
  // Prep the buffer for sending the required commands to SMM.
  //
  ZeroMem (CommBufferBase, CommBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_UNBLOCKED_REQUEST;
  AuditCommHeader->RequestIndex = 0;

  //
  // Repeatedly call to SMM and copy the data, if present.
  //
  do {
    AuditCommData->HasMore = FALSE;
    BufferSize             = CommBufferSize;

    //
    // Signal trip to SMM.
    //
    Status = SmmCommunication->Communicate (
                                 SmmCommunication,
                                 CommBufferBase,
                                 &BufferSize
                                 );
    ASSERT_EFI_ERROR (Status);

    //
    // Get the data out of the comm buffer.
    //
    for (Index = 0; Index < AuditCommData->UnblockedRegionCount; Index++) {
      AsciiSPrint (
        &TempString[0],
        MAX_STRING_SIZE,
        "UnblockedRegion,0x%016lx,0x%016lx,%c,%g\n",
        AuditCommData->UnblockedRegions[Index].MemoryDescriptor.PhysicalStart,
        EFI_PAGES_TO_SIZE (AuditCommData->UnblockedRegions[Index].MemoryDescriptor.NumberOfPages),
        (AuditCommData->UnblockedRegions[Index].MemoryDescriptor.Attribute & EFI_MEMORY_SP) ? 'S' : 'U',
        &AuditCommData->UnblockedRegions[Index].IdentifierGuid
        );
      AppendToMemoryInfoDatabase (&TempString[0]);
    }

    AuditCommHeader->RequestIndex++;
  } while (AuditCommData->HasMore);

  return;
} // SmmUnblockedRegionsDump()

/**
  This helper function will call to the SMM agent to retrieve the entire contents of the
  SMM Page Tables. It will then dump those tables to files differentiated by the
  page size (1G, 2M, 4K).

  Will do nothing if all inputs are not provided.

  @param[in]  SmmCommunication    A pointer to the SmmCommunication protocol.
  @param[in]  CommBufferBase      A pointer to the base of the buffer that should be used
                                  for SMM communication.
  @param[in]  CommBufferSize      The size of the buffer.

**/
STATIC
VOID
SmmPageTableEntriesDump (
  IN MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication,
  IN VOID                                  *CommBufferBase,
  IN UINTN                                 CommBufferSize
  )
{
  EFI_STATUS                              Status;
  EFI_SMM_COMMUNICATE_HEADER              *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER              *AuditCommHeader;
  SMM_PAGE_AUDIT_TABLE_ENTRY_COMM_BUFFER  *AuditCommData;
  UINTN                                   MinBufferSize, BufferSize;
  UINTN                                   NewCount, NewSize;
  UINTN                                   Pte1GCount    = 0;
  UINTN                                   Pte2MCount    = 0;
  UINTN                                   Pte4KCount    = 0;
  PAGE_TABLE_1G_ENTRY                     *Pte1GEntries = NULL;
  PAGE_TABLE_ENTRY                        *Pte2MEntries = NULL;
  PAGE_TABLE_4K_ENTRY                     *Pte4KEntries = NULL;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Check to make sure we have what we need.
  //
  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
                  sizeof (SMM_PAGE_AUDIT_COMM_HEADER) +
                  sizeof (SMM_PAGE_AUDIT_TABLE_ENTRY_COMM_BUFFER);
  if ((SmmCommunication == NULL) || (CommBufferBase == NULL) || (CommBufferSize < MinBufferSize)) {
    DEBUG ((DEBUG_ERROR, "%a - Bad parameters. This shouldn't happen.\n", __FUNCTION__));
    return;
  }

  //
  // Prep the buffer for sending the required commands to SMM.
  //
  ZeroMem (CommBufferBase, CommBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_TABLE_REQUEST;
  AuditCommHeader->RequestIndex = 0;

  //
  // Repeatedly call to SMM and copy the data, if present.
  //
  do {
    AuditCommData->HasMore = FALSE;
    BufferSize             = CommBufferSize;

    //
    // Signal trip to SMM
    //
    Status = SmmCommunication->Communicate (
                                 SmmCommunication,
                                 CommBufferBase,
                                 &BufferSize
                                 );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - SmmCommunication errored - %r.\n", __FUNCTION__, Status));
      goto Cleanup;
    }

    //
    // Get the data out of the comm buffer.
    //
    if (AuditCommData->Pte1GCount > 0) {
      NewCount     = Pte1GCount + AuditCommData->Pte1GCount;
      NewSize      = NewCount * sizeof (PAGE_TABLE_1G_ENTRY);
      Pte1GEntries = ReallocatePool (Pte1GCount * sizeof (PAGE_TABLE_1G_ENTRY), NewSize, Pte1GEntries);
      if (Pte1GEntries == NULL) {
        DEBUG ((DEBUG_ERROR, "%a - 1G entries not allocated.\n", __FUNCTION__));
        goto Cleanup;
      }

      CopyMem (&Pte1GEntries[Pte1GCount], &AuditCommData->Pte1G[0], AuditCommData->Pte1GCount * sizeof (PAGE_TABLE_1G_ENTRY));
      Pte1GCount = NewCount;
    }

    if (AuditCommData->Pte2MCount > 0) {
      NewCount     = Pte2MCount + AuditCommData->Pte2MCount;
      NewSize      = NewCount * sizeof (PAGE_TABLE_ENTRY);
      Pte2MEntries = ReallocatePool (Pte2MCount * sizeof (PAGE_TABLE_ENTRY), NewSize, Pte2MEntries);
      if (Pte2MEntries == NULL) {
        DEBUG ((DEBUG_ERROR, "%a - 2M entries not allocated.\n", __FUNCTION__));
        goto Cleanup;
      }

      CopyMem (&Pte2MEntries[Pte2MCount], &AuditCommData->Pte2M[0], AuditCommData->Pte2MCount * sizeof (PAGE_TABLE_ENTRY));
      Pte2MCount = NewCount;
    }

    if (AuditCommData->Pte4KCount > 0) {
      NewCount     = Pte4KCount + AuditCommData->Pte4KCount;
      NewSize      = NewCount * sizeof (PAGE_TABLE_4K_ENTRY);
      Pte4KEntries = ReallocatePool (Pte4KCount * sizeof (PAGE_TABLE_4K_ENTRY), NewSize, Pte4KEntries);
      if (Pte4KEntries == NULL) {
        DEBUG ((DEBUG_ERROR, "%a - 4K entries not allocated.\n", __FUNCTION__));
        goto Cleanup;
      }

      CopyMem (&Pte4KEntries[Pte4KCount], &AuditCommData->Pte4K[0], AuditCommData->Pte4KCount * sizeof (PAGE_TABLE_4K_ENTRY));
      Pte4KCount = NewCount;
    }

    AuditCommHeader->RequestIndex++;
  } while (AuditCommData->HasMore);

  //
  // Write data from the comm buffer to file.
  //
  WriteBufferToFile (L"1G", Pte1GEntries, Pte1GCount * sizeof (PAGE_TABLE_1G_ENTRY));
  WriteBufferToFile (L"2M", Pte2MEntries, Pte2MCount * sizeof (PAGE_TABLE_ENTRY));
  WriteBufferToFile (L"4K", Pte4KEntries, Pte4KCount * sizeof (PAGE_TABLE_4K_ENTRY));

Cleanup:
  // Always put away your toys.
  if (Pte1GEntries != NULL) {
    FreePool (Pte1GEntries);
  }

  if (Pte2MEntries != NULL) {
    FreePool (Pte2MEntries);
  }

  if (Pte4KEntries != NULL) {
    FreePool (Pte4KEntries);
  }

  return;
} // SmmPageTableEntriesDump()

/**
  This helper function will call to the SMM agent to retrieve the entire contents of the
  SMM Page Tables. It will then dump those tables to files differentiated by the
  page size (1G, 2M, 4K).

  Will do nothing if all inputs are not provided.

  @param[in]  SmmCommunication    A pointer to the SmmCommunication protocol.
  @param[in]  CommBufferBase      A pointer to the base of the buffer that should be used
                                  for SMM communication.
  @param[in]  CommBufferSize      The size of the buffer.

**/
STATIC
VOID
SmmGuardPageEntriesDump (
  IN MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication,
  IN VOID                                  *CommBufferBase,
  IN UINTN                                 CommBufferSize
  )
{
  EFI_STATUS                              Status;
  EFI_SMM_COMMUNICATE_HEADER              *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER              *AuditCommHeader;
  SMM_PAGE_AUDIT_GUARD_ENTRY_COMM_BUFFER  *AuditCommData;
  UINTN                                   MinBufferSize, BufferSize;
  UINTN                                   NewCount, NewSize;
  UINTN                                   GuardCount    = 0;
  UINT64                                  *GuardEntries = NULL;
  CHAR8                                   TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Check to make sure we have what we need.
  //
  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
                  sizeof (SMM_PAGE_AUDIT_COMM_HEADER) +
                  sizeof (SMM_PAGE_AUDIT_GUARD_ENTRY_COMM_BUFFER);
  if ((SmmCommunication == NULL) || (CommBufferBase == NULL) || (CommBufferSize < MinBufferSize)) {
    DEBUG ((DEBUG_ERROR, "%a - Bad parameters. This shouldn't happen.\n", __FUNCTION__));
    return;
  }

  //
  // Prep the buffer for sending the required commands to SMM.
  //
  ZeroMem (CommBufferBase, CommBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_GUARD_PAGE_REQUEST;
  AuditCommHeader->RequestIndex = 0;

  //
  // Repeatedly call to SMM and copy the data, if present.
  //
  do {
    AuditCommData->HasMore = FALSE;
    BufferSize             = CommBufferSize;

    //
    // Signal trip to SMM
    //
    Status = SmmCommunication->Communicate (
                                 SmmCommunication,
                                 CommBufferBase,
                                 &BufferSize
                                 );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - SmmCommunication errored - %r.\n", __FUNCTION__, Status));
      goto Cleanup;
    }

    //
    // Get the data out of the comm buffer.
    //
    if (AuditCommData->GuardPageCount > 0) {
      NewCount     = GuardCount + AuditCommData->GuardPageCount;
      NewSize      = NewCount * sizeof (UINT64);
      GuardEntries = ReallocatePool (GuardCount * sizeof (UINT64), NewSize, GuardEntries);
      if (GuardEntries == NULL) {
        DEBUG ((DEBUG_ERROR, "%a - Guard pages not allocated.\n", __FUNCTION__));
        goto Cleanup;
      }

      CopyMem (&GuardEntries[GuardCount], &AuditCommData->GuardPage[0], AuditCommData->GuardPageCount * sizeof (UINT64));
      GuardCount = NewCount;
    }

    AuditCommHeader->RequestIndex++;
  } while (AuditCommData->HasMore);

  // Only populate guard pages when function call is successful
  for (UINT64 i = 0; i < GuardCount; i++) {
    AsciiSPrint (
      TempString,
      MAX_STRING_SIZE,
      "GuardPage,0x%016lx\n",
      GuardEntries[i]
      );
    DEBUG ((DEBUG_ERROR, "%a  %s\n", __FUNCTION__, TempString));
    AppendToMemoryInfoDatabase (TempString);
  }

  FlushAndClearMemoryInfoDatabase (L"GuardPage");

Cleanup:
  // Always put away your toys.
  if (GuardEntries != NULL) {
    FreePool (GuardEntries);
  }

  return;
} // SmmGuardPageEntriesDump()

/**
  This helper function will call to the SMM agent to retrieve all the Page Table Directory entries.
  It will then dump those tables to a file.

  Will do nothing if all inputs are not provided.

  @param[in]  SmmCommunication    A pointer to the SmmCommunication protocol.
  @param[in]  CommBufferBase      A pointer to the base of the buffer that should be used
                                  for SMM communication.
  @param[in]  CommBufferSize      The size of the buffer.

**/
STATIC
VOID
SmmPdeEntriesDump (
  IN MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication,
  IN VOID                                  *CommBufferBase,
  IN UINTN                                 CommBufferSize
  )
{
  EFI_STATUS                            Status;
  EFI_SMM_COMMUNICATE_HEADER            *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER            *AuditCommHeader;
  SMM_PAGE_AUDIT_PDE_ENTRY_COMM_BUFFER  *AuditCommData;
  UINTN                                 MinBufferSize, BufferSize;
  UINTN                                 Index;
  CHAR8                                 TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Check to make sure we have what we need.
  //
  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) +
                  sizeof (SMM_PAGE_AUDIT_COMM_HEADER) +
                  sizeof (SMM_PAGE_AUDIT_PDE_ENTRY_COMM_BUFFER);
  if ((SmmCommunication == NULL) || (CommBufferBase == NULL) || (CommBufferSize < MinBufferSize)) {
    DEBUG ((DEBUG_ERROR, "%a - Bad parameters. This shouldn't happen.\n", __FUNCTION__));
    return;
  }

  //
  // Prep the buffer for sending the required commands to SMM.
  //
  ZeroMem (CommBufferBase, CommBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_PDE_REQUEST;
  AuditCommHeader->RequestIndex = 0;

  //
  // Repeatedly call to SMM and copy the data, if present.
  //
  do {
    AuditCommData->HasMore = FALSE;
    BufferSize             = CommBufferSize;

    //
    // Signal trip to SMM.
    //
    Status = SmmCommunication->Communicate (
                                 SmmCommunication,
                                 CommBufferBase,
                                 &BufferSize
                                 );
    ASSERT_EFI_ERROR (Status);

    //
    // Get the data out of the comm buffer.
    //
    for (Index = 0; Index < AuditCommData->PdeCount; Index++) {
      AsciiSPrint (
        &TempString[0],
        MAX_STRING_SIZE,
        "PDE,0x%lx,0x%lx\n",
        AuditCommData->Pde[Index],
        512ull
        );                   // 512 is the size of a Page Directory
      AppendToMemoryInfoDatabase (&TempString[0]);
    }

    AuditCommHeader->RequestIndex++;
  } while (AuditCommData->HasMore);

  return;
} // SmmPdeEntriesDump()

/**
  This helper function actually sends the requested communication
  to the SMM driver.

  @retval     EFI_SUCCESS                  Communication was successful.
  @retval     EFI_ABORTED                  Some error occurred.
  @retval     EFI_BUFFER_TOO_SMALL         Buffer size smaller than minimal requirement.

**/
STATIC
EFI_STATUS
SmmMemoryProtectionsDxeToSmmCommunicate (
  VOID
  )
{
  EFI_STATUS                            Status            = EFI_SUCCESS;
  MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication = NULL;
  VOID                                  *CommBufferBase;
  EFI_SMM_COMMUNICATE_HEADER            *CommHeader;
  SMM_PAGE_AUDIT_COMM_HEADER            *AuditCommHeader;
  SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *AuditCommData;
  UINTN                                 MinBufferSize, BufferSize;
  CHAR8                                 TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Make sure that we have access to a buffer that seems to be sufficient to do everything we need to do.
  //
  if (mPiSmmCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Communication mBuffer not found!\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) + sizeof (SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER);
  if (MinBufferSize > mPiSmmCommonCommBufferSize) {
    DEBUG ((DEBUG_ERROR, "%a - Communication mBuffer is too small\n", __FUNCTION__));
    return EFI_BUFFER_TOO_SMALL;
  }

  CommBufferBase = mPiSmmCommonCommBufferAddress;

  //
  // Locate the protocol as needed.
  //
  if (SmmCommunication == NULL) {
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&SmmCommunication);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Call all related handlers.
  //
  SmmPageTableEntriesDump (SmmCommunication, mPiSmmCommonCommBufferAddress, mPiSmmCommonCommBufferSize);
  SmmPdeEntriesDump (SmmCommunication, mPiSmmCommonCommBufferAddress, mPiSmmCommonCommBufferSize);
  SmmLoadedImageTableDump (SmmCommunication, mPiSmmCommonCommBufferAddress, mPiSmmCommonCommBufferSize);
  SmmSmiEntryDump (SmmCommunication, mPiSmmCommonCommBufferAddress, mPiSmmCommonCommBufferSize);
  SmmUnblockedRegionsDump (SmmCommunication, mPiSmmCommonCommBufferAddress, mPiSmmCommonCommBufferSize);

  //
  // Prep the buffer for getting the last of the misc data.
  //
  ZeroMem (CommBufferBase, MinBufferSize);
  CommHeader      = CommBufferBase;
  AuditCommHeader = (VOID *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  AuditCommData   = (VOID *)((UINTN)AuditCommHeader + sizeof (SMM_PAGE_AUDIT_COMM_HEADER));
  CopyGuid (&CommHeader->HeaderGuid, &gMmPagingAuditMmiHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_MISC_DATA_REQUEST;
  AuditCommHeader->RequestIndex = 0;
  AuditCommData->HasMore        = FALSE;
  BufferSize                    = MinBufferSize;

  //
  // Signal trip to SMM.
  //
  Status = SmmCommunication->Communicate (
                               SmmCommunication,
                               CommBufferBase,
                               &BufferSize
                               );

  //
  // Add remaining misc data to the database.
  //
  AsciiSPrint (
    &TempString[0],
    MAX_STRING_SIZE,
    "Bitwidth,0x%02x\n",
    AuditCommData->MaxAddessBitwidth
    );
  AppendToMemoryInfoDatabase (&TempString[0]);

  AsciiSPrint (
    &TempString[0],
    MAX_STRING_SIZE,
    "SupervisorStack,0x%016lx,0x%016lx\n",
    AuditCommData->SupvStackBaseAddr,
    (UINT64)AuditCommData->SupvStackSize
    );
  AppendToMemoryInfoDatabase (&TempString[0]);

  AsciiSPrint (
    &TempString[0],
    MAX_STRING_SIZE,
    "UserStack,0x%016lx,0x%016lx\n",
    AuditCommData->UserStackBaseAddr,
    (UINT64)AuditCommData->UserStackSize
    );
  AppendToMemoryInfoDatabase (&TempString[0]);

  AsciiSPrint (
    &TempString[0],
    MAX_STRING_SIZE,
    "SupervisorCommBuffer,0x%016lx,0x%016lx\n",
    AuditCommData->SupvCommBufferBase,
    (UINT64)AuditCommData->SupvCommBufferSize
    );
  AppendToMemoryInfoDatabase (&TempString[0]);

  AsciiSPrint (
    &TempString[0],
    MAX_STRING_SIZE,
    "UserCommBuffer,0x%016lx,0x%016lx\n",
    AuditCommData->UserCommBufferBase,
    (UINT64)AuditCommData->UserCommBufferSize
    );
  AppendToMemoryInfoDatabase (&TempString[0]);

  AsciiSPrint (
    &TempString[0],
    MAX_STRING_SIZE,
    "IDT,0x%016lx,0x%016lx\n",
    AuditCommData->Idtr.Base,
    (UINT64)AuditCommData->Idtr.Limit
    );
  AppendToMemoryInfoDatabase (&TempString[0]);

  FlushAndClearMemoryInfoDatabase (L"MemoryInfoDatabase");

  //
  // Collect all guard pages here as it will flush under GuardPages.dat file.
  //
  SmmGuardPageEntriesDump (SmmCommunication, mPiSmmCommonCommBufferAddress, mPiSmmCommonCommBufferSize);

  //
  // Clean up the SMM cache.
  //
  AuditCommHeader->RequestType  = SMM_PAGE_AUDIT_CLEAR_DATA_REQUEST;
  AuditCommHeader->RequestIndex = 0;
  BufferSize                    = MinBufferSize;
  Status                        = SmmCommunication->Communicate (
                                                      SmmCommunication,
                                                      CommBufferBase,
                                                      &BufferSize
                                                      );

  return EFI_SUCCESS;
} // SmmMemoryProtectionsDxeToSmmCommunicate()

/**
  This helper function will flush the MemoryInfoDatabase to its corresponding
  file and free all resources currently associated with it.

  @param[in]  FileName    Name of the file to be flushed to.

  @retval     EFI_SUCCESS     Database has been flushed to file.

**/
EFI_STATUS
FlushAndClearMemoryInfoDatabase (
  IN CONST CHAR16  *FileName
  )
{
  // If we have database contents, flush them to the file.
  if (mMemoryInfoDatabaseSize > 0) {
    WriteBufferToFile (FileName, mMemoryInfoDatabaseBuffer, mMemoryInfoDatabaseSize);
  }

  // If we have a database, free it, and reset all counters.
  if (mMemoryInfoDatabaseBuffer != NULL) {
    FreePool (mMemoryInfoDatabaseBuffer);
    mMemoryInfoDatabaseBuffer = NULL;
  }

  mMemoryInfoDatabaseAllocSize = 0;
  mMemoryInfoDatabaseSize      = 0;

  return EFI_SUCCESS;
} // FlushAndClearMemoryInfoDatabase()

/**
 * @brief      Locates and stores address of comm buffer.
 *
 * @return     EFI_ABORTED if buffer has already been located, error
 *             from getting system table, or success.
 */
EFI_STATUS
EFIAPI
LocateSmmCommonCommBuffer (
  VOID
  )
{
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
  EFI_MEMORY_DESCRIPTOR                    *SmmCommMemRegion;
  UINTN                                    Index, BufferSize;
  EFI_STATUS                               Status = EFI_ABORTED;
  UINTN                                    DesiredBufferSize;

  if (mPiSmmCommonCommBufferAddress == NULL) {
    Status = EfiGetSystemConfigurationTable (&gMmSupervisorCommunicationRegionTableGuid, (VOID **)&PiSmmCommunicationRegionTable);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Failed to get system configuration table %r\n", __FUNCTION__, Status));
      return Status;
    }

    Status = EFI_BAD_BUFFER_SIZE;

    DesiredBufferSize = sizeof (SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER);
    DEBUG ((DEBUG_ERROR, "%a desired comm buffer size %ld\n", __FUNCTION__, DesiredBufferSize));
    BufferSize       = 0;
    SmmCommMemRegion = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
      if (SmmCommMemRegion->Type == EfiConventionalMemory) {
        BufferSize = EFI_PAGES_TO_SIZE ((UINTN)SmmCommMemRegion->NumberOfPages);
        if (BufferSize >= (DesiredBufferSize + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data))) {
          Status = EFI_SUCCESS;
          break;
        }
      }

      SmmCommMemRegion = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)SmmCommMemRegion + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    mPiSmmCommonCommBufferAddress = (VOID *)SmmCommMemRegion->PhysicalStart;
    mPiSmmCommonCommBufferSize    = BufferSize;
  }

  return Status;
} // LocateSmmCommonCommBuffer()

/**
  This helper function writes a string entry to the memory info database buffer.
  If string would exceed current buffer allocation, it will realloc.

  NOTE: The buffer tracks its size. It does not work with NULL terminators.

  @param[in]  DatabaseString    A pointer to a CHAR8 string that should be
                                added to the database.

  @retval     EFI_SUCCESS           String was successfully added.
  @retval     EFI_OUT_OF_RESOURCES  Buffer could not be grown to accommodate string.
                                    String has not been added.

**/
EFI_STATUS
EFIAPI
AppendToMemoryInfoDatabase (
  IN CONST CHAR8  *DatabaseString
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;
  UINTN       NewStringSize, NewDatabaseSize;
  CHAR8       *NewDatabaseBuffer;

  // If the incoming string is NULL or empty, get out of here.
  if ((DatabaseString == NULL) || (DatabaseString[0] == '\0')) {
    return EFI_SUCCESS;
  }

  // Determine the length of the incoming string.
  // NOTE: This size includes the NULL terminator.
  NewStringSize = AsciiStrnSizeS (DatabaseString, MEM_INFO_DATABASE_MAX_STRING_SIZE);
  NewStringSize = NewStringSize - sizeof (CHAR8);    // Remove NULL.

  // If we need more space, realloc now.
  // Subtract 1 because we only need a single NULL terminator.
  NewDatabaseSize = NewStringSize + mMemoryInfoDatabaseSize;
  if (NewDatabaseSize > mMemoryInfoDatabaseAllocSize) {
    NewDatabaseBuffer = ReallocatePool (
                          mMemoryInfoDatabaseAllocSize,
                          mMemoryInfoDatabaseAllocSize + MEM_INFO_DATABASE_REALLOC_CHUNK,
                          mMemoryInfoDatabaseBuffer
                          );
    // If we failed, don't change anything.
    if (NewDatabaseBuffer == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
    }
    // Otherwise, updated the pointers and sizes.
    else {
      mMemoryInfoDatabaseBuffer     = NewDatabaseBuffer;
      mMemoryInfoDatabaseAllocSize += MEM_INFO_DATABASE_REALLOC_CHUNK;
    }
  }

  // If we're still good, copy the new string to the end of
  // the buffer and update the size.
  if (!EFI_ERROR (Status)) {
    // Subtract 1 to remove the previous NULL terminator.
    CopyMem (&mMemoryInfoDatabaseBuffer[mMemoryInfoDatabaseSize], DatabaseString, NewStringSize);
    mMemoryInfoDatabaseSize = NewDatabaseSize;
  }

  return Status;
} // AppendToMemoryInfoDatabase()

/**
  Creates a new file and writes the contents of the caller's data buffer to the file.

  @param    Fs_Handle           Handle to an opened filesystem volume/partition.
  @param    FileName            Name of the file to create.
  @param    DataBufferSize      Size of data to buffer to be written in bytes.
  @param    Data                Data to be written.

  @retval   EFI_STATUS          File was created and data successfully written.
  @retval   Others              The operation failed.

**/
EFI_STATUS
CreateAndWriteFileSFS (
  IN EFI_FILE  *Fs_Handle,
  IN CHAR16    *FileName,
  IN UINTN     DataBufferSize,
  IN VOID      *Data
  )
{
  EFI_STATUS  Status      = EFI_SUCCESS;
  EFI_FILE    *FileHandle = NULL;

  DEBUG ((DEBUG_ERROR, "%a: Creating file: %s \n", __FUNCTION__, FileName));

  // Create the file with RW permissions.
  //
  Status = Fs_Handle->Open (
                        Fs_Handle,
                        &FileHandle,
                        FileName,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        0
                        );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to create file %s: %r !\n", __FUNCTION__, FileName, Status));
    goto CleanUp;
  }

  // Write the contents of the caller's data buffer to the file.
  //
  Status = FileHandle->Write (
                         FileHandle,
                         &DataBufferSize,
                         Data
                         );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to write to file %s: %r !\n", __FUNCTION__, FileName, Status));
    goto CleanUp;
  }

  FileHandle->Flush (Fs_Handle);

CleanUp:

  // Close the file if it was successfully opened.
  //
  if (FileHandle != NULL) {
    FileHandle->Close (FileHandle);
  }

  return Status;
}

/**
 * @brief      Writes a buffer to file.
 *
 * @param[in]  FileName     The name of the file being written to.
 * @param[in]  Buffer       The buffer to write to file.
 * @param[in]  BufferSize   Size of the buffer.
 */
VOID
EFIAPI
WriteBufferToFile (
  IN CONST CHAR16  *FileName,
  IN       VOID    *Buffer,
  IN       UINTN   BufferSize
  )
{
  EFI_STATUS  Status;
  CHAR16      FileNameAndExt[MAX_STRING_SIZE];

  if (mFs_Handle == NULL) {
    Status = OpenVolumeSFS (&mFs_Handle);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a error opening sfs volume - %r\n", __FUNCTION__, Status));
      return;
    }
  }

  // Calculate final file name.
  ZeroMem (FileNameAndExt, sizeof (CHAR16) * MAX_STRING_SIZE);
  UnicodeSPrint (FileNameAndExt, MAX_STRING_SIZE, L"%s.dat", FileName);

  Status = CreateAndWriteFileSFS (mFs_Handle, FileNameAndExt, BufferSize, Buffer);
  DEBUG ((DEBUG_ERROR, "%a Writing file %s - %r\n", __FUNCTION__, FileNameAndExt, Status));
}

/**
 * @brief      Writes the MemoryAttributesTable to a file.
 */
VOID
EFIAPI
MemoryAttributesTableDump (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_MEMORY_ATTRIBUTES_TABLE  *MatMap;
  EFI_MEMORY_DESCRIPTOR        *Map;
  UINT64                       EntrySize;
  UINT64                       EntryCount;
  CHAR8                        *WriteString;
  CHAR8                        *Buffer;
  UINT64                       Index;
  UINTN                        BufferSize;
  UINTN                        FormattedStringSize;
  // NOTE: Important to use fixed-size formatters for pointer movement.
  CHAR8  MatFormatString[] = "MAT,0x%016lx,0x%016lx,0x%016lx,0x%016lx,0x%016lx\n";
  CHAR8  TempString[MAX_STRING_SIZE];

  //
  // First, we need to locate the MAT table.
  //
  Status = EfiGetSystemConfigurationTable (&gEfiMemoryAttributesTableGuid, (VOID **)&MatMap);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to retrieve MAT %r\n", __FUNCTION__, Status));
    return;
  }

  // MAT should now be at the pointer.
  EntrySize  = MatMap->DescriptorSize;
  EntryCount = MatMap->NumberOfEntries;
  Map        = (VOID *)((UINT8 *)MatMap + sizeof (*MatMap));

  //
  // Next, we need to allocate a buffer to hold all of the entries.
  // We'll be storing the data as fixed-length strings.
  //
  // Do a dummy format to determine the size of a string.
  // We're safe to use 0's, since the formatters are fixed-size.
  FormattedStringSize = AsciiSPrint (TempString, MAX_STRING_SIZE, MatFormatString, 0, 0, 0, 0, 0);
  // Make sure to add space for the NULL terminator at the end.
  BufferSize = (EntryCount * FormattedStringSize) + sizeof (CHAR8);
  Buffer     = AllocatePool (BufferSize);
  if (!Buffer) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate buffer for data dump!\n", __FUNCTION__));
    return;
  }

  //
  // Add all entries to the buffer.
  //
  WriteString = Buffer;
  for (Index = 0; Index < EntryCount; Index++) {
    AsciiSPrint (
      WriteString,
      FormattedStringSize+1,
      MatFormatString,
      Map->Type,
      Map->PhysicalStart,
      Map->VirtualStart,
      Map->NumberOfPages,
      Map->Attribute
      );

    WriteString += FormattedStringSize;
    Map          = NEXT_MEMORY_DESCRIPTOR (Map, EntrySize);
  }

  //
  // Finally, write the strings to the dump file.
  //
  // NOTE: Don't need to save the NULL terminator.
  WriteBufferToFile (L"MAT", Buffer, BufferSize-1);

  FreePool (Buffer);
}

/**
 * @brief      Writes the UEFI memory map to file.
 */
VOID
EFIAPI
MemoryMapDumpHandler (
  VOID
  )
{
  EFI_STATUS             Status;
  UINTN                  EfiMemoryMapSize;
  UINTN                  EfiMapKey;
  UINTN                  EfiDescriptorSize;
  UINT32                 EfiDescriptorVersion;
  EFI_MEMORY_DESCRIPTOR  *EfiMemoryMap;
  EFI_MEMORY_DESCRIPTOR  *EfiMemoryMapEnd;
  EFI_MEMORY_DESCRIPTOR  *EfiMemNext;
  CHAR8                  TempString[MAX_STRING_SIZE];

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Get the EFI memory map.
  //
  EfiMemoryMapSize = 0;
  EfiMemoryMap     = NULL;
  Status           = gBS->GetMemoryMap (
                            &EfiMemoryMapSize,
                            EfiMemoryMap,
                            &EfiMapKey,
                            &EfiDescriptorSize,
                            &EfiDescriptorVersion
                            );
  //
  // Loop to allocate space for the memory map and then copy it in.
  //
  do {
    EfiMemoryMap = (EFI_MEMORY_DESCRIPTOR *)AllocateZeroPool (EfiMemoryMapSize);
    ASSERT (EfiMemoryMap != NULL);
    Status = gBS->GetMemoryMap (
                    &EfiMemoryMapSize,
                    EfiMemoryMap,
                    &EfiMapKey,
                    &EfiDescriptorSize,
                    &EfiDescriptorVersion
                    );
    if (EFI_ERROR (Status)) {
      FreePool (EfiMemoryMap);
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  EfiMemoryMapEnd = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)EfiMemoryMap + EfiMemoryMapSize);
  EfiMemNext      = EfiMemoryMap;

  while (EfiMemNext < EfiMemoryMapEnd) {
    AsciiSPrint (
      TempString,
      MAX_STRING_SIZE,
      "MemoryMap,0x%016lx,0x%016lx,0x%016lx,0x%016lx,0x%016lx\n",
      EfiMemNext->Type,
      EfiMemNext->PhysicalStart,
      EfiMemNext->VirtualStart,
      EfiMemNext->NumberOfPages,
      EfiMemNext->Attribute
      );
    AppendToMemoryInfoDatabase (TempString);
    EfiMemNext = NEXT_MEMORY_DESCRIPTOR (EfiMemNext, EfiDescriptorSize);
  }

  if (EfiMemoryMap) {
    FreePool (EfiMemoryMap);
  }
}

/**
 * @brief      Writes the name, base, and limit of each image in the image table to a file.
 */
VOID
EFIAPI
LoadedImageTableDump (
  VOID
  )
{
  EFI_STATUS                         Status;
  EFI_DEBUG_IMAGE_INFO_TABLE_HEADER  *TableHeader;
  EFI_DEBUG_IMAGE_INFO               *Table;
  EFI_LOADED_IMAGE_PROTOCOL          *LoadedImageProtocolInstance;
  UINT64                             ImageBase;
  UINT64                             ImageSize;
  UINT64                             Index;
  UINT32                             TableSize;
  EFI_DEBUG_IMAGE_INFO_NORMAL        *NormalImage;
  CHAR8                              *PdbFileName;
  CHAR8                              TempString[MAX_STRING_SIZE];
  EFI_GUID                           FileGuid;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // locate DebugImageInfoTable
  //
  Status = EfiGetSystemConfigurationTable (&gEfiDebugImageInfoTableGuid, (VOID **)&TableHeader);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to retrieve loaded image table %r", Status));
    return;
  }

  Table     = TableHeader->EfiDebugImageInfoTable;
  TableSize = TableHeader->TableSize;

  DEBUG ((DEBUG_VERBOSE, "%a\n\nLength %lx Start x0x%016lx\n\n", __FUNCTION__, TableHeader->TableSize, Table));

  for (Index = 0; Index < TableSize; Index++) {
    if (Table[Index].NormalImage == NULL) {
      continue;
    }

    NormalImage                 = Table[Index].NormalImage;
    LoadedImageProtocolInstance = NormalImage->LoadedImageProtocolInstance;
    ImageSize                   = LoadedImageProtocolInstance->ImageSize;
    ImageBase                   = (UINT64)LoadedImageProtocolInstance->ImageBase;

    if (ImageSize == 0) {
      // No need to register empty slots in the table as images.
      continue;
    }

    PdbFileName = PeCoffLoaderGetPdbPointer (LoadedImageProtocolInstance->ImageBase);

    // Prepare for the file guid
    EFI_DEVICE_PATH_PROTOCOL  *DevicePath = LoadedImageProtocolInstance->FilePath;
    while (!IsDevicePathEnd (DevicePath)) {
      if ((MEDIA_DEVICE_PATH == DevicePathType (DevicePath)) &&
          (MEDIA_PIWG_FW_FILE_DP == DevicePathSubType (DevicePath)))
      {
        CopyGuid (&FileGuid, EfiGetNameGuidFromFwVolDevicePathNode ((MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)DevicePath));
      }

      DevicePath = NextDevicePathNode (DevicePath);
    }

    AsciiSPrint (
      TempString,
      MAX_STRING_SIZE,
      "LoadedImage,0x%016lx,0x%016lx,%a,%g\n",
      ImageBase,
      ImageSize,
      PdbFileName,
      &FileGuid
      );
    AppendToMemoryInfoDatabase (TempString);
  }
}

/**

  Opens the SFS volume and if successful, returns a FS handle to the opened volume.

  @param    mFs_Handle       Handle to the opened volume.

  @retval   EFI_SUCCESS     The FS volume was opened successfully.
  @retval   Others          The operation failed.

**/
EFI_STATUS
OpenVolumeSFS (
  OUT EFI_FILE  **Fs_Handle
  )
{
  EFI_DEVICE_PATH_PROTOCOL         *DevicePath;
  BOOLEAN                          Found;
  EFI_HANDLE                       Handle;
  EFI_HANDLE                       *HandleBuffer;
  UINTN                            Index;
  UINTN                            NumHandles;
  EFI_DEVICE_PATH_PROTOCOL         *OrigDevicePath;
  EFI_STRING                       PathNameStr;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SfProtocol;
  EFI_STATUS                       Status;

  Status       = EFI_SUCCESS;
  SfProtocol   = NULL;
  NumHandles   = 0;
  HandleBuffer = NULL;

  //
  // Locate all handles that are using the SFS protocol.
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumHandles,
                  &HandleBuffer
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to locate all handles using the Simple FS protocol (%r)\n", __FUNCTION__, Status));
    goto CleanUp;
  }

  //
  // Search the handles to find one that is on a GPT partition on a hard drive.
  //
  Found = FALSE;
  for (Index = 0; (Index < NumHandles) && (Found == FALSE); Index += 1) {
    DevicePath = DevicePathFromHandle (HandleBuffer[Index]);
    if (DevicePath == NULL) {
      continue;
    }

    //
    // Save the original device path because we change it as we're checking it
    // below. We'll need the unmodified version if we determine that it's good.
    //
    OrigDevicePath = DevicePath;

    //
    // Convert the device path to a string to print it.
    //
    PathNameStr = ConvertDevicePathToText (DevicePath, TRUE, TRUE);
    DEBUG ((DEBUG_ERROR, "%a: device path %d -> %s\n", __FUNCTION__, Index, PathNameStr));

    //
    // Check if this is a block IO device path. If it is not, keep searching.
    // This changes our locate device path variable, so we'll have to restore
    // it afterwards.
    //
    Status = gBS->LocateDevicePath (
                    &gEfiBlockIoProtocolGuid,
                    &DevicePath,
                    &Handle
                    );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: not a block IO device path\n", __FUNCTION__));
      continue;
    }

    //
    // Restore the device path and check if this is a GPT partition. We only
    // want to write our log on GPT partitions.
    //
    DevicePath = OrigDevicePath;
    while (IsDevicePathEnd (DevicePath) == FALSE) {
      //
      // If the device path is not a hard drive, we don't want it.
      //
      if ((DevicePathType (DevicePath) == MEDIA_DEVICE_PATH) &&
          (DevicePathSubType (DevicePath) == MEDIA_HARDDRIVE_DP))
      {
        //
        // Check if this is a gpt partition. If it is, we'll use it. Otherwise,
        // keep searching.
        //
        if ((((HARDDRIVE_DEVICE_PATH *)DevicePath)->MBRType == MBR_TYPE_EFI_PARTITION_TABLE_HEADER) &&
            (((HARDDRIVE_DEVICE_PATH *)DevicePath)->SignatureType == SIGNATURE_TYPE_GUID))
        {
          DevicePath = OrigDevicePath;
          Found      = TRUE;
          break;
        }
      }

      //
      // Still searching. Advance to the next device path node.
      //
      DevicePath = NextDevicePathNode (DevicePath);
    }

    //
    // If we found a good device path, stop searching.
    //
    if (Found) {
      DEBUG ((DEBUG_ERROR, "%a: found GPT partition Index:%d\n", __FUNCTION__, Index));
      break;
    }
  }

  //
  // If a suitable handle was not found, return error.
  //
  if (Found == FALSE) {
    Status = EFI_NOT_FOUND;
    goto CleanUp;
  }

  Status = gBS->HandleProtocol (
                  HandleBuffer[Index],
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&SfProtocol
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to locate Simple FS protocol using the handle to fs0: %r \n", __FUNCTION__, Status));
    goto CleanUp;
  }

  //
  // Open the volume/partition.
  //
  Status = SfProtocol->OpenVolume (SfProtocol, Fs_Handle);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to open Simple FS volume fs0: %r \n", __FUNCTION__, Status));
    goto CleanUp;
  }

CleanUp:
  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  return Status;
}

/**
  MmPagingAuditAppEntryPoint

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point executed successfully.
  @retval other           Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmPagingAuditAppEntryPoint (
  IN     EFI_HANDLE        ImageHandle,
  IN     EFI_SYSTEM_TABLE  *SystemTable
  )
{
  DumpProcessorSpecificHandlers ();
  MemoryMapDumpHandler ();
  LoadedImageTableDump ();
  MemoryAttributesTableDump ();

  if (EFI_ERROR (LocateSmmCommonCommBuffer ())) {
    DEBUG ((DEBUG_ERROR, "%a Comm buffer setup failed\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  SmmMemoryProtectionsDxeToSmmCommunicate ();

  DEBUG ((DEBUG_INFO, "%a the app's done!\n", __FUNCTION__));

  return EFI_SUCCESS;
} // MmPagingAuditAppEntryPoint()
