/** @file -- MmPagingAuditApp.c
This user-facing application collects information from the SMM page tables and
writes it to files.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

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
#include <Library/DxeServicesLib.h>

#include <Protocol/SmmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>
#include <Protocol/Tcg2Protocol.h>

#include <Guid/PiSmmCommunicationRegionTable.h>

#define MEM_INFO_DATABASE_REALLOC_CHUNK    0x1000
#define MEM_INFO_DATABASE_MAX_STRING_SIZE  0x400

EFI_FILE  *mFs_Handle;
VOID      *mPiSmmCommonCommBufferAddress = NULL;
UINTN     mPiSmmCommonCommBufferSize;
CHAR8     *mMemoryInfoDatabaseBuffer   = NULL;
UINTN     mMemoryInfoDatabaseSize      = 0;
UINTN     mMemoryInfoDatabaseAllocSize = 0;

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
  UINTN                                 MinBufferSize, BufferSize;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // Make sure that we have access to a buffer that seems to be sufficient to do everything we need to do.
  //
  if (mPiSmmCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Communication mBuffer not found!\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) + 1;
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
  // Prep the buffer for getting the last of the misc data.
  //
  ZeroMem (CommBufferBase, MinBufferSize);
  CommHeader      = CommBufferBase;
  CopyGuid (&CommHeader->HeaderGuid, &gSpamValidationTestHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  BufferSize                    = MinBufferSize;

  //
  // Signal trip to SMM.
  //
  Status = SmmCommunication->Communicate (
                               SmmCommunication,
                               CommBufferBase,
                               &BufferSize
                               );

  return Status;
} // SmmMemoryProtectionsDxeToSmmCommunicate()

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

    DesiredBufferSize = sizeof (EFI_SMM_COMMUNICATE_HEADER);
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
  Measure PE image into TPM log based on the authenticode image hashing in
  PE/COFF Specification 8.0 Appendix A.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  @param[in] MeasureBootProtocols   Pointer to the located MeasureBoot protocol instances.
  @param[in] ImageAddress           Start address of image buffer.
  @param[in] ImageSize              Image size
  @param[in] LinkTimeBase           Address that the image is loaded into memory.
  @param[in] ImageType              Image subsystem type.
  @param[in] FilePath               File path is corresponding to the input image.

  @retval EFI_SUCCESS            Successfully measure image.
  @retval EFI_OUT_OF_RESOURCES   No enough resource to measure image.
  @retval EFI_UNSUPPORTED        ImageType is unsupported or PE image is mal-format.
  @retval other error value
**/
EFI_STATUS
EFIAPI
Tcg2MeasurePeImage (
  IN  EFI_PHYSICAL_ADDRESS      ImageAddress,
  IN  UINTN                     ImageSize
  )
{
  EFI_STATUS                   Status;
  EFI_TCG2_EVENT               *Tcg2Event;
  UINT32                       EventSize;
  EFI_TCG2_PROTOCOL            *Tcg2Protocol;
  UINT8                        *EventPtr;

  Status    = EFI_UNSUPPORTED;
  EventPtr  = NULL;
  Tcg2Event = NULL;

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2Protocol);
  if (EFI_ERROR (Status) || (Tcg2Protocol == NULL)) {
    ASSERT (FALSE);
    return EFI_UNSUPPORTED;
  }

  EventSize = OFFSET_OF (EFI_TCG2_EVENT, Event);

  //
  // Determine destination PCR by BootPolicy
  //
  // from a malicious GPT disk partition
  EventPtr = AllocateZeroPool (EventSize);
  if (EventPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Tcg2Event                       = (EFI_TCG2_EVENT *)EventPtr;
  Tcg2Event->Size                 = EventSize;
  Tcg2Event->Header.HeaderSize    = sizeof (EFI_TCG2_EVENT_HEADER);
  Tcg2Event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Tcg2Event->Header.EventType     = EV_EFI_BOOT_SERVICES_APPLICATION;
  Tcg2Event->Header.PCRIndex      = 0;

  //
  // Log the PE data
  //
  Status = Tcg2Protocol->HashLogExtendEvent (
                            Tcg2Protocol,
                            PE_COFF_IMAGE,
                            ImageAddress,
                            ImageSize,
                            Tcg2Event
                            );
  DEBUG ((DEBUG_INFO, "DxeTpm2MeasureBootHandler - Tcg2 MeasurePeImage - %r\n", Status));

  if (Status == EFI_VOLUME_FULL) {
    //
    // Volume full here means the image is hashed and its result is extended to PCR.
    // But the event log can't be saved since log area is full.
    // Just return EFI_SUCCESS in order not to block the image load.
    //
    Status = EFI_SUCCESS;
  }

  if (EventPtr != NULL) {
    FreePool (EventPtr);
  }

  return Status;
}

/**
  ResponderValidationTestAppEntry

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point executed successfully.
  @retval other           Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
ResponderValidationTestAppEntry (
  IN     EFI_HANDLE        ImageHandle,
  IN     EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;
  VOID    *SourceBuffer;
  UINTN   SourceSize;

  DEBUG ((DEBUG_INFO, "%a the app's up!\n", __FUNCTION__));

  if (EFI_ERROR (LocateSmmCommonCommBuffer ())) {
    DEBUG ((DEBUG_ERROR, "%a Comm buffer setup failed\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  SmmMemoryProtectionsDxeToSmmCommunicate ();

  Status = GetSectionFromAnyFvByFileType (
             EFI_FV_FILETYPE_MM_CORE_STANDALONE,
             0,
             EFI_SECTION_PE32,
             0,
             &SourceBuffer,
             &SourceSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to get the section from the FV - %r\n", __FUNCTION__, Status));
    return Status;
  }

  Status =  Tcg2MeasurePeImage (
              (EFI_PHYSICAL_ADDRESS)(UINTN)SourceBuffer,
              SourceSize
              );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to measure and log the MM code - %r\n", __FUNCTION__, Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "%a the app's done!\n", __FUNCTION__));

  return EFI_SUCCESS;
} // ResponderValidationTestAppEntry()
