/** @file -- MmPagingAuditApp.c
This user-facing application collects information from the SMM page tables and
writes it to files.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <SeaResponder.h>
#include <SmmSecurePolicy.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PrintLib.h>
#include <Library/PcdLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DxeServicesLib.h>

#include <Protocol/SmmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>
#include <Protocol/Tcg2Protocol.h>

#include <Guid/SeaTestCommRegion.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

VOID   *mPiSmmCommonCommBufferAddress = NULL;
UINTN  mPiSmmCommonCommBufferSize;

/**
  This helper function actually sends the requested communication
  to the SMM driver.

  @retval     EFI_SUCCESS                  Communication was successful.
  @retval     EFI_ABORTED                  Some error occurred.
  @retval     EFI_BUFFER_TOO_SMALL         Buffer size smaller than minimal requirement.

**/
STATIC
EFI_STATUS
DxeToSmmCommunicate (
  VOID
  )
{
  EFI_STATUS                            Status            = EFI_SUCCESS;
  MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication = NULL;
  VOID                                  *CommBufferBase;
  EFI_SMM_COMMUNICATE_HEADER            *CommHeader;
  UINTN                                 MinBufferSize, BufferSize;
  SEA_TEST_COMM_INPUT_REGION            *SeaTestCommInputBuffer;
  SEA_TEST_COMM_OUTPUT_REGION           *SeaTestCommOutputputBuffer;

  DEBUG ((DEBUG_INFO, "%a()\n", __func__));

  //
  // Make sure that we have access to a buffer that seems to be sufficient to do everything we need to do.
  //
  if (mPiSmmCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Communication mBuffer not found!\n", __func__));
    return EFI_ABORTED;
  }

  MinBufferSize = OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data) + sizeof (SEA_TEST_COMM_INPUT_REGION) + PcdGetSize (PcdAuxBinFile);
  if (MinBufferSize > mPiSmmCommonCommBufferSize) {
    DEBUG ((DEBUG_ERROR, "%a - Communication mBuffer is too small\n", __func__));
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
  ZeroMem (CommBufferBase, mPiSmmCommonCommBufferSize);
  CommHeader = CommBufferBase;
  CopyGuid (&CommHeader->HeaderGuid, &gSeaValidationTestHandlerGuid);
  CommHeader->MessageLength = MinBufferSize - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);

  SeaTestCommInputBuffer                        = (SEA_TEST_COMM_INPUT_REGION *)((UINTN)CommHeader + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data));
  SeaTestCommInputBuffer->SupervisorAuxFileSize = PcdGetSize (PcdAuxBinFile);
  CopyMem (SeaTestCommInputBuffer->SupervisorAuxFileBase, PcdGetPtr (PcdAuxBinFile), PcdGetSize (PcdAuxBinFile));

  SeaTestCommInputBuffer->SupvDigestList[MMI_ENTRY_DIGEST_INDEX].digests[0].hashAlg = TPM_ALG_SHA256;
  SeaTestCommInputBuffer->SupvDigestList[MMI_ENTRY_DIGEST_INDEX].count              = 1;
  CopyMem (SeaTestCommInputBuffer->SupvDigestList[MMI_ENTRY_DIGEST_INDEX].digests[0].digest.sha256, PcdGetPtr (PcdMmiEntryBinHash), SHA256_DIGEST_SIZE);

  SeaTestCommInputBuffer->SupvDigestList[MM_SUPV_DIGEST_INDEX].digests[0].hashAlg = TPM_ALG_SHA256;
  SeaTestCommInputBuffer->SupvDigestList[MM_SUPV_DIGEST_INDEX].count              = 1;
  CopyMem (SeaTestCommInputBuffer->SupvDigestList[MM_SUPV_DIGEST_INDEX].digests[0].digest.sha256, PcdGetPtr (PcdMmSupervisorCoreHash), SHA256_DIGEST_SIZE);

  SeaTestCommInputBuffer->SupvDigestListCount = SUPPORTED_DIGEST_COUNT;
  SeaTestCommInputBuffer->MmiEntryFileSize    = PcdGet64 (PcdMmiEntryBinSize);

  BufferSize = mPiSmmCommonCommBufferSize;

  //
  // Signal trip to SMM.
  //
  Status = SmmCommunication->Communicate (
                               SmmCommunication,
                               CommBufferBase,
                               &BufferSize
                               );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Communication failed - %r\n", __func__, Status));
    goto Exit;
  }

  SeaTestCommOutputputBuffer = (SEA_TEST_COMM_OUTPUT_REGION *)(CommHeader + 1);
  DEBUG ((DEBUG_INFO, "%a - FirmwarePolicy: %p\n", __func__, &SeaTestCommOutputputBuffer->FirmwarePolicy));

Exit:
  return Status;
} // DxeToSmmCommunicate()

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
      DEBUG ((DEBUG_ERROR, "%a Failed to get system configuration table %r\n", __func__, Status));
      return Status;
    }

    Status = EFI_BAD_BUFFER_SIZE;

    DesiredBufferSize = sizeof (EFI_SMM_COMMUNICATE_HEADER);
    DEBUG ((DEBUG_ERROR, "%a desired comm buffer size %ld\n", __func__, DesiredBufferSize));
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
  IN  EFI_PHYSICAL_ADDRESS  ImageAddress,
  IN  UINTN                 ImageSize
  )
{
  EFI_STATUS         Status;
  EFI_TCG2_EVENT     *Tcg2Event;
  UINT32             EventSize;
  EFI_TCG2_PROTOCOL  *Tcg2Protocol;
  UINT8              *EventPtr;

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
  EFI_STATUS  Status;
  VOID        *SourceBuffer;
  UINTN       SourceSize;

  DEBUG ((DEBUG_INFO, "%a the app's up!\n", __func__));

  if (EFI_ERROR (LocateSmmCommonCommBuffer ())) {
    DEBUG ((DEBUG_ERROR, "%a Comm buffer setup failed\n", __func__));
    return EFI_ABORTED;
  }

  DxeToSmmCommunicate ();

  Status = GetSectionFromAnyFvByFileType (
             EFI_FV_FILETYPE_MM_CORE_STANDALONE,
             0,
             EFI_SECTION_PE32,
             0,
             &SourceBuffer,
             &SourceSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to get the section from the FV - %r\n", __func__, Status));
    return Status;
  }

  Status =  Tcg2MeasurePeImage (
              (EFI_PHYSICAL_ADDRESS)(UINTN)SourceBuffer,
              SourceSize
              );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to measure and log the MM code - %r\n", __func__, Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "%a the app's done!\n", __func__));

  return EFI_SUCCESS;
} // ResponderValidationTestAppEntry()
