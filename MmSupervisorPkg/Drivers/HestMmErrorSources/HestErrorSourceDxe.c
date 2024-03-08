/** @file
  Collects and appends the HEST error source descriptors from the MM drivers.

  The drivers entry point locates the MM Communication protocol and calls into
  Standalone MM to get the HEST error sources length and count. It also
  retrieves descriptor information.
  The information is then used to build the HEST table using the HEST table
  generation protocol.

  Copyright (c) 2020, ARM Limited. All rights reserved.
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Pi/PiStatusCode.h>
#include <IndustryStandard/Acpi.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmGhesTableRegion.h>
#include <Protocol/MmCommunication.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MmUnblockMemoryLib.h>

#include <Protocol/HestTable.h>

#define MM_SUPV_GHES_SRC_ID   0xBA5E

STATIC HEST_TABLE_PROTOCOL    *mHestProtocol;

/**
  Locate the MM communication buffer and protocol, then use it to communicate GHES buffer information to
  MmSupervisorErrorReport.

  @param[in, out] TcgNvs         The NVS subject to send to MM environment.

  @return                        The status for locating MM common buffer, communicate to MM, etc.

**/
EFI_STATUS
EFIAPI
ExchangeCommonBuffer (
  IN  EFI_PHYSICAL_ADDRESS  Address,
  IN  UINTN                 PageNumber
  )
{
  EFI_STATUS                               Status;
  EFI_MM_COMMUNICATION_PROTOCOL            *MmCommunication;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
  EFI_MEMORY_DESCRIPTOR                    *MmCommMemRegion;
  EFI_MM_COMMUNICATE_HEADER                *CommHeader;
  MM_GHES_TABLE_REGION                     *CommBuffer;
  UINTN                                    CommBufferSize;
  UINTN                                    Index;

  // Step 0: Sanity check for input argument
  if (((VOID*)(UINTN)Address == NULL) || (PageNumber == 0)) {
    DEBUG ((DEBUG_ERROR, "%a - Input argument is NULL!\n", __FUNCTION__));
    return EFI_INVALID_PARAMETER;
  }

  // Step 1: Grab the common buffer header
  Status = EfiGetSystemConfigurationTable (&gEdkiiPiSmmCommunicationRegionTableGuid, (VOID **)&PiSmmCommunicationRegionTable);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to locate SMM communication common buffer - %r!\n", __FUNCTION__, Status));
    return Status;
  }

  // Step 2: Grab one that is large enough to hold MM_GHES_TABLE_REGION, the IPL one should be sufficient
  CommBufferSize  = 0;
  MmCommMemRegion = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (MmCommMemRegion->Type == EfiConventionalMemory) {
      CommBufferSize = EFI_PAGES_TO_SIZE ((UINTN)MmCommMemRegion->NumberOfPages);
      if (CommBufferSize >= (sizeof (MM_GHES_TABLE_REGION) + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))) {
        break;
      }
    }

    MmCommMemRegion = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MmCommMemRegion + PiSmmCommunicationRegionTable->DescriptorSize);
  }

  if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
    // Could not find one that meets our goal...
    DEBUG ((DEBUG_ERROR, "%a - Could not find a common buffer that is big enough for NVS!\n", __FUNCTION__));
    return EFI_OUT_OF_RESOURCES;
  }

  // Step 3: Start to populate contents
  // Step 3.1: MM Communication common header
  CommHeader     = (EFI_MM_COMMUNICATE_HEADER *)(UINTN)MmCommMemRegion->PhysicalStart;
  CommBufferSize = sizeof (MM_GHES_TABLE_REGION) + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  ZeroMem (CommHeader, CommBufferSize);
  CopyGuid (&CommHeader->HeaderGuid, &gMmGhesTableRegionGuid);
  CommHeader->MessageLength = sizeof (MM_GHES_TABLE_REGION);

  // Step 3.2: MM_GHES_TABLE_REGION content per our needs
  CommBuffer                                   = (MM_GHES_TABLE_REGION *)(CommHeader->Data);
  CommBuffer->MmGhesTableRegion.Attribute      = EFI_MEMORY_XP;
  CommBuffer->MmGhesTableRegion.PhysicalStart  = Address;
  CommBuffer->MmGhesTableRegion.VirtualStart   = Address;
  CommBuffer->MmGhesTableRegion.NumberOfPages  = PageNumber;
  CommBuffer->MmGhesTableRegion.Type           = EfiACPIMemoryNVS;

  // Step 4: Locate the protocol and signal Mmi.
  Status = gBS->LocateProtocol (&gEfiMmCommunicationProtocolGuid, NULL, (VOID **)&MmCommunication);
  if (!EFI_ERROR (Status)) {
    Status = MmCommunication->Communicate (MmCommunication, CommHeader, &CommBufferSize);
    DEBUG ((DEBUG_INFO, "%a - Communicate() = %r\n", __FUNCTION__, Status));
  } else {
    DEBUG ((DEBUG_ERROR, "%a - Failed to locate MmCommunication protocol - %r\n", __FUNCTION__, Status));
    return Status;
  }

  // Step 5: If everything goes well, populate the channel number
  if (EFI_ERROR (CommBuffer->ReturnStatus)) {
    Status = ENCODE_ERROR ((UINTN)CommBuffer->ReturnStatus);
  } else {
    Status = EFI_SUCCESS;
  }

  return Status;
}

/**
  Collect HEST error source descriptors from all Standalone MM drivers and append
  them to the HEST table.

  Use MM Communication Protocol to communicate and collect the error source
  descriptor information from Standalone MM. Check for the required buffer size
  returned by the MM driver. Allocate buffer of adequate size and call again into
  MM.

  @retval EFI_SUCCESS          Successful to collect and append the error source
                               descriptors to HEST table.
  @retval EFI_OUT_OF_RESOURCES Memory allocation failure.
  @retval Other                For any other error.

**/
STATIC
EFI_STATUS
AppendMmSupvErrorSources (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  StatusBlock;
  EFI_PHYSICAL_ADDRESS  MmCommonRegionAddr  = 0;
  UINT64                MmCommonRegionPages = 0;

  EFI_ACPI_6_4_GENERIC_HARDWARE_ERROR_SOURCE_VERSION_2_STRUCTURE  GhesV2ErrorStruct;

  SetMem (&GhesV2ErrorStruct, sizeof (GhesV2ErrorStruct), 0);
  GhesV2ErrorStruct.Type = EFI_ACPI_6_4_GENERIC_HARDWARE_ERROR_VERSION_2;
  GhesV2ErrorStruct.SourceId = MM_SUPV_GHES_SRC_ID;
  GhesV2ErrorStruct.RelatedSourceId = 0xFFFF; // TODO: check to see if this needs firmware_first flag
  // GhesV2ErrorStruct.Flags
  GhesV2ErrorStruct.Enabled = 1;
  GhesV2ErrorStruct.NumberOfRecordsToPreAllocate = 1; // Only 1 exception from MM supv, then we should reboot...
  GhesV2ErrorStruct.MaxSectionsPerRecord = 1; // Only 1 section in from MM supv.

  // Connect up the error status block to allocated GHES space buffer
  MmCommonRegionPages = FixedPcdGet64 (PcdGhesBufferPages);
  Status  = gBS->AllocatePages (AllocateAnyPages, EfiACPIMemoryNVS, MmCommonRegionPages, &MmCommonRegionAddr);
  if (EFI_ERROR (Status)) {
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  Status = MmUnblockMemoryRequest (MmCommonRegionAddr, MmCommonRegionPages);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Unable to notify StandaloneMM. Code=%r\n", __FUNCTION__, Status));
    goto Done;
  } else {
    DEBUG ((DEBUG_INFO, "%a: StandaloneMM Hob data published\n", __FUNCTION__));
  }

  Status = ExchangeCommonBuffer (MmCommonRegionAddr, MmCommonRegionPages);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to exchange common buffer. Code=%r\n", __FUNCTION__, Status));
    goto Done;
  }

  GhesV2ErrorStruct.MaxRawDataLength = (UINT32)EFI_PAGES_TO_SIZE (MmCommonRegionPages);
  GhesV2ErrorStruct.ErrorStatusAddress.AddressSpaceId = EFI_ACPI_6_4_SYSTEM_MEMORY;
  GhesV2ErrorStruct.ErrorStatusAddress.RegisterBitWidth = 64; // 64 bit physical address
  GhesV2ErrorStruct.ErrorStatusAddress.RegisterBitOffset = 0;
  GhesV2ErrorStruct.ErrorStatusAddress.AccessSize = EFI_ACPI_6_4_QWORD;

  // The Error Status Address structure contains the address that contains the pointer to status block
  // And the content here will be the generic status (follow BertErrorBlockAddErrorData, where the data should be a MU_TELEMETRY_CPER_SECTION_DATA)
  StatusBlock = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocateReservedPool (sizeof (EFI_PHYSICAL_ADDRESS));
  if ((VOID*)StatusBlock == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }
  *(EFI_PHYSICAL_ADDRESS*)StatusBlock = MmCommonRegionAddr;
  GhesV2ErrorStruct.ErrorStatusAddress.Address = StatusBlock;

  SetMem (&GhesV2ErrorStruct.NotificationStructure, sizeof (GhesV2ErrorStruct.NotificationStructure), 0);
  GhesV2ErrorStruct.NotificationStructure.Type = EFI_ACPI_6_4_HARDWARE_ERROR_NOTIFICATION_NMI;
  GhesV2ErrorStruct.NotificationStructure.Length = sizeof (GhesV2ErrorStruct.NotificationStructure);
  // GhesV2ErrorStruct.NotificationStructure.ConfigurationWriteEnable; // Not modifiable by OSPM
  // GhesV2ErrorStruct.NotificationStructure.PollInterval;
  GhesV2ErrorStruct.NotificationStructure.Vector = EFI_SW_EC_X64_GP_FAULT;
  // GhesV2ErrorStruct.NotificationStructure.SwitchToPollingThresholdValue;
  // GhesV2ErrorStruct.NotificationStructure.SwitchToPollingThresholdWindow;
  // GhesV2ErrorStruct.NotificationStructure.ErrorThresholdValue;
  // GhesV2ErrorStruct.NotificationStructure.ErrorThresholdWindow;

  GhesV2ErrorStruct.ErrorStatusBlockLength = (UINT32)EFI_PAGES_TO_SIZE (MmCommonRegionPages);

  // TODO: This is not properly used yet. Maybe write leave this to the platform?
  GhesV2ErrorStruct.ReadAckRegister.AddressSpaceId = EFI_ACPI_6_4_SYSTEM_MEMORY;
  GhesV2ErrorStruct.ReadAckRegister.RegisterBitWidth = 64; // 64 bit physical address
  GhesV2ErrorStruct.ReadAckRegister.RegisterBitOffset = 0;
  GhesV2ErrorStruct.ReadAckRegister.AccessSize = EFI_ACPI_6_4_QWORD;
  GhesV2ErrorStruct.ReadAckRegister.Address = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocateReservedPool (sizeof (EFI_PHYSICAL_ADDRESS));

  GhesV2ErrorStruct.ReadAckPreserve = 0;
  GhesV2ErrorStruct.ReadAckWrite = BIT0;

  DEBUG ((
    DEBUG_INFO,
    "HEST Generic Error Status Block: Address = 0x%p, Pages = 0x%x \n",
    MmCommonRegionAddr,
    MmCommonRegionPages
    ));
  //
  // Append the error source descriptors to HEST table using the HEST table
  // generation protocol.
  //
  Status = mHestProtocol->AppendErrorSourceDescriptors (
                            &GhesV2ErrorStruct,
                            sizeof (GhesV2ErrorStruct),
                            1
                            );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Failed to append error source(s), status: %r\n",
      Status
      ));
  }

Done:
  if (EFI_ERROR (Status)) {
    if (MmCommonRegionAddr != 0) {
      FreePages ((VOID*)MmCommonRegionAddr, MmCommonRegionPages);
    }
  }
  return Status;
}

/**
  The Entry Point for Hest Error Source DXE driver.

  Locates the Hest Table generation and MM Communication2 protocols. Using the
  MM Communication2, the driver collects the Error Source Descriptor(s) from
  Standalone MM. It then appends those Error Source Descriptor(s) to the Hest
  table using the Hest Table generation protocol.

  @param[in] ImageHandle The firmware allocated handle for the EFI image.
  @param[in] SystemTable A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
HestErrorSourceInitialize (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = gBS->LocateProtocol (
                  &gHestTableProtocolGuid,
                  NULL,
                  (VOID **)&mHestProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Failed to locate HEST table generation protocol, status:%r\n",
      Status
      ));
    return Status;
  }

  //
  // Append HEST error sources retrieved from StandaloneMM, if any, into the HEST
  // ACPI table.
  //
  Status = AppendMmSupvErrorSources ();
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "HEST table creation faied, status:%r\n",
      Status
      ));
  }

  Status = mHestProtocol->InstallHestTable ();
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "HEST table installation faied, status:%r\n",
      Status
      ));
  }

  return Status;
}
