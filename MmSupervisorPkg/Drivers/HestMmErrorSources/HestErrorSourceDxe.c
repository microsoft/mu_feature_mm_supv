/** @file
  Collects and appends the HEST error source descriptors from the MM drivers.

  The drivers entry point locates the MM Communication protocol and calls into
  Standalone MM to get the HEST error sources length and count. It also
  retrieves descriptor information.
  The information is then used to build the HEST table using the HEST table
  generation protocol.

  Copyright (c) 2020, ARM Limited. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Pi/PiStatusCode.h>
#include <IndustryStandard/Acpi.h>
#include <Guid/MmCommonRegion.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/HestTable.h>

#define MM_SUPV_GHES_SRC_ID   0xBA5E

STATIC HEST_TABLE_PROTOCOL    *mHestProtocol;

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
  EFI_PEI_HOB_POINTERS  GuidHob;
  EFI_PHYSICAL_ADDRESS  StatusBlock;
  MM_COMM_REGION_HOB    *CommRegionHob;

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
  CommRegionHob = NULL;
  GuidHob.Guid = GetFirstGuidHob (&gMmCommonRegionHobGuid);
  while (GuidHob.Guid != NULL) {
    CommRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);
    if (CommRegionHob->MmCommonRegionType == MM_GHES_BUFFER_T) {
      // This is what we need
      break;
    }

    GuidHob.Guid = GET_NEXT_HOB (GuidHob);
    GuidHob.Guid = GetNextGuidHob (&gMmCommonRegionHobGuid, GuidHob.Guid);
  }

  if (CommRegionHob == NULL) {
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  GhesV2ErrorStruct.MaxRawDataLength = (UINT32)EFI_PAGES_TO_SIZE (CommRegionHob->MmCommonRegionPages);
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
  *(EFI_PHYSICAL_ADDRESS*)StatusBlock = CommRegionHob->MmCommonRegionAddr;
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

  GhesV2ErrorStruct.ErrorStatusBlockLength = (UINT32)EFI_PAGES_TO_SIZE (CommRegionHob->MmCommonRegionPages);

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
    CommRegionHob->MmCommonRegionAddr,
    CommRegionHob->MmCommonRegionPages
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
