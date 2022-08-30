/** @file
This module collects standalone MM communication buffers published in HOBs and
registers a corresponding communication region table to DXE core.

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmCommonRegion.h>

/**
  Entry Point for MM communication buffer driver DXE phase.

  @param[in] ImageHandle  Image handle of this driver.
  @param[in] SystemTable  A Pointer to the EFI System Table.

  @retval EFI_SUCCESS
  @return Others          Some error occurs.
**/
EFI_STATUS
EFIAPI
MmCommunicationBufferDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                               Status = EFI_NOT_FOUND;
  UINT32                                   DescriptorSize;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
  EFI_MEMORY_DESCRIPTOR                    *Entry;
  // MU_CHANGE Starts: MM_SUPV: Fetch allocated communication buffer from HOBs.
  EFI_GUID              *ConfTableGuid;
  EFI_PEI_HOB_POINTERS  GuidHob;
  MM_COMM_REGION_HOB    *CommRegionHob;

  GuidHob.Guid = GetFirstGuidHob (&gMmCommonRegionHobGuid);
  if (GuidHob.Guid == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Did not locate any published hob under %g to create communication buffer table!!!\n", __FUNCTION__, &gMmCommonRegionHobGuid));
    ASSERT (FALSE);
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  while (GuidHob.Guid != NULL) {
    PiSmmCommunicationRegionTable = NULL;
    CommRegionHob                 = GET_GUID_HOB_DATA (GuidHob.Guid);
    if (CommRegionHob->MmCommonRegionType == MM_USER_BUFFER_T) {
      ConfTableGuid = &gEdkiiPiSmmCommunicationRegionTableGuid;
    } else if (CommRegionHob->MmCommonRegionType == MM_SUPERVISOR_BUFFER_T) {
      ConfTableGuid = &gMmSupervisorCommunicationRegionTableGuid;
    } else if (CommRegionHob->MmCommonRegionType == MM_GHES_BUFFER_T) {
      // Do nothing for GHES region
      goto SkipTableInstall;
    } else {
      // Unrecognized buffer type, do not proceed with comm buffer table installation
      DEBUG ((DEBUG_ERROR, "%a Unsupported communication region type discovered (0x%x), the communication buffer could be misconfigured!!!\n", __FUNCTION__, CommRegionHob->MmCommonRegionType));
      Status = EFI_UNSUPPORTED;
      ASSERT (FALSE);
      goto Done;
    }

    // MU_CHANGE Ends: MM_SUPV.

    DescriptorSize = sizeof (EFI_MEMORY_DESCRIPTOR);
    //
    // Make sure Size != sizeof(EFI_MEMORY_DESCRIPTOR). This will
    // prevent people from having pointer math bugs in their code.
    // now you have to use *DescriptorSize to make things work.
    //
    DescriptorSize += sizeof (UINT64) - (DescriptorSize % sizeof (UINT64));

    //
    // Allocate and fill PiSmmCommunicationRegionTable
    //
    PiSmmCommunicationRegionTable = AllocateReservedPool (sizeof (EDKII_PI_SMM_COMMUNICATION_REGION_TABLE) + DescriptorSize);
    ASSERT (PiSmmCommunicationRegionTable != NULL);
    // MU_CHANGE: MM_SUPV: Exit loop if allocation failed.
    if (PiSmmCommunicationRegionTable == NULL) {
      DEBUG ((DEBUG_ERROR, "%a Failed to allocate buffer for communication buffer table!!!\n", __FUNCTION__));
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    ZeroMem (PiSmmCommunicationRegionTable, sizeof (EDKII_PI_SMM_COMMUNICATION_REGION_TABLE) + DescriptorSize);

    PiSmmCommunicationRegionTable->Version         = EDKII_PI_SMM_COMMUNICATION_REGION_TABLE_VERSION;
    PiSmmCommunicationRegionTable->NumberOfEntries = 1;
    PiSmmCommunicationRegionTable->DescriptorSize  = DescriptorSize;
    Entry                                          = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Entry->Type                                    = EfiConventionalMemory;
    Entry->PhysicalStart                           = (EFI_PHYSICAL_ADDRESS)(UINTN)CommRegionHob->MmCommonRegionAddr; // MU_CHANGE: MM_SUPV: BAR from HOB
    ASSERT (Entry->PhysicalStart != 0);
    // MU_CHANGE: MM_SUPV: Exit loop if HOB data is null pointer.
    if (Entry->PhysicalStart == 0) {
      DEBUG ((
        DEBUG_ERROR,
        "%a Target HOB does not contain valid communication buffer data: type: 0x%x, addr: 0x%p, size: 0x%x!!!\n",
        __FUNCTION__,
        CommRegionHob->MmCommonRegionType,
        CommRegionHob->MmCommonRegionAddr,
        CommRegionHob->MmCommonRegionPages
        ));
      Status = EFI_NOT_STARTED;
      goto Done;
    }

    Entry->VirtualStart  = 0;
    Entry->NumberOfPages = CommRegionHob->MmCommonRegionPages; // MU_CHANGE: MM_SUPV: Buffer size from HOB
    Entry->Attribute     = 0;

    DEBUG ((DEBUG_INFO, "PiSmmCommunicationRegionTable:(0x%x)\n", PiSmmCommunicationRegionTable));
    DEBUG ((DEBUG_INFO, "  Version         - 0x%x\n", PiSmmCommunicationRegionTable->Version));
    DEBUG ((DEBUG_INFO, "  NumberOfEntries - 0x%x\n", PiSmmCommunicationRegionTable->NumberOfEntries));
    DEBUG ((DEBUG_INFO, "  DescriptorSize  - 0x%x\n", PiSmmCommunicationRegionTable->DescriptorSize));
    DEBUG ((DEBUG_INFO, "Entry:(0x%x)\n", Entry));
    DEBUG ((DEBUG_INFO, "  Type            - 0x%x\n", Entry->Type));
    DEBUG ((DEBUG_INFO, "  PhysicalStart   - 0x%lx\n", Entry->PhysicalStart));
    DEBUG ((DEBUG_INFO, "  VirtualStart    - 0x%lx\n", Entry->VirtualStart));
    DEBUG ((DEBUG_INFO, "  NumberOfPages   - 0x%lx\n", Entry->NumberOfPages));
    DEBUG ((DEBUG_INFO, "  Attribute       - 0x%lx\n", Entry->Attribute));

    //
    // Publish this table, so that other driver can use the buffer.
    //
    Status = gBS->InstallConfigurationTable (ConfTableGuid, PiSmmCommunicationRegionTable);
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    // MU_CHANGE Starts: MM_SUPV: Fetch allocated communication buffer from HOBs
    //                   And publish notification when the table is installed.
SkipTableInstall:
    GuidHob.Guid = GET_NEXT_HOB (GuidHob);
    GuidHob.Guid = GetNextGuidHob (&gMmCommonRegionHobGuid, GuidHob.Guid);
  }

Done:
  if (EFI_ERROR (Status) && (PiSmmCommunicationRegionTable != NULL)) {
    // We failed.. At least clean up the mass.
    FreePool (PiSmmCommunicationRegionTable);
  }

  // MU_CHANGE Ends: MM_SUPV.
  return Status;
}
