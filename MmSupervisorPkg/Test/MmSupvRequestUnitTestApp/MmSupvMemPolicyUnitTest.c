/** @file -- MmSupvRequestUnitTestApp.c

Tests for MM SUPV request operations.

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <SmmSecurePolicy.h>

#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmSupervisorRequestData.h>

#include <Protocol/MmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UnitTestLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiCpuLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <IndustryStandard/DmaRemappingReportingTable.h>

#include "MmPolicyMeasurementLevels.h"
#include "IVRS.h"
#include "Acpi.h"

#define UNIT_TEST_APP_NAME        "MM Supervisor Request Test Cases"
#define UNIT_TEST_APP_VERSION     "1.0"

#define UNDEFINED_LEVEL           MAX_UINT32

MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SupvCommunication = NULL;
VOID      *mMmSupvCommonCommBufferAddress = NULL;
UINTN     mMmSupvCommonCommBufferSize;

///================================================================================================
///================================================================================================
///
/// HELPER FUNCTIONS
///
///================================================================================================
///================================================================================================

/*
  Helper function to get all IOMMU controller regions from DMAR table
*/
EFI_STATUS
GetIommuBaseIntel (
  OUT UINT64      **BaseAddress,
  OUT UINT64      **Size,
  OUT UINTN       *Count
  )
{
  EFI_ACPI_DMAR_HEADER            *AcpiDmarTable;
  EFI_ACPI_DMAR_STRUCTURE_HEADER  *DmarHeader;
  EFI_STATUS                      Status;
  UINTN                           VtdIndex;

  // First get DMAR table
  Status = GetAcpiTable (EFI_ACPI_6_3_DMA_REMAPPING_TABLE_SIGNATURE, (VOID **)&AcpiDmarTable);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // Then get through the table to get a count of VTds
  VtdIndex = 0;
  DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *)((UINTN)(AcpiDmarTable + 1));
  while ((UINTN)DmarHeader < (UINTN)AcpiDmarTable + AcpiDmarTable->Header.Length) {
    switch (DmarHeader->Type) {
      case EFI_ACPI_DMAR_TYPE_DRHD:
        VtdIndex++;
        break;
      default:
        break;
    }

    DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *)((UINTN)DmarHeader + DmarHeader->Length);
  }

  *BaseAddress = AllocatePool (VtdIndex * sizeof (UINT64));
  if (BaseAddress == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *Size = AllocatePool (VtdIndex * sizeof (UINT64));
  if (Size == NULL) {
    FreePool (*BaseAddress);
    return EFI_OUT_OF_RESOURCES;
  }

  *Count = VtdIndex;

  VtdIndex = 0;
  DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *)((UINTN)(AcpiDmarTable + 1));
  while ((UINTN)DmarHeader < (UINTN)AcpiDmarTable + AcpiDmarTable->Header.Length) {
    switch (DmarHeader->Type) {
      case EFI_ACPI_DMAR_TYPE_DRHD:
        (*BaseAddress)[VtdIndex] = ((EFI_ACPI_DMAR_DRHD_HEADER *)DmarHeader)->RegisterBaseAddress;
        (*Size)[VtdIndex] = EFI_PAGE_SIZE;
        VtdIndex++;
        break;

      default:
        break;
    }

    DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *)((UINTN)DmarHeader + DmarHeader->Length);
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/*
  Helper function to get all IOMMU controller regions from IVRS table
*/
EFI_STATUS
GetIommuBaseAmd (
  OUT UINT64      **BaseAddress,
  OUT UINT64      **Size,
  OUT UINTN       *Count
  )
{
  EFI_ACPI_IVRS_HEADER  *AcpiIVRSTable;
  IVHD_Header           *IvhdHeader;
  EFI_STATUS            Status;
  UINTN                 IommuIndex;

  // First get IVRS table
  Status = GetAcpiTable (EFI_ACPI_6_3_IO_VIRTUALIZATION_REPORTING_STRUCTURE_SIGNATURE, (VOID **)&AcpiIVRSTable);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // Then get through the table to get a count of IVHDs
  IommuIndex = 0;
  IvhdHeader = (IVHD_Header *)((UINTN)(AcpiIVRSTable + 1));
  while ((UINTN)IvhdHeader < (UINTN)AcpiIVRSTable + AcpiIVRSTable->Header.Length) {
    switch (IvhdHeader->Type) {
      case IVHD_TYPE_10H:
      case IVHD_TYPE_11H:
      case IVHD_TYPE_40H:
        IommuIndex++;
        break;
      default:
        break;
    }

    IvhdHeader = (IVHD_Header *)((UINTN)IvhdHeader + IvhdHeader->Length);
  }

  *BaseAddress = AllocatePool (IommuIndex * sizeof (UINT64));
  if (BaseAddress == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *Size = AllocatePool (IommuIndex * sizeof (UINT64));
  if (Size == NULL) {
    FreePool (*BaseAddress);
    return EFI_OUT_OF_RESOURCES;
  }

  *Count = IommuIndex;

  IommuIndex = 0;
  IvhdHeader = (IVHD_Header *)((UINTN)(AcpiIVRSTable + 1));
  while ((UINTN)IvhdHeader < (UINTN)AcpiIVRSTable + AcpiIVRSTable->Header.Length) {
    switch (IvhdHeader->Type) {
      case IVHD_TYPE_10H:
      case IVHD_TYPE_11H:
      case IVHD_TYPE_40H:
        (*BaseAddress)[IommuIndex] = IvhdHeader->IOMMUBaseAddress;
        (*Size)[IommuIndex] = EFI_PAGE_SIZE;
        IommuIndex++;
        break;

      default:
        break;
    }

    IvhdHeader = (IVHD_Header *)((UINTN)IvhdHeader + IvhdHeader->Length);
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/*
  Helper function to check possible policy level against IOMMU regions
*/
STATIC
EFI_STATUS
VerifyIommuMemoryWithPolicy (
  IN  VOID        *MemPolicy,
  IN  UINT32      MemPolicyCount,
  IN  UINT32      AccessAttr
  )
{
  EFI_STATUS  Status;
  UINT64      *IommuBases;
  UINT64      *IommuSizes;
  UINT64      Count;
  UINTN       Index1;
  UINTN       Index2;
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *MemDesc;

  MemDesc = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0*)MemPolicy;

  if (!StandardSignatureIsAuthenticAMD ()) {
    // Intel processors
    Status = GetIommuBaseIntel (&IommuBases, &IommuSizes, &Count);
  } else {
    // AMD processors
    Status = GetIommuBaseAmd (&IommuBases, &IommuSizes, &Count);
  }

  if (EFI_ERROR (Status)) {
    goto Done;
  }

  for (Index1 = 0; Index1 < Count; Index1 ++) {
    for (Index2 = 0; Index2 < MemPolicyCount; Index2 ++) {
      if (((IommuBases[Index1] <= MemDesc[Index2].BaseAddress &&
            IommuBases[Index1] + IommuSizes[Index1] > MemDesc[Index2].BaseAddress)) ||
          (IommuBases[Index1] <= (MemDesc[Index2].BaseAddress + MemDesc[Index2].Size) &&
            IommuBases[Index1] + IommuSizes[Index1] > MemDesc[Index2].BaseAddress + MemDesc[Index2].Size)) {
        // Shoot, found an overlap and we are an allow list...
        Status = EFI_SECURITY_VIOLATION;
        goto Done;
      }
    }
  }

Done:
  if (IommuBases != NULL) {
    FreePool (IommuBases);
  }
  if (IommuSizes != NULL) {
    FreePool (IommuSizes);
  }
  return Status;
}

/*
  Helper function to check possible policy level on the MSR block
*/
EFI_STATUS
EFIAPI
VerifyMemPolicy (
  IN  VOID        *MemPolicy,
  IN  UINT32      MemPolicyCount,
  IN  UINT32      AccessAttr,
  OUT UINT32      *Level
  )
{
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemEntries;
  UINTN Index1;
  UINTN Index2;
  EFI_STATUS Status;

  UINTN                  MapKey;
  UINTN                  MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapStart;
  UINTN                  MemoryMapEntryCount;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;

  if (MemPolicy == NULL || Level == NULL || AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY) {
    return EFI_INVALID_PARAMETER;
  }

  MemEntries = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0*)MemPolicy;

  // The method is very brute force...

  // First set the level to at most 0, failing everything here
  // will not make it below that value
  *Level = 0;

  // Grab the memory map from DXE core and verify the below:
  // 1.1 Do NOT contain any mappings to EfiConventionalMemory (e.g. no OS/VMM owned memory)
  // 1.2 Do NOT contain any mappings to code sections within EfiRuntimeServicesCode
  MemoryMapSize = 0;
  MemoryMap     = NULL;
  Status        = gBS->GetMemoryMap (
                         &MemoryMapSize,
                         MemoryMap,
                         &MapKey,
                         &DescriptorSize,
                         &DescriptorVersion
                         );
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);

  do {
    Status = gBS->AllocatePool (EfiBootServicesData, MemoryMapSize, (VOID **)&MemoryMap);
    ASSERT (MemoryMap != NULL);

    Status = gBS->GetMemoryMap (
                    &MemoryMapSize,
                    MemoryMap,
                    &MapKey,
                    &DescriptorSize,
                    &DescriptorVersion
                    );
    if (EFI_ERROR (Status)) {
      gBS->FreePool (MemoryMap);
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  //
  // Get Count
  //
  MemoryMapEntryCount  = MemoryMapSize/DescriptorSize;
  MemoryMapStart       = MemoryMap;
  for (Index1 = 0; Index1 < MemoryMapEntryCount; Index1++) {
    switch (MemoryMap->Type) {
      case EfiConventionalMemory:
      case EfiRuntimeServicesCode:
        for (Index2 = 0; Index2 < MemPolicyCount; Index2 ++) {
          if (((MemoryMap->PhysicalStart <= MemEntries[Index2].BaseAddress &&
               MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE (MemoryMap->NumberOfPages) > MemEntries[Index2].BaseAddress)) ||
              (MemoryMap->PhysicalStart <= (MemEntries[Index2].BaseAddress + MemEntries[Index2].Size) &&
               MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE (MemoryMap->NumberOfPages) > MemEntries[Index2].BaseAddress + MemEntries[Index2].Size)) {
            // Shoot, found a match and we are an allow list...
            goto Done;
          }
        }
        break;
    }

    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, DescriptorSize);
  }

  // 1.3 Do NOT have execute and write permissions for the same page
  for (Index2 = 0; Index2 < MemPolicyCount; Index2 ++) {
    if ((MemEntries[Index2].MemAttributes & (SECURE_POLICY_RESOURCE_ATTR_WRITE|SECURE_POLICY_RESOURCE_ATTR_EXECUTE)) ==
        (SECURE_POLICY_RESOURCE_ATTR_WRITE|SECURE_POLICY_RESOURCE_ATTR_EXECUTE)) {
      // Shoot, found a W/EX region and we are an allow list...
      goto Done;
    }
  }

  // So level 10 passed, set it to at least level 10
  *Level = SMM_POLICY_LEVEL_20;

  // Level 20:
  // Write access must be denied to any MMIO or other system registers which allow configuration of any of the system IOMMUs
  Status = VerifyIommuMemoryWithPolicy (MemPolicy, MemPolicyCount, AccessAttr);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // So level 20 passed, set it to at least level 20
  *Level = SMM_POLICY_LEVEL_20;

  if (!StandardSignatureIsAuthenticAMD ()) {
    //TODO: Still need to check overlap with TXT regions
    goto Done;
  }

  // At this point, IO will not prevent the measurement level to be the highest
  *Level = MAX_SUPPORTED_LEVEL;

Done:
  return Status;
}
