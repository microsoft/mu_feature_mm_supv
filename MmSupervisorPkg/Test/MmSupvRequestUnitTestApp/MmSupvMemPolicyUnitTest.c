/** @file -- MmSupvRequestUnitTestApp.c

Tests for MM SUPV request operations.

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <SmmSecurePolicy.h>

#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MemoryAttributesTable.h>

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
#include <Library/IoLib.h>

#include <IndustryStandard/DmaRemappingReportingTable.h>

#include "MmPolicyMeasurementLevels.h"
#include "IVRS.h"
#include "Acpi.h"

#define UNIT_TEST_APP_NAME     "MM Supervisor Request Test Cases"
#define UNIT_TEST_APP_VERSION  "1.0"

#define UNDEFINED_LEVEL  MAX_UINT32

MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SupvCommunication              = NULL;
VOID                                  *mMmSupvCommonCommBufferAddress = NULL;
UINTN                                 mMmSupvCommonCommBufferSize;

/// ================================================================================================
/// ================================================================================================
///
/// HELPER FUNCTIONS
///
/// ================================================================================================
/// ================================================================================================

/*
  Helper function to get all IOMMU controller regions from DMAR table
*/
EFI_STATUS
GetIommuBaseIntel (
  OUT UINT64  **BaseAddress,
  OUT UINT64  **Size,
  OUT UINTN   *Count
  )
{
  EFI_ACPI_DMAR_HEADER            *AcpiDmarTable;
  EFI_ACPI_DMAR_STRUCTURE_HEADER  *DmarHeader;
  EFI_STATUS                      Status;
  UINTN                           VtdIndex;

  // First get DMAR table
  AcpiDmarTable = NULL;
  Status        = GetAcpiTable (EFI_ACPI_6_3_DMA_REMAPPING_TABLE_SIGNATURE, (VOID **)&AcpiDmarTable);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // Then get through the table to get a count of VTds
  VtdIndex   = 0;
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

  VtdIndex   = 0;
  DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *)((UINTN)(AcpiDmarTable + 1));
  while ((UINTN)DmarHeader < (UINTN)AcpiDmarTable + AcpiDmarTable->Header.Length) {
    switch (DmarHeader->Type) {
      case EFI_ACPI_DMAR_TYPE_DRHD:
        (*BaseAddress)[VtdIndex] = ((EFI_ACPI_DMAR_DRHD_HEADER *)DmarHeader)->RegisterBaseAddress;
        (*Size)[VtdIndex]        = EFI_PAGE_SIZE;
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
  OUT UINT64  **BaseAddress,
  OUT UINT64  **Size,
  OUT UINTN   *Count
  )
{
  EFI_ACPI_IVRS_HEADER  *AcpiIVRSTable;
  IVHD_Header           *IvhdHeader;
  EFI_STATUS            Status;
  UINTN                 IommuIndex;

  // First get IVRS table
  AcpiIVRSTable = NULL;
  Status        = GetAcpiTable (EFI_ACPI_6_3_IO_VIRTUALIZATION_REPORTING_STRUCTURE_SIGNATURE, (VOID **)&AcpiIVRSTable);
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
        (*Size)[IommuIndex]        = EFI_PAGE_SIZE;
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
  Helper function to get all TXT related regions for Intel processors
*/
EFI_STATUS
GetTxtRegions (
  OUT UINT64  **BaseAddress,
  OUT UINT64  **Size,
  OUT UINTN   *Count
  )
{
  UINTN   TxtIndex;
  UINT32  Temp;

  // TXT public and private regions + Heap + DPR
  *BaseAddress = AllocatePool (TXT_REGION_COUNT * sizeof (UINT64));
  if (BaseAddress == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *Size = AllocatePool (TXT_REGION_COUNT * sizeof (UINT64));
  if (Size == NULL) {
    FreePool (*BaseAddress);
    return EFI_OUT_OF_RESOURCES;
  }

  TxtIndex                 = 0;
  (*Size)[TxtIndex]        = TXT_DEVICE_SIZE;
  (*BaseAddress)[TxtIndex] = TXT_DEVICE_BASE;

  TxtIndex++;
  (*Size)[TxtIndex]        = MmioRead32 (TXT_HEAP_SIZE_REG);
  (*BaseAddress)[TxtIndex] = MmioRead32 (TXT_HEAP_BASE_REG);

  TxtIndex++;
  Temp = MmioRead32 (TXT_DPR_REG);

  (*Size)[TxtIndex] = (Temp & 0xFF0) << 16;

  (*BaseAddress)[TxtIndex] = (Temp & 0xFFF00000) - (*Size)[TxtIndex];

  *Count = TxtIndex;
  return EFI_SUCCESS;
}

/*
  Helper function to check possible policy level against IOMMU regions
*/
STATIC
EFI_STATUS
VerifyIommuMemoryWithPolicy (
  IN  VOID    *MemPolicy,
  IN  UINT32  MemPolicyCount,
  IN  UINT32  AccessAttr
  )
{
  EFI_STATUS                                  Status;
  UINT64                                      *IommuBases;
  UINT64                                      *IommuSizes;
  UINT64                                      Count;
  UINTN                                       Index1;
  UINTN                                       Index2;
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemDesc;

  IommuBases = NULL;
  IommuSizes = NULL;
  MemDesc    = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *)MemPolicy;

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

  for (Index1 = 0; Index1 < Count; Index1++) {
    for (Index2 = 0; Index2 < MemPolicyCount; Index2++) {
      if ((((IommuBases[Index1] <= MemDesc[Index2].BaseAddress) &&
            (IommuBases[Index1] + IommuSizes[Index1] > MemDesc[Index2].BaseAddress))) ||
          ((IommuBases[Index1] < (MemDesc[Index2].BaseAddress + MemDesc[Index2].Size)) &&
           (IommuBases[Index1] + IommuSizes[Index1] >= MemDesc[Index2].BaseAddress + MemDesc[Index2].Size)))
      {
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
  Helper function to check possible policy level against TXT regions
*/
STATIC
EFI_STATUS
VerifyTxtMemoryWithPolicy (
  IN  VOID    *MemPolicy,
  IN  UINT32  MemPolicyCount,
  IN  UINT32  AccessAttr
  )
{
  EFI_STATUS                                  Status;
  UINT64                                      *TxtBases;
  UINT64                                      *TxtSizes;
  UINT64                                      Count;
  UINTN                                       Index1;
  UINTN                                       Index2;
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemDesc;

  TxtBases = NULL;
  TxtSizes = NULL;
  MemDesc  = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *)MemPolicy;

  Status = GetTxtRegions (&TxtBases, &TxtSizes, &Count);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  for (Index1 = 0; Index1 < Count; Index1++) {
    for (Index2 = 0; Index2 < MemPolicyCount; Index2++) {
      if ((((TxtBases[Index1] <= MemDesc[Index2].BaseAddress) &&
            (TxtBases[Index1] + TxtSizes[Index1] > MemDesc[Index2].BaseAddress))) ||
          ((TxtBases[Index1] < (MemDesc[Index2].BaseAddress + MemDesc[Index2].Size)) &&
           (TxtBases[Index1] + TxtSizes[Index1] >= MemDesc[Index2].BaseAddress + MemDesc[Index2].Size)))
      {
        // Shoot, found an overlap and we are an allow list...
        Status = EFI_SECURITY_VIOLATION;
        goto Done;
      }
    }
  }

Done:
  if (TxtBases != NULL) {
    FreePool (TxtBases);
  }

  if (TxtSizes != NULL) {
    FreePool (TxtSizes);
  }

  return Status;
}

/*
  Helper function to check possible policy level on the MSR block
*/
EFI_STATUS
EFIAPI
VerifyMemPolicy (
  IN  VOID    *MemPolicy,
  IN  UINT32  MemPolicyCount,
  IN  UINT32  AccessAttr,
  OUT UINT32  *Level
  )
{
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemEntries;
  UINTN                                       Index1;
  UINTN                                       Index2;
  EFI_STATUS                                  Status;

  EFI_MEMORY_ATTRIBUTES_TABLE  *MatMap;
  EFI_MEMORY_DESCRIPTOR        *MemoryMap;
  UINTN                        MemoryMapEntryCount;
  UINTN                        DescriptorSize;

  if ((MemPolicy == NULL) || (Level == NULL) || (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) {
    return EFI_INVALID_PARAMETER;
  }

  MemEntries = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *)MemPolicy;

  // The method is very brute force...

  // First set the level to at most 0, failing everything here
  // will not make it below that value
  *Level = 0;

  // Grab the memory map from DXE core and verify the below:
  // 1.1 Do NOT contain any mappings to EfiConventionalMemory (e.g. no OS/VMM owned memory)
  // 1.2 Do NOT contain any mappings to code sections within EfiRuntimeServicesCode
  Status = EfiGetSystemConfigurationTable (&gEfiMemoryAttributesTableGuid, (VOID **)&MatMap);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Get Count
  //
  DescriptorSize      = MatMap->DescriptorSize;
  MemoryMapEntryCount = MatMap->NumberOfEntries;
  MemoryMap           = (VOID *)((UINT8 *)MatMap + sizeof (*MatMap));
  for (Index1 = 0; Index1 < MemoryMapEntryCount; Index1++) {
    switch (MemoryMap->Type) {
      case EfiConventionalMemory:
      case EfiRuntimeServicesCode:
        for (Index2 = 0; Index2 < MemPolicyCount; Index2++) {
          if ((((MemoryMap->PhysicalStart <= MemEntries[Index2].BaseAddress) &&
                (MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE (MemoryMap->NumberOfPages) > MemEntries[Index2].BaseAddress))) ||
              ((MemoryMap->PhysicalStart < (MemEntries[Index2].BaseAddress + MemEntries[Index2].Size)) &&
               (MemoryMap->PhysicalStart + EFI_PAGES_TO_SIZE (MemoryMap->NumberOfPages) >= MemEntries[Index2].BaseAddress + MemEntries[Index2].Size)))
          {
            // Shoot, found an overlap and we are an allow list...
            if ((MemoryMap->Attribute & EFI_MEMORY_XP) == 0) {
              // Check the paging attribute to see if this really is a code page
              goto Done;
            }
          }
        }

        break;
    }

    MemoryMap = NEXT_MEMORY_DESCRIPTOR (MemoryMap, DescriptorSize);
  }

  // 1.3 Do NOT have execute and write permissions for the same page
  for (Index2 = 0; Index2 < MemPolicyCount; Index2++) {
    if ((MemEntries[Index2].MemAttributes & (SECURE_POLICY_RESOURCE_ATTR_WRITE|SECURE_POLICY_RESOURCE_ATTR_EXECUTE)) ==
        (SECURE_POLICY_RESOURCE_ATTR_WRITE|SECURE_POLICY_RESOURCE_ATTR_EXECUTE))
    {
      // Shoot, found a W/EX region and we are an allow list...
      goto Done;
    }
  }

  // So level 10 passed, set it to at least level 10
  *Level = SMM_POLICY_LEVEL_10;

  // Level 20:
  // Write access must be denied to any MMIO or other system registers which allow configuration of any of the system IOMMUs
  Status = VerifyIommuMemoryWithPolicy (MemPolicy, MemPolicyCount, AccessAttr);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "%a Failed to validate memory policy against IOMMU regions - %r\n", __FUNCTION__, Status));
    // This is not an error anymore, since it should at least get level 10 report
    Status = EFI_SUCCESS;
    goto Done;
  }

  // So level 20 passed, set it to at least level 20
  *Level = SMM_POLICY_LEVEL_20;

  if (!StandardSignatureIsAuthenticAMD ()) {
    // Check overlap with TXT regions for Intel processors
    Status = VerifyTxtMemoryWithPolicy (MemPolicy, MemPolicyCount, AccessAttr);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "%a Failed to validate memory policy against TXT regions - %r\n", __FUNCTION__, Status));
      // This is not an error anymore, since it should at least get level 20 report
      Status = EFI_SUCCESS;
      goto Done;
    }
  }

  // At this point, IO will not prevent the measurement level to be the highest
  *Level = MAX_SUPPORTED_LEVEL;

Done:
  return Status;
}
