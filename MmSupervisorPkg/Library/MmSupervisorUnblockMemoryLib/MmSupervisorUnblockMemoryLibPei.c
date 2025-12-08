/** @file
  MM Unblock Page Library Implementation for PEI phase.

  This library provides an abstraction layer of requesting certain page access to be unblocked
  by MM supervisor in PEI phase.

  Note: Requests through this API after MM PEI has launched will not take effect and/or cause asserts.

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MmUnblockRegion.h>
#include <Ppi/MmSupervisorCommunication.h>

#include <Library/HobLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeiServicesLib.h>

/**
  This API provides a way to unblock certain data pages to be accessible inside MM environment.

  @param  UnblockAddress          The address of buffer caller requests to unblock, the address
                                  has to be page aligned.
  @param  NumberOfPages           The number of pages requested to be unblocked from MM
                                  environment.

  @return EFI_SUCCESS             The request goes through successfully.
  @return EFI_NOT_AVAILABLE_YET   The requested functionality is not produced yet.
  @return EFI_UNSUPPORTED         The requested functionality is not supported on current platform.
  @return EFI_SECURITY_VIOLATION  The requested address failed to pass security check for
                                  unblocking.
  @return EFI_INVALID_PARAMETER   Input address either NULL pointer or not page aligned.
  @return EFI_ACCESS_DENIED       The request is rejected due to system has passed certain boot
                                  phase.

**/
EFI_STATUS
EFIAPI
MmUnblockMemoryRequest (
  IN EFI_PHYSICAL_ADDRESS  UnblockAddress,
  IN UINT64                NumberOfPages
  )
{
  EFI_STATUS                           Status;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *MmSupvUnblockMemoryHob;
  MM_SUPERVISOR_COMMUNICATION_PPI      *MmCommunicatePpi;

  Status = PeiServicesLocatePpi (
             &gPeiMmSupervisorCommunicationPpiGuid,
             0,
             NULL,
             (VOID **)&MmCommunicatePpi
             );
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Communicate PPI is installed, request too late for PEI phase\n", __FUNCTION__));
    ASSERT (FALSE);
    Status = EFI_ACCESS_DENIED;
    goto Done;
  }

  // Build the GUID'd HOB for MmCore
  MmSupvUnblockMemoryHob = BuildGuidHob (&gMmSupvUnblockRegionHobGuid, sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS));

  if (MmSupvUnblockMemoryHob == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate hob for unblocked data parameter!!\n", __FUNCTION__));
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  ZeroMem (MmSupvUnblockMemoryHob, sizeof (MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS));
  CopyMem (&MmSupvUnblockMemoryHob->IdentifierGuid, &gEfiCallerIdGuid, sizeof (EFI_GUID));
  MmSupvUnblockMemoryHob->MemoryDescriptor.PhysicalStart = UnblockAddress;
  MmSupvUnblockMemoryHob->MemoryDescriptor.NumberOfPages = NumberOfPages;

  Status = EFI_SUCCESS;

Done:
  return Status;
}
