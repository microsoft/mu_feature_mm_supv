/** @file
  Core (MmSupervisorCore) image-region and common-buffer attribute setup.

  Linked only into the runtime MmSupervisorCore driver:

    * PatchMmSupervisorCoreRegion   - Final pass after image record routines
                                      that locks down the supervisor core image
                                      and the firmware policy region.  Init
                                      additionally needs to walk a discovered-
                                      driver list and free per-driver entries;
                                      see SmmCpuMemoryManagement_init.c.

    * SetCommonBufferRegionAttribute
                                    - Marks the supervisor / user shared
                                      communicate buffers as accessible from
                                      MM, using ProcessUnblockPages.  Init
                                      uses SmmSetMemoryAttributes for the
                                      same effect since it does not yet have
                                      the unblock dispatcher up; see
                                      SmmCpuMemoryManagement_init.c.

  Copyright (c) 2016 - 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>
#include <Guid/MmSupvUnblockRegion.h>
#include <Guid/MmSupervisorRequestData.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/ResetSystemLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "Relocate/Relocate.h"
#include "Request/Request.h"

VOID
EFIAPI
PatchMmSupervisorCoreRegion (
  VOID
  )
{
  //
  // Patch MM Supervisor Core
  //
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "%a - Enter\n", __func__));

  //
  // The range should have been set to RO/XP based on image record routines
  // this is the last pass that makes sure the entire region is still in
  // supervisor realm.
  //
  Status = SmmSetImagePageAttributes (mMmCoreDriverEntry, TRUE);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to set image attribute for MM core %r!!!\n", __func__, Status));
    // We should not continue with this configuration, either hang the system or reboot
    ResetCold ();
    // Should not be here
    CpuDeadLoop ();
  }

  Status = SmmSetMemoryAttributes (
             mMmCoreDriverEntry->ImageBuffer,
             EFI_PAGES_TO_SIZE (mMmCoreDriverEntry->NumberOfPage),
             EFI_MEMORY_SP
             );

  if (FirmwarePolicy == NULL) {
    Status = EFI_SECURITY_VIOLATION;
    ASSERT (FALSE);
    return;
  }

  //
  // Mark firmware policy pages as supervisor read only
  // EFI_MEMORY_XP should be given as they are data pages
  //
  Status = SmmSetMemoryAttributes (
             (EFI_PHYSICAL_ADDRESS)(UINTN)FirmwarePolicy,
             (FirmwarePolicy->Size + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE -1),
             EFI_MEMORY_RO | EFI_MEMORY_SP
             );

  DEBUG ((DEBUG_INFO, "%a - Exit - %r\n", __func__, Status));
}

/*
Helper function to mark common buffer range as accessible from inside MM
*/
EFI_STATUS
EFIAPI
SetCommonBufferRegionAttribute (
  VOID
  )
{
  EFI_STATUS                           Status;
  UINTN                                Index;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  UnblockRegionParams;

  ZeroMem (&UnblockRegionParams, sizeof (UnblockRegionParams));
  CopyMem (&UnblockRegionParams.IdentifierGuid, &gEfiCallerIdGuid, sizeof (EFI_GUID));

  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    // For the supervisor buffer communication buffer space
    if (mMmSupervisorAccessBuffer[Index].PhysicalStart == 0) {
      // For the supervisor communication buffer space
      ASSERT (mMmSupervisorAccessBuffer[Index].PhysicalStart != 0);
      Status = EFI_NOT_AVAILABLE_YET;
      goto Cleanup;
    } else {
      // Sanity check on the comm buffers and the mailbox data region
      if (InternalIsBufferOverlapped (
            (UINT8 *)mMmCommMailboxBufferStatus,
            sizeof (*mMmCommMailboxBufferStatus),
            (UINT8 *)(UINTN)mMmSupervisorAccessBuffer[Index].PhysicalStart,
            EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages)
            ))
      {
        DEBUG ((DEBUG_ERROR, "%a - Communicate buffer overlaps with mailbox buffer with IPL!\n", __func__));
        ASSERT_EFI_ERROR (Status);
        Status = EFI_SECURITY_VIOLATION;
        goto Cleanup;
      }

      // Remove RX set above
      CopyMem (&UnblockRegionParams.MemoryDescriptor, &mMmSupervisorAccessBuffer[Index], sizeof (EFI_MEMORY_DESCRIPTOR));
      Status = ProcessUnblockPages (&UnblockRegionParams);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __func__, Status));
        ASSERT (FALSE);
        goto Cleanup;
      }
    }
  }

  // For the supervisor core private data that is shared with the IPL
  // TODO: really do not want this region to be accessible by the IPL, but what
  // is the difference if you will need it for common buffer anyway?
  // Remove RX set above
  ZeroMem (&UnblockRegionParams.MemoryDescriptor, sizeof (EFI_MEMORY_DESCRIPTOR));
  UnblockRegionParams.MemoryDescriptor.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommMailboxBufferStatus;
  UnblockRegionParams.MemoryDescriptor.NumberOfPages = EFI_SIZE_TO_PAGES ((sizeof (mMmCommMailboxBufferStatus) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK));
  UnblockRegionParams.MemoryDescriptor.Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  UnblockRegionParams.MemoryDescriptor.Type          = EfiRuntimeServicesData;
  Status                                             = ProcessUnblockPages (&UnblockRegionParams);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __func__, Status));
    ASSERT (FALSE);
  }

Cleanup:
  return Status;
}
