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
