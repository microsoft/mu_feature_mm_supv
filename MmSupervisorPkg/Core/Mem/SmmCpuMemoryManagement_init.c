/** @file
  Init (MmSupervisorInit) image-region and common-buffer attribute setup.

  Linked only into MmSupervisorInit.  Both routines below diverge from the
  runtime versions in SmmCpuMemoryManagement_core.c:

    * PatchMmSupervisorCoreRegion   - Init also locks down the user-driver
                                      image, walks the discovered-driver list,
                                      and frees per-driver entries (the runtime
                                      driver does this at a different stage).

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
#include <Library/MemoryAllocationLib.h>
#include <Library/ResetSystemLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "Relocate/Relocate.h"
#include "Request/Request.h"

//
// mDiscoveredList lives in our own Dispatcher.c.  mMmUserDriverEntry is now
// declared in the shared Core/MmSupervisorCore.h.
//
extern LIST_ENTRY  mDiscoveredList;

VOID
EFIAPI
PatchMmSupervisorCoreRegion (
  VOID
  )
{
  //
  // Patch MM Supervisor Core
  //
  EFI_STATUS           Status;
  LIST_ENTRY           *Link;
  EFI_MM_DRIVER_ENTRY  *DriverEntry;

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

  // Status = SmmSetMemoryAttributes (
  //            mMmCoreDriverEntry->ImageBuffer,
  //            EFI_PAGES_TO_SIZE (mMmCoreDriverEntry->NumberOfPage),
  //            EFI_MEMORY_SP
  //            );

  FreePool (mMmCoreDriverEntry);
  mMmCoreDriverEntry = NULL;

  DEBUG ((DEBUG_INFO, "%a - User module - %r\n", __func__, Status));
  //
  // The range should have been set to RO/XP based on image record routines
  // this is the last pass that makes sure the entire region is still in
  // supervisor realm.
  //
  Status = SmmSetImagePageAttributes (mMmUserDriverEntry, FALSE);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to set image attribute for MM user %r!!!\n", __func__, Status));
    // We should not continue with this configuration, either hang the system or reboot
    ResetCold ();
    // Should not be here
    CpuDeadLoop ();
  }

  // Status = SmmClearMemoryAttributes (
  //            mMmUserDriverEntry->ImageBuffer,
  //            EFI_PAGES_TO_SIZE (mMmUserDriverEntry->NumberOfPage),
  //            EFI_MEMORY_SP
  //            );

  FreePool (mMmUserDriverEntry);
  mMmUserDriverEntry = NULL;

  // Now handle the rest of discovered MM drivers
  while (!IsListEmpty (&mDiscoveredList)) {
    Link        = mDiscoveredList.ForwardLink;
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);

    DEBUG ((DEBUG_INFO, "  Setting image attributes - %g\n", &DriverEntry->FileName));
    SmmSetImagePageAttributes (DriverEntry, FALSE);

    RemoveEntryList (&DriverEntry->Link);
    FreePool (DriverEntry);
  }

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
