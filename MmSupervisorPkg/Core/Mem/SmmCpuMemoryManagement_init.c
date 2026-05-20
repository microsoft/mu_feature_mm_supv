/** @file
  Init (MmSupervisorInit) image-region and common-buffer attribute setup.

  Linked only into MmSupervisorInit.  Both routines below diverge from the
  runtime versions in SmmCpuMemoryManagement_core.c:

    * PatchMmSupervisorCoreRegion   - Init also locks down the user-driver
                                      image, walks the discovered-driver list,
                                      and frees per-driver entries (the runtime
                                      driver does this at a different stage).

    * SetCommonBufferRegionAttribute
                                    - Init's unblock dispatcher is not online
                                      yet, so user buffers and the mailbox
                                      status page get marked via
                                      SmmSetMemoryAttributes(SP) directly
                                      instead of via ProcessUnblockPages.

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
            (UINT8 *)mMmCommSupvMailboxBufferStatus,
            sizeof (*mMmCommSupvMailboxBufferStatus),
            (UINT8 *)(UINTN)mMmSupervisorAccessBuffer[Index].PhysicalStart,
            EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages)
            ))
      {
        DEBUG ((DEBUG_ERROR, "%a - Communicate buffer overlaps with supervisor mailbox buffer with IPL!\n", __func__));
        Status = EFI_SECURITY_VIOLATION;
        ASSERT_EFI_ERROR (Status);
        goto Cleanup;
      } else if (InternalIsBufferOverlapped (
                   (UINT8 *)mMmCommUserMailboxBufferStatus,
                   sizeof (*mMmCommUserMailboxBufferStatus),
                   (UINT8 *)(UINTN)mMmSupervisorAccessBuffer[Index].PhysicalStart,
                   EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages)
                   ))
      {
        DEBUG ((DEBUG_ERROR, "%a - Communicate buffer overlaps with user mailbox buffer with IPL!\n", __func__));
        Status = EFI_SECURITY_VIOLATION;
        ASSERT_EFI_ERROR (Status);
        goto Cleanup;
      }

      if (Index == MM_SUPERVISOR_BUFFER_T) {
        DEBUG ((DEBUG_INFO, "%a - Marking Supervisor common buffer as accessible to SMM, Start(0x%0lx) Length(0x%0lx)\n", __func__, mMmSupervisorAccessBuffer[Index].PhysicalStart, EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages)));
        // Remove RX set above
        CopyMem (&UnblockRegionParams.MemoryDescriptor, &mMmSupervisorAccessBuffer[Index], sizeof (EFI_MEMORY_DESCRIPTOR));
        Status = ProcessUnblockPages (&UnblockRegionParams);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __func__, Status));
          ASSERT (FALSE);
          goto Cleanup;
        }
      } else {
        DEBUG ((DEBUG_INFO, "%a - Marking Supervisor access buffer index %d as accessible to SMM, Start(0x%0lx) Length(0x%0lx)\n", __func__, Index, mMmSupervisorAccessBuffer[Index].PhysicalStart, EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages)));
        // For user comm buffer, it should be unblocked just like other unblocked regions, and we will just add SP to it.
        Status = SmmSetMemoryAttributes (
                   mMmSupervisorAccessBuffer[Index].PhysicalStart,
                   EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[Index].NumberOfPages),
                   EFI_MEMORY_SP
                   );
      }
    }
  }

  // For the supervisor core private data that is shared with the IPL
  // TODO: really do not want this region to be accessible by the IPL, but what
  // is the difference if you will need it for common buffer anyway?
  DEBUG ((DEBUG_INFO, "%a - Marking Supervisor mailbox buffer as accessible to SMM, Start(0x%0lx) Length(0x%0lx)\n", __func__, (UINTN)mMmCommSupvMailboxBufferStatus, sizeof (*mMmCommSupvMailboxBufferStatus)));
  // For user comm buffer, it should be unblocked just like other unblocked regions, and we will just add SP to it.
  Status = SmmSetMemoryAttributes (
             (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommSupvMailboxBufferStatus,
             (sizeof (mMmCommSupvMailboxBufferStatus) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK),
             EFI_MEMORY_SP
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to mark Supervisor common buffer as unblocked - %r\n", __func__, Status));
    ASSERT (FALSE);
  }

  // For the user status buffer that is shared with the non-MM world
  DEBUG ((DEBUG_INFO, "%a - Marking User mailbox buffer as accessible to SMM, Start(0x%0lx) Length(0x%0lx)\n", __func__, (UINTN)mMmCommUserMailboxBufferStatus, sizeof (*mMmCommUserMailboxBufferStatus)));
  // For user comm buffer, it should be unblocked just like other unblocked regions, and we will just add SP to it.
  Status = SmmSetMemoryAttributes (
             (EFI_PHYSICAL_ADDRESS)(UINTN)mMmCommUserMailboxBufferStatus,
             (sizeof (mMmCommUserMailboxBufferStatus) + EFI_PAGE_MASK) & ~(EFI_PAGE_MASK),
             EFI_MEMORY_SP
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to mark User common buffer as unblocked - %r\n", __func__, Status));
    ASSERT (FALSE);
  }

Cleanup:
  return Status;
}
