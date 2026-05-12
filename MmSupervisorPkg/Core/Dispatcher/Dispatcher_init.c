/** @file
  Init (MmSupervisorInit) implementation of dispatcher functions.

  Provides:
    * MmInitDriverEntry — allocates and initializes an EFI_MM_DRIVER_ENTRY
      from raw FFS data, used by MmSupervisorInit.c during early discovery.
    * MmLoadButNotDispatch — single pre-runtime pass that loads every driver
      on mDiscoveredList without scheduling or invoking entry points.  Used
      by MmSupervisorInit.c when handing the discovered images over to the
      runtime supervisor.
    * MmRegisterLoadedImage — no-op stub matching the helper that the shared
      MmLoadImage calls after each image is loaded.  Init does not install
      the EFI_LOADED_IMAGE_PROTOCOL or apply image page attributes, so the
      stub simply returns EFI_SUCCESS.
    * ProcessDepexBeforeDispatch — no-op stub matching the depex hook that
      shared MmAddToDriverList invokes after appending a discovered driver.
      Init does not run depex evaluation.

  See Dispatcher_core.c for the runtime supervisor implementations of the
  two helper hooks.

  Copyright (c) 2014, Hewlett-Packard Development Company, L.P.
  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/PanicLib.h>

#include "MmSupervisorCore.h"

//
// Defined in shared Dispatcher.c.
//
extern LIST_ENTRY  mDiscoveredList;

EFI_MM_DRIVER_ENTRY *
MmInitDriverEntry (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader,
  IN VOID                        *Pe32Data,
  IN UINTN                       Pe32DataSize,
  IN VOID                        *Depex,
  IN UINTN                       DepexSize,
  IN EFI_GUID                    *DriverName
  )
{
  EFI_MM_DRIVER_ENTRY  *DriverEntry;

  DEBUG ((DEBUG_INFO, "%a - %g (0x%08x)\n", __func__, DriverName, Pe32Data));

  //
  // Create the Driver Entry for the list. ZeroPool initializes lots of variables to
  // NULL or FALSE.
  //
  DriverEntry = AllocateZeroPool (sizeof (EFI_MM_DRIVER_ENTRY));
  ASSERT (DriverEntry != NULL);

  DriverEntry->Signature = EFI_MM_DRIVER_ENTRY_SIGNATURE;
  CopyGuid (&DriverEntry->FileName, DriverName);
  DriverEntry->FwVolHeader  = FwVolHeader;
  DriverEntry->Pe32Data     = Pe32Data;
  DriverEntry->Pe32DataSize = Pe32DataSize;
  DriverEntry->DepexSize    = DepexSize;

  if (Depex != NULL) {
    DriverEntry->Depex = AllocateCopyPool (DepexSize, Depex);
    ASSERT (DriverEntry->Depex != NULL);
  } else {
    DriverEntry->Depex = NULL;
  }

  return DriverEntry;
}

/**
  This is the main Dispatcher for MM and it exits when there are no more
  drivers to run. Drain the mScheduledQueue and load and start a PE
  image for each driver. Search the mDiscoveredList to see if any driver can
  be placed on the mScheduledQueue. If no drivers are placed on the
  mScheduledQueue exit the function.

  @retval EFI_SUCCESS           All of the MM Drivers that could be dispatched
                                have been run and the MM Entry Point has been
                                registered.
  @retval EFI_NOT_READY         The MM Driver that registered the MM Entry Point
                                was just dispatched.
  @retval EFI_NOT_FOUND         There are no MM Drivers available to be dispatched.
  @retval EFI_ALREADY_STARTED   The MM Dispatcher is already running

**/
EFI_STATUS
MmLoadButNotDispatch (
  VOID
  )
{
  EFI_STATUS                    Status;
  LIST_ENTRY                    *Link;
  EFI_MM_DRIVER_ENTRY           *DriverEntry;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

  DEBUG ((DEBUG_INFO, "%a\n", __func__));

  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    DEBUG ((DEBUG_DISPATCH, "  DriverEntry (Discovered) - %g\n", &DriverEntry->FileName));

    ZeroMem (&ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));

    Status = MmLoadImage (DriverEntry, &ImageContext);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a MmLoadImage failed for %g: %r\n", __func__, &DriverEntry->FileName, Status));
      PANIC ("Failed to load MM driver image");
    }
  }

  return EFI_SUCCESS;
}

/**
  No-op stub: Init does not install the EFI_LOADED_IMAGE_PROTOCOL or apply
  image page attributes for loaded MM drivers.  See Dispatcher_core.c for
  the runtime implementation.
**/
EFI_STATUS
MmRegisterLoadedImage (
  IN OUT EFI_MM_DRIVER_ENTRY            *DriverEntry,
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT   *ImageContext,
  IN     EFI_PHYSICAL_ADDRESS           DstBuffer,
  IN     UINTN                          PageCount
  )
{
  return EFI_SUCCESS;
}

/**
  No-op stub: Init does not run depex evaluation when a driver is added to
  mDiscoveredList.  See Dispatcher_core.c for the runtime hook.
**/
VOID
ProcessDepexBeforeDispatch (
  IN EFI_MM_DRIVER_ENTRY  *DriverEntry
  )
{
}
