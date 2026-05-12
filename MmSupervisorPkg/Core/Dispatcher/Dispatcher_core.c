/** @file
  Core (MmSupervisorCore) implementation of dispatcher functions that are
  not used by the Init build.

  Provides:
    * The MmDispatcher state machine that drains mScheduledQueue, loads each
      pending driver image, demotes to user mode, and invokes its entry point.
    * MmInsertOnScheduledQueueWhileProcessingBeforeAndAfter (the Before/After
      depex sequencer used by the dispatcher to schedule drivers).
    * MmDriverDispatchHandler / MmDisplayDiscoveredNotDispatched and the
      FindFileNameFromDiscoveredList lookup helper used by Telemetry,
      SmiHandlerProfile, and PagingAudit.
    * MmPreProcessDepex / MmGetDepexSectionAndPreProccess — depex section
      pre-processing.
    * Two helpers exported to the shared Dispatcher.c:
        MmRegisterLoadedImage    — installs the EFI_LOADED_IMAGE_PROTOCOL and
                                   sets image page attributes for a freshly
                                   loaded MM driver.
        ProcessDepexBeforeDispatch — wraps MmGetDepexSectionAndPreProccess so
                                   the shared MmAddToDriverList can call it
                                   without dragging the depex code into Init.

  The Init build provides matching no-op stubs for the two helpers in
  Dispatcher_init.c, plus its own MmInitDriverEntry / MmLoadButNotDispatch
  routines that operate on the same mDiscoveredList list.

  Copyright (c) 2014, Hewlett-Packard Development Company, L.P.
  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"

//
// Globals defined in the shared Dispatcher.c — declared here for use by
// MmDispatcher and MmInsertOnScheduledQueueWhileProcessingBeforeAndAfter.
//
extern LIST_ENTRY  mDiscoveredList;
extern LIST_ENTRY  mScheduledQueue;
extern BOOLEAN     gDispatcherRunning;
extern BOOLEAN     gRequestDispatch;

/**
  Install the EFI_LOADED_IMAGE_PROTOCOL for a freshly loaded MM driver image
  and apply the image's code/data page attributes.

  Called from the shared MmLoadImage immediately after the PE/COFF image has
  been loaded, relocated, and its entry point recorded.  On error, releases
  any partially-allocated resources (image pages and PE/COFF state) before
  returning so the caller does not need to undo this routine's work.

  @param[in,out] DriverEntry    The driver entry tracking the loaded image.
  @param[in,out] ImageContext   PE/COFF context for the loaded image.
  @param[in]     DstBuffer      Physical address of the image's allocated pages
                                (passed in so cleanup can free them on error).
  @param[in]     PageCount      Number of pages backing DstBuffer.

  @retval EFI_SUCCESS           Loaded image protocol installed and page
                                attributes applied.
  @retval other                 Allocation, install, or page-attribute failure.

**/
EFI_STATUS
MmRegisterLoadedImage (
  IN OUT EFI_MM_DRIVER_ENTRY            *DriverEntry,
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT   *ImageContext,
  IN     EFI_PHYSICAL_ADDRESS           DstBuffer,
  IN     UINTN                          PageCount
  )
{
  EFI_STATUS  Status;

  // if (mEfiSystemTable != NULL) {
  // TODO: This is throw away memory but need to use until it is locked down...
  Status = MmAllocateSupervisorPool (
             EfiRuntimeServicesData,
             sizeof (EFI_LOADED_IMAGE_PROTOCOL),
             (VOID **)&DriverEntry->LoadedImage
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate pool for loaded image protocol %r\n", __func__, Status));
    PeCoffLoaderUnloadImage (ImageContext);
    MmFreePages (DstBuffer, PageCount);
    return Status;
  }

  ZeroMem (DriverEntry->LoadedImage, sizeof (EFI_LOADED_IMAGE_PROTOCOL));
  //
  // Fill in the remaining fields of the Loaded Image Protocol instance.
  // Note: ImageBase is an SMRAM address that can not be accessed outside of SMRAM if SMRAM window is closed.
  //
  DriverEntry->LoadedImage->Revision     = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
  DriverEntry->LoadedImage->ParentHandle = NULL;
  DriverEntry->LoadedImage->SystemTable  = mEfiSystemTable;
  DriverEntry->LoadedImage->DeviceHandle = NULL;
  DriverEntry->LoadedImage->FilePath     = NULL;

  DriverEntry->LoadedImage->ImageBase     = (VOID *)(UINTN)DriverEntry->ImageBuffer;
  DriverEntry->LoadedImage->ImageSize     = ImageContext->ImageSize;
  DriverEntry->LoadedImage->ImageCodeType = EfiRuntimeServicesCode;
  DriverEntry->LoadedImage->ImageDataType = EfiRuntimeServicesData;

  //
  // Create a new image handle in the UEFI handle database for the MM Driver
  //
  DriverEntry->ImageHandle = NULL;
  Status                   = gMmCoreMmst.MmInstallProtocolInterface (
                                           &DriverEntry->ImageHandle,
                                           &gEfiLoadedImageProtocolGuid,
                                           EFI_NATIVE_INTERFACE,
                                           DriverEntry->LoadedImage
                                           );
  // }

  //
  // After loading, (hopefully before executing) we apply necessary code/data pages to this image
  //
  Status = SmmSetImagePageAttributes (DriverEntry, FALSE);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to set image attribute for loaded image %r\n", __func__, Status));
    MmFreePages (DstBuffer, PageCount);
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Preprocess dependency expression and update DriverEntry to reflect the
  state of  Before and After dependencies. If DriverEntry->Before
  or DriverEntry->After is set it will never be cleared.

  @param  DriverEntry           DriverEntry element to update .

  @retval EFI_SUCCESS           It always works.

**/
EFI_STATUS
MmPreProcessDepex (
  IN EFI_MM_DRIVER_ENTRY  *DriverEntry
  )
{
  UINT8  *Iterator;

  Iterator               = DriverEntry->Depex;
  DriverEntry->Dependent = TRUE;

  if (*Iterator == EFI_DEP_BEFORE) {
    DriverEntry->Before = TRUE;
  } else if (*Iterator == EFI_DEP_AFTER) {
    DriverEntry->After = TRUE;
  }

  if (DriverEntry->Before || DriverEntry->After) {
    CopyMem (&DriverEntry->BeforeAfterGuid, Iterator + 1, sizeof (EFI_GUID));
  }

  return EFI_SUCCESS;
}

/**
  Read Depex and pre-process the Depex for Before and After. If Section Extraction
  protocol returns an error via ReadSection defer the reading of the Depex.

  @param  DriverEntry           Driver to work on.

  @retval EFI_SUCCESS           Depex read and preprossesed
  @retval EFI_PROTOCOL_ERROR    The section extraction protocol returned an error
                                and  Depex reading needs to be retried.
  @retval Error                 DEPEX not found.

**/
EFI_STATUS
MmGetDepexSectionAndPreProccess (
  IN EFI_MM_DRIVER_ENTRY  *DriverEntry
  )
{
  EFI_STATUS  Status;

  //
  // Data already read
  //
  if (DriverEntry->Depex == NULL) {
    Status = EFI_NOT_FOUND;
  } else {
    Status = EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    if (Status == EFI_PROTOCOL_ERROR) {
      //
      // The section extraction protocol failed so set protocol error flag
      //
      DriverEntry->DepexProtocolError = TRUE;
    } else {
      //
      // If no Depex assume depend on all architectural protocols
      //
      DriverEntry->Depex              = NULL;
      DriverEntry->Dependent          = TRUE;
      DriverEntry->DepexProtocolError = FALSE;
    }
  } else {
    //
    // Set Before and After state information based on Depex
    // Driver will be put in Dependent state
    //
    MmPreProcessDepex (DriverEntry);
    DriverEntry->DepexProtocolError = FALSE;
  }

  return Status;
}

/**
  Hook for the shared MmAddToDriverList: kick off depex pre-processing as
  soon as a driver is added to mDiscoveredList.  Init does not run any depex
  evaluation, so it provides a no-op stub of this hook.

  @param[in,out] DriverEntry  The driver just added to mDiscoveredList.
**/
VOID
ProcessDepexBeforeDispatch (
  IN EFI_MM_DRIVER_ENTRY  *DriverEntry
  )
{
  MmGetDepexSectionAndPreProccess (DriverEntry);
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
MmDispatcher (
  VOID
  )
{
  EFI_STATUS                    Status;
  LIST_ENTRY                    *Link;
  EFI_MM_DRIVER_ENTRY           *DriverEntry;
  BOOLEAN                       ReadyToRun;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

  DEBUG ((DEBUG_INFO, "MmDispatcher\n"));

  if (!gRequestDispatch) {
    DEBUG ((DEBUG_INFO, "  !gRequestDispatch\n"));
    return EFI_NOT_FOUND;
  }

  if (gDispatcherRunning) {
    DEBUG ((DEBUG_INFO, "  gDispatcherRunning\n"));
    //
    // If the dispatcher is running don't let it be restarted.
    //
    return EFI_ALREADY_STARTED;
  }

  gDispatcherRunning = TRUE;

  do {
    //
    // Drain the Scheduled Queue
    //
    DEBUG ((DEBUG_INFO, "  Drain the Scheduled Queue\n"));
    while (!IsListEmpty (&mScheduledQueue)) {
      DriverEntry = CR (
                      mScheduledQueue.ForwardLink,
                      EFI_MM_DRIVER_ENTRY,
                      ScheduledLink,
                      EFI_MM_DRIVER_ENTRY_SIGNATURE
                      );
      DEBUG ((DEBUG_DISPATCH, "  DriverEntry (Scheduled) - %g\n", &DriverEntry->FileName));

      //
      // Load the MM Driver image into memory. If the Driver was transitioned from
      // Untrusted to Scheduled it would have already been loaded so we may need to
      // skip the LoadImage
      //
      if (DriverEntry->ImageHandle == NULL) {
        Status = MmLoadImage (DriverEntry, &ImageContext);

        //
        // Update the driver state to reflect that it's been loaded
        //
        if (EFI_ERROR (Status)) {
          //
          // The MM Driver could not be loaded, and do not attempt to load or start it again.
          // Take driver from Scheduled to Initialized.
          //
          DriverEntry->Initialized = TRUE;
          DriverEntry->Scheduled   = FALSE;
          RemoveEntryList (&DriverEntry->ScheduledLink);

          //
          // If it's an error don't try the StartImage
          //
          continue;
        }
      }

      DriverEntry->Scheduled   = FALSE;
      DriverEntry->Initialized = TRUE;
      RemoveEntryList (&DriverEntry->ScheduledLink);

      //
      // For each MM driver, pass NULL as ImageHandle
      //
      DEBUG ((DEBUG_INFO, "StartImage - 0x%x (Standalone Mode)\n", DriverEntry->ImageEntryPoint));
      Status = InvokeDemotedDriverEntryPoint (
                 (MM_IMAGE_ENTRY_POINT *)DriverEntry->ImageEntryPoint,
                 DriverEntry->ImageHandle,
                 gMmUserMmst
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_INFO, "StartImage Status - %r\n", Status));

        // we need to unload the image before we free the pages. On some architectures (e.g. x86), this is a no-op, but
        // on others (e.g. AARCH64) this will remove the image memory protections set on the region so that when the
        // memory is freed, it has the default attributes set and can be used generically
        PeCoffLoaderUnloadImage (&ImageContext);
        MmFreePages (DriverEntry->ImageBuffer, DriverEntry->NumberOfPage);
        Status = gMmCoreMmst.MmUninstallProtocolInterface (DriverEntry->ImageHandle, &gEfiLoadedImageProtocolGuid, DriverEntry->LoadedImage);
        if (!EFI_ERROR (Status)) {
          MmFreeSupervisorPool (DriverEntry->LoadedImage);
          MmFreeSupervisorPool (DriverEntry->Depex);
        }
      }
    }

    //
    // Search DriverList for items to place on Scheduled Queue
    //
    DEBUG ((DEBUG_INFO, "  Search DriverList for items to place on Scheduled Queue\n"));
    ReadyToRun = FALSE;
    for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
      DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
      DEBUG ((DEBUG_DISPATCH, "  DriverEntry (Discovered) - %g\n", &DriverEntry->FileName));

      if (DriverEntry->DepexProtocolError) {
        //
        // If Section Extraction Protocol did not let the Depex be read before retry the read
        //
        Status = MmGetDepexSectionAndPreProccess (DriverEntry);
      }

      if (DriverEntry->Dependent) {
        if (MmIsSchedulable (DriverEntry)) {
          MmInsertOnScheduledQueueWhileProcessingBeforeAndAfter (DriverEntry);
          ReadyToRun = TRUE;
        }
      }
    }
  } while (ReadyToRun);

  //
  // If there is no more MM driver to dispatch, stop the dispatch request
  //
  DEBUG ((DEBUG_DISPATCH, "  no more MM driver to dispatch, stop the dispatch request\n"));
  gRequestDispatch = FALSE;
  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    DEBUG ((DEBUG_DISPATCH, "  DriverEntry (Discovered) - %g\n", &DriverEntry->FileName));

    if (!DriverEntry->Initialized) {
      //
      // We have MM driver pending to dispatch
      //
      gRequestDispatch = TRUE;
      break;
    }
  }

  gDispatcherRunning = FALSE;

  return EFI_SUCCESS;
}

/**
  Insert InsertedDriverEntry onto the mScheduledQueue. To do this you
  must add any driver with a before dependency on InsertedDriverEntry first.
  You do this by recursively calling this routine. After all the Befores are
  processed you can add InsertedDriverEntry to the mScheduledQueue.
  Then you can add any driver with an After dependency on InsertedDriverEntry
  by recursively calling this routine.

  @param  InsertedDriverEntry   The driver to insert on the ScheduledLink Queue

**/
VOID
MmInsertOnScheduledQueueWhileProcessingBeforeAndAfter (
  IN  EFI_MM_DRIVER_ENTRY  *InsertedDriverEntry
  )
{
  LIST_ENTRY           *Link;
  EFI_MM_DRIVER_ENTRY  *DriverEntry;

  //
  // Process Before Dependency
  //
  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    if (DriverEntry->Before && DriverEntry->Dependent && (DriverEntry != InsertedDriverEntry)) {
      DEBUG ((DEBUG_DISPATCH, "Evaluate MM DEPEX for FFS(%g)\n", &DriverEntry->FileName));
      DEBUG ((DEBUG_DISPATCH, "  BEFORE FFS(%g) = ", &DriverEntry->BeforeAfterGuid));
      if (CompareGuid (&InsertedDriverEntry->FileName, &DriverEntry->BeforeAfterGuid)) {
        //
        // Recursively process BEFORE
        //
        DEBUG ((DEBUG_DISPATCH, "TRUE\n  END\n  RESULT = TRUE\n"));
        MmInsertOnScheduledQueueWhileProcessingBeforeAndAfter (DriverEntry);
      } else {
        DEBUG ((DEBUG_DISPATCH, "FALSE\n  END\n  RESULT = FALSE\n"));
      }
    }
  }

  //
  // Convert driver from Dependent to Scheduled state
  //

  InsertedDriverEntry->Dependent = FALSE;
  InsertedDriverEntry->Scheduled = TRUE;
  InsertTailList (&mScheduledQueue, &InsertedDriverEntry->ScheduledLink);

  //
  // Process After Dependency
  //
  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    if (DriverEntry->After && DriverEntry->Dependent && (DriverEntry != InsertedDriverEntry)) {
      DEBUG ((DEBUG_DISPATCH, "Evaluate MM DEPEX for FFS(%g)\n", &DriverEntry->FileName));
      DEBUG ((DEBUG_DISPATCH, "  AFTER FFS(%g) = ", &DriverEntry->BeforeAfterGuid));
      if (CompareGuid (&InsertedDriverEntry->FileName, &DriverEntry->BeforeAfterGuid)) {
        //
        // Recursively process AFTER
        //
        DEBUG ((DEBUG_DISPATCH, "TRUE\n  END\n  RESULT = TRUE\n"));
        MmInsertOnScheduledQueueWhileProcessingBeforeAndAfter (DriverEntry);
      } else {
        DEBUG ((DEBUG_DISPATCH, "FALSE\n  END\n  RESULT = FALSE\n"));
      }
    }
  }
}

/**
  This function is the main entry point for an SMM handler dispatch
  or communicate-based callback.

  Event notification that is fired every time a FV dispatch protocol is added.
  More than one protocol may have been added when this event is fired, so you
  must loop on SmmLocateHandle () to see how many protocols were added and
  do the following to each FV:
  If the Fv has already been processed, skip it. If the Fv has not been
  processed then mark it as being processed, as we are about to process it.
  Read the Fv and add any driver in the Fv to the mDiscoveredList.The
  mDiscoveredList is never freed and contains variables that define
  the other states the SMM driver transitions to..
  While you are at it read the A Priori file into memory.
  Place drivers in the A Priori list onto the mScheduledQueue.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmDriverDispatchHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS            Status;
  EFI_PEI_HOB_POINTERS  Hob;

  PERF_CALLBACK_BEGIN (&gMmSupervisorDriverDispatchGuid);

  DEBUG ((DEBUG_INFO, "%a Entry\n", __func__));

  Hob.Raw = GetHobList ();
  if (Hob.Raw == NULL) {
    Status = EFI_NOT_FOUND;
    goto PrepareCommonBuffer;
  }

  //
  // Execute the SMM Dispatcher on any newly discovered FVs and previously
  // discovered SMM drivers that have been discovered but not dispatched.
  //
  Status = MmDispatcher ();

PrepareCommonBuffer:
  //
  // Check to see if CommBuffer and CommBufferSize are valid
  //
  if ((CommBuffer != NULL) && (CommBufferSize != NULL)) {
    if (*CommBufferSize >= sizeof (EFI_STATUS)) {
      //
      // Set the status of MmDispatcher to CommBuffer
      //
      *(EFI_STATUS *)CommBuffer = Status;
    }
  }

  DEBUG ((DEBUG_INFO, "%a Exit\n", __func__));

  PERF_CALLBACK_END (&gMmSupervisorDriverDispatchGuid);

  return EFI_SUCCESS;
}

/**
  Traverse the discovered list for any drivers that were discovered but not loaded
  because the dependency expressions evaluated to false.

**/
VOID
MmDisplayDiscoveredNotDispatched (
  VOID
  )
{
  LIST_ENTRY           *Link;
  EFI_MM_DRIVER_ENTRY  *DriverEntry;

  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    if (DriverEntry->Dependent) {
      DEBUG ((DEBUG_LOAD, "MM Driver %g was discovered but not loaded!!\n", &DriverEntry->FileName));
    }
  }
}

/**
  Helper function that will look up the driver GUID from discovered list using loaded image address.

  @param  DriverAddr      The address of loaded image that is of interest.
  @param  Guid            The pointer to hold returned driver GUID.

  @return EFI_SUCCESS             FileName is found successfully.
  @return EFI_INVALID_PARAMETER   Incoming Guid point is null.
  @return EFI_NOT_FOUND           FileName is not found from internal list.

**/
EFI_STATUS
FindFileNameFromDiscoveredList (
  IN  EFI_PHYSICAL_ADDRESS  DriverAddress,
  OUT EFI_GUID              *Guid
  )
{
  LIST_ENTRY           *Link;
  EFI_MM_DRIVER_ENTRY  *DriverEntry;
  EFI_STATUS           Status;

  if (Guid == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  Status = EFI_NOT_FOUND;

  // First check if this is the core itself
  if ((EFI_PHYSICAL_ADDRESS)(UINTN)mMmCoreDriverEntry->LoadedImage->ImageBase == DriverAddress) {
    CopyMem (Guid, &gEfiCallerIdGuid, sizeof (EFI_GUID));
    Status = EFI_SUCCESS;
    goto Exit;
  }

  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    if ((DriverEntry->LoadedImage != NULL) &&
        ((UINTN)DriverEntry->LoadedImage->ImageBase == DriverAddress))
    {
      CopyMem (Guid, &DriverEntry->FileName, sizeof (EFI_GUID));
      Status = EFI_SUCCESS;
      break;
    }
  }

Exit:
  return Status;
}
