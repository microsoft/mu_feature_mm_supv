/** @file
  MM Driver Dispatcher.

  Step #1 - When a FV protocol is added to the system every driver in the FV
            is added to the mDiscoveredList. The Before, and After Depex are
            pre-processed as drivers are added to the mDiscoveredList. If an Apriori
            file exists in the FV those drivers are added to the
            mScheduledQueue. The mFwVolList is used to make sure a
            FV is only processed once.

  Step #2 - Dispatch. Remove driver from the mScheduledQueue and load and
            start it. After mScheduledQueue is drained check the
            mDiscoveredList to see if any item has a Depex that is ready to
            be placed on the mScheduledQueue.

  Step #3 - Adding to the mScheduledQueue requires that you process Before
            and After dependencies. This is done recursively as the call to add
            to the mScheduledQueue checks for Before and recursively adds
            all Befores. It then adds the item that was passed in and then
            processess the After dependencies by recursively calling the routine.

  Dispatcher Rules:
  The rules for the dispatcher are similar to the DXE dispatcher.

  The rules for DXE dispatcher are in chapter 10 of the DXE CIS. Figure 10-3
  is the state diagram for the DXE dispatcher

  Depex - Dependency Expresion.

  Copyright (c) 2014, Hewlett-Packard Development Company, L.P.
  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"

//
// Function Prototypes
//

EFI_STATUS
MmCoreFfsFindMmDriver (
  IN  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  );

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
  );

//
// The Driver List contains one copy of every driver that has been discovered.
// Items are never removed from the driver list. List of EFI_MM_DRIVER_ENTRY
//
LIST_ENTRY  mDiscoveredList = INITIALIZE_LIST_HEAD_VARIABLE (mDiscoveredList);

//
// Queue of drivers that are ready to dispatch. This queue is a subset of the
// mDiscoveredList.list of EFI_MM_DRIVER_ENTRY.
//
LIST_ENTRY  mScheduledQueue = INITIALIZE_LIST_HEAD_VARIABLE (mScheduledQueue);

//
// List of firmware volume headers whose containing firmware volumes have been
// parsed and added to the mFwDriverList.
//
LIST_ENTRY  mFwVolList = INITIALIZE_LIST_HEAD_VARIABLE (mFwVolList);

//
// Flag for the MM Dispacher.  TRUE if dispatcher is executing.
//
BOOLEAN  gDispatcherRunning = FALSE;

//
// Flag for the MM Dispacher.  TRUE if there is one or more MM drivers ready to be dispatched
//
BOOLEAN  gRequestDispatch = FALSE;

/**
  Loads an EFI image into SMRAM.

  @param  DriverEntry             EFI_MM_DRIVER_ENTRY instance
  @param  ImageContext            Allocated ImageContext to be filled out by this function

  @return EFI_STATUS

**/
EFI_STATUS
EFIAPI
MmLoadImage (
  IN OUT EFI_MM_DRIVER_ENTRY           *DriverEntry,
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  UINTN                 PageCount;
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  DstBuffer;

  DEBUG ((DEBUG_INFO, "MmLoadImage - %g\n", &DriverEntry->FileName));

  if (ImageContext == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_SUCCESS;

  //
  // Initialize ImageContext
  //
  ImageContext->Handle    = DriverEntry->Pe32Data;
  ImageContext->ImageRead = PeCoffLoaderImageReadFromMemory;

  //
  // Get information about the image being loaded
  //
  Status = PeCoffLoaderGetImageInfo (ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to read Pe/Coff loader image info %r\n", __FUNCTION__, Status));
    return Status;
  }

  PageCount = (UINTN)EFI_SIZE_TO_PAGES ((UINTN)ImageContext->ImageSize + ImageContext->SectionAlignment);
  DstBuffer = (UINTN)(-1);

  // Note that the buffer will be protected after analyzing the PE/Coff data.
  Status = MmAllocatePages (
             AllocateMaxAddress,
             EfiRuntimeServicesCode,
             PageCount,
             &DstBuffer
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate 0x%x pages for loading image %r\n", __FUNCTION__, PageCount, Status));
    return Status;
  }

  ImageContext->ImageAddress = (EFI_PHYSICAL_ADDRESS)DstBuffer;

  //
  // Align buffer on section boundary
  //
  ImageContext->ImageAddress += ImageContext->SectionAlignment - 1;
  ImageContext->ImageAddress &= ~((EFI_PHYSICAL_ADDRESS)(ImageContext->SectionAlignment - 1));

  //
  // Load the image to our new buffer
  //
  Status = PeCoffLoaderLoadImage (ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to load image into our allocated buffer %r\n", __FUNCTION__, Status));
    MmFreePages (DstBuffer, PageCount);
    return Status;
  }

  //
  // Relocate the image in our new buffer
  //
  Status = PeCoffLoaderRelocateImage (ImageContext);
  if (EFI_ERROR (Status)) {
    // if relocate fails, we don't need to call unload image here, as the extra action that may change page attributes
    // only is called on a successful return
    DEBUG ((DEBUG_ERROR, "%a Failed to relocate image %r\n", __FUNCTION__, Status));
    MmFreePages (DstBuffer, PageCount);
    return Status;
  }

  //
  // Flush the instruction cache so the image data are written before we execute it
  //
  InvalidateInstructionCacheRange ((VOID *)(UINTN)ImageContext->ImageAddress, (UINTN)ImageContext->ImageSize);

  //
  // Save Image EntryPoint in DriverEntry
  //
  DriverEntry->ImageEntryPoint = ImageContext->EntryPoint;
  DriverEntry->ImageBuffer     = DstBuffer;
  DriverEntry->NumberOfPage    = PageCount;

  // if (mEfiSystemTable != NULL) {
  // TODO: This is throw away memory but need to use until it is locked down...
  Status = MmAllocateSupervisorPool (
             EfiRuntimeServicesData,
             sizeof (EFI_LOADED_IMAGE_PROTOCOL),
             (VOID **)&DriverEntry->LoadedImage
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate pool for loaded image protocol %r\n", __FUNCTION__, Status));
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
    DEBUG ((DEBUG_ERROR, "%a Failed to set image attribute for loaded image %r\n", __FUNCTION__, Status));
    MmFreePages (DstBuffer, PageCount);
    return Status;
  }

  //
  // Print the load address and the PDB file name if it is available
  //
  DEBUG_CODE_BEGIN ();

  UINTN  Index;
  UINTN  StartIndex;
  CHAR8  EfiFileName[256];

  DEBUG ((
    DEBUG_INFO | DEBUG_LOAD,
    "Loading MM driver at 0x%11p EntryPoint=0x%11p ",
    (VOID *)(UINTN)ImageContext->ImageAddress,
    FUNCTION_ENTRY_POINT (ImageContext->EntryPoint)
    ));

  //
  // Print Module Name by Pdb file path.
  // Windows and Unix style file path are all trimmed correctly.
  //
  if (ImageContext->PdbPointer != NULL) {
    StartIndex = 0;
    for (Index = 0; ImageContext->PdbPointer[Index] != 0; Index++) {
      if ((ImageContext->PdbPointer[Index] == '\\') || (ImageContext->PdbPointer[Index] == '/')) {
        StartIndex = Index + 1;
      }
    }

    //
    // Copy the PDB file name to our temporary string, and replace .pdb with .efi
    // The PDB file name is limited in the range of 0~255.
    // If the length is bigger than 255, trim the redundant characters to avoid overflow in array boundary.
    //
    for (Index = 0; Index < sizeof (EfiFileName) - 4; Index++) {
      EfiFileName[Index] = ImageContext->PdbPointer[Index + StartIndex];
      if (EfiFileName[Index] == 0) {
        EfiFileName[Index] = '.';
      }

      if (EfiFileName[Index] == '.') {
        EfiFileName[Index + 1] = 'e';
        EfiFileName[Index + 2] = 'f';
        EfiFileName[Index + 3] = 'i';
        EfiFileName[Index + 4] = 0;
        break;
      }
    }

    if (Index == sizeof (EfiFileName) - 4) {
      EfiFileName[Index] = 0;
    }

    DEBUG ((DEBUG_INFO | DEBUG_LOAD, "%a", EfiFileName));
  }

  DEBUG ((DEBUG_INFO | DEBUG_LOAD, "\n"));

  DEBUG_CODE_END ();

  return Status;
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
  Return TRUE if the firmware volume has been processed, FALSE if not.

  @param  FwVolHeader           The header of the firmware volume that's being
                                tested.

  @retval TRUE                  The firmware volume denoted by FwVolHeader has
                                been processed
  @retval FALSE                 The firmware volume denoted by FwVolHeader has
                                not yet been processed

**/
BOOLEAN
FvHasBeenProcessed (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  )
{
  LIST_ENTRY   *Link;
  KNOWN_FWVOL  *KnownFwVol;

  for (Link = mFwVolList.ForwardLink;
       Link != &mFwVolList;
       Link = Link->ForwardLink)
  {
    KnownFwVol = CR (Link, KNOWN_FWVOL, Link, KNOWN_FWVOL_SIGNATURE);
    if (KnownFwVol->FwVolHeader == FwVolHeader) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Verify checksum of the firmware volume header.

  @param  FvHeader       Points to the firmware volume header to be checked

  @retval TRUE           Checksum verification passed
  @retval FALSE          Checksum verification failed

**/
BOOLEAN
VerifyFvHeaderChecksum (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FvHeader
  )
{
  UINT16  Checksum;

  Checksum = CalculateSum16 ((UINT16 *)FvHeader, FvHeader->HeaderLength);

  if (Checksum == 0) {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
  Remember that the firmware volume denoted by FwVolHeader has had its drivers
  placed on mDiscoveredList. This function adds entries to mFwVolList. Items
  are never removed/freed from mFwVolList.

  @param  FwVolHeader           The header of the firmware volume that's being
                                processed.

**/
KNOWN_FWVOL *
FvIsBeingProcessed (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  )
{
  KNOWN_FWVOL  *KnownFwVol;
  EFI_GUID     FvNameGuid;
  BOOLEAN      FvNameGuidIsFound = FALSE;
  LIST_ENTRY   *Link;

  DEBUG ((DEBUG_INFO, "FvIsBeingProcessed - 0x%08x\n", FwVolHeader));

  ASSERT (FwVolHeader != NULL);

  if (VerifyFvHeaderChecksum (FwVolHeader) && (FwVolHeader->ExtHeaderOffset != 0)) {
    CopyGuid (&FvNameGuid, &((EFI_FIRMWARE_VOLUME_EXT_HEADER *)((UINT8 *)FwVolHeader + FwVolHeader->ExtHeaderOffset))->FvName);
    FvNameGuidIsFound = TRUE;
  }

  if (FvNameGuidIsFound) {
    //
    // Check whether the FV image with the found FvNameGuid has been processed.
    //
    for (Link = mFwVolList.ForwardLink; Link != &mFwVolList; Link = Link->ForwardLink) {
      KnownFwVol = CR (Link, KNOWN_FWVOL, Link, KNOWN_FWVOL_SIGNATURE);
      if (CompareGuid (&FvNameGuid, &KnownFwVol->FvNameGuid)) {
        DEBUG ((DEBUG_INFO, "FvImage on FvHandle %p and %p has the same FvNameGuid %g.\n", FwVolHeader, KnownFwVol->FwVolHeader, &FvNameGuid));
        return NULL;
      }
    }
  }

  KnownFwVol = AllocatePool (sizeof (KNOWN_FWVOL));
  if (KnownFwVol == NULL) {
    ASSERT (FALSE);
    return NULL;
  }

  KnownFwVol->Signature   = KNOWN_FWVOL_SIGNATURE;
  KnownFwVol->FwVolHeader = FwVolHeader;
  if (FvNameGuidIsFound) {
    CopyGuid (&KnownFwVol->FvNameGuid, &FvNameGuid);
  }

  InsertTailList (&mFwVolList, &KnownFwVol->Link);
  return KnownFwVol;
}

/**
  Add an entry to the mDiscoveredList. Allocate memory to store the DriverEntry,
  and initialize any state variables. Read the Depex from the FV and store it
  in DriverEntry. Pre-process the Depex to set the Before and After state.
  The Discovered list is never freed and contains booleans that represent the
  other possible MM driver states.

  @param  Fv                    Fv protocol, needed to read Depex info out of
                                FLASH.
  @param  FvHandle              Handle for Fv, needed in the
                                EFI_MM_DRIVER_ENTRY so that the PE image can be
                                read out of the FV at a later time.
  @param  DriverName            Name of driver to add to mDiscoveredList.

  @retval EFI_SUCCESS           If driver was added to the mDiscoveredList.
  @retval EFI_ALREADY_STARTED   The driver has already been started. Only one
                                DriverName may be active in the system at any one
                                time.

**/
EFI_STATUS
MmAddToDriverList (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader,
  IN VOID                        *Pe32Data,
  IN UINTN                       Pe32DataSize,
  IN VOID                        *Depex,
  IN UINTN                       DepexSize,
  IN EFI_GUID                    *DriverName
  )
{
  EFI_MM_DRIVER_ENTRY  *DriverEntry;

  DEBUG ((DEBUG_INFO, "MmAddToDriverList - %g (0x%08x)\n", DriverName, Pe32Data));

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

  DriverEntry->Depex = AllocateCopyPool (DepexSize, Depex);
  ASSERT (DriverEntry->Depex != NULL);

  MmGetDepexSectionAndPreProccess (DriverEntry);

  InsertTailList (&mDiscoveredList, &DriverEntry->Link);
  gRequestDispatch = TRUE;

  return EFI_SUCCESS;
}
#define COMM_BUFFER_MM_DISPATCH_ERROR    0x00
#define COMM_BUFFER_MM_DISPATCH_SUCCESS  0x01
#define COMM_BUFFER_MM_DISPATCH_RESTART  0x02
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

  DEBUG ((DEBUG_INFO, "%a Entry\n", __FUNCTION__));

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
    if (*CommBufferSize > 0) {
      if (Status == EFI_NOT_READY) {
        //
        // If a the SMM Core Entry Point was just registered, then set flag to
        // request the SMM Dispatcher to be restarted.
        //
        *(UINT8 *)CommBuffer = COMM_BUFFER_MM_DISPATCH_RESTART;
      } else if (!EFI_ERROR (Status)) {
        //
        // Set the flag to show that the SMM Dispatcher executed without errors
        //
        *(UINT8 *)CommBuffer = COMM_BUFFER_MM_DISPATCH_SUCCESS;
      } else {
        //
        // Set the flag to show that the SMM Dispatcher encountered an error
        //
        *(UINT8 *)CommBuffer = COMM_BUFFER_MM_DISPATCH_ERROR;
      }
    }
  }

  DEBUG ((DEBUG_INFO, "%a Exit\n", __FUNCTION__));

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
