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

//
// Helpers split between Dispatcher_core.c (full implementation) and
// Dispatcher_init.c (no-op stubs).  See those files for the rationale.
//
EFI_STATUS
MmRegisterLoadedImage (
  IN OUT EFI_MM_DRIVER_ENTRY            *DriverEntry,
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT   *ImageContext,
  IN     EFI_PHYSICAL_ADDRESS           DstBuffer,
  IN     UINTN                          PageCount
  );

VOID
ProcessDepexBeforeDispatch (
  IN EFI_MM_DRIVER_ENTRY  *DriverEntry
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
    DEBUG ((DEBUG_ERROR, "%a Failed to read Pe/Coff loader image info %r\n", __func__, Status));
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
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate 0x%x pages for loading image %r\n", __func__, PageCount, Status));
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
    DEBUG ((DEBUG_ERROR, "%a Failed to load image into our allocated buffer %r\n", __func__, Status));
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
    DEBUG ((DEBUG_ERROR, "%a Failed to relocate image %r\n", __func__, Status));
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

  Status = MmRegisterLoadedImage (DriverEntry, ImageContext, DstBuffer, PageCount);
  if (EFI_ERROR (Status)) {
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

  ProcessDepexBeforeDispatch (DriverEntry);

  InsertTailList (&mDiscoveredList, &DriverEntry->Link);
  gRequestDispatch = TRUE;

  return EFI_SUCCESS;
}
