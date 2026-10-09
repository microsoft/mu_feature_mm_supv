/** @file
  Discover and load MM drivers for the separately built supervisor runtime.

  Firmware volumes are processed once. Drivers and their dependency expressions
  are collected for the runtime to dispatch after initialization.

  Copyright (c) 2014, Hewlett-Packard Development Company, L.P.
  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include "MmSupervisorCore.h"

//
// The Driver List contains one copy of every driver that has been discovered.
// Items are never removed from the driver list. List of EFI_MM_DRIVER_ENTRY
//
LIST_ENTRY  mDiscoveredList = INITIALIZE_LIST_HEAD_VARIABLE (mDiscoveredList);

//
// List of firmware volume headers whose containing firmware volumes have been
// parsed and added to the mDiscoveredList.
//
LIST_ENTRY  mFwVolList = INITIALIZE_LIST_HEAD_VARIABLE (mFwVolList);

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
  and copy the dependency expression for the runtime to evaluate.

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

  InsertTailList (&mDiscoveredList, &DriverEntry->Link);

  return EFI_SUCCESS;
}

/**
  Load every discovered MM driver without invoking its entry point.

  @retval EFI_SUCCESS           All discovered MM drivers have been loaded.

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
