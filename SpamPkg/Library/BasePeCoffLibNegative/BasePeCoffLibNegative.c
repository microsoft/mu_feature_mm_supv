/** @file
  Base PE/COFF loader supports loading any PE32/PE32+ or TE image, but
  only supports relocating IA32, x64, IPF, ARM, RISC-V, LoongArch and EBC images.

  Caution: This file requires additional review when modified.
  This library will have external input - PE/COFF image.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  The basic guideline is that caller need provide ImageContext->ImageRead () with the
  necessary data range check, to make sure when this library reads PE/COFF image, the
  PE image buffer is always in valid range.
  This library will also do some additional check for PE header fields.

  PeCoffLoaderGetPeHeader() routine will do basic check for PE/COFF header.
  PeCoffLoaderGetImageInfo() routine will do basic check for whole PE/COFF image.

  Copyright (c) 2006 - 2019, Intel Corporation. All rights reserved.<BR>
  Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  Portions Copyright (c) 2020, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
  Portions Copyright (c) 2022, Loongson Technology Corporation Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Base.h>
#include <Library/PeCoffLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffExtraActionLib.h>
#include <Library/PeCoffLibNegative.h>
#include <IndustryStandard/PeImage.h>

/**
  Retrieves the PE or TE Header from a PE/COFF or TE image.

  @param  ImageContext    The context of the image being loaded.
  @param  Hdr             The buffer in which to return the PE32, PE32+, or TE header.

  @retval RETURN_SUCCESS  The PE or TE Header is read.
  @retval Other           The error status from reading the PE/COFF or TE image using the ImageRead function.

**/
RETURN_STATUS
PeCoffLoaderGetPeHeader (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT         *ImageContext,
  OUT    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr
  );

/**
  Converts an image address to the loaded address copy.

  @param  ImageContext      The context of the image being loaded.
  @param  Address           The address to be converted to the loaded address.
  @param  TeStrippedOffset  Stripped offset for TE image.

  @return The converted address or NULL if the address can not be converted.

**/
VOID *
PeCoffLoaderCopiedImageAddress (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  IN     UINTN                         Address,
  IN     UINTN                         TeStrippedOffset
  )
{
  //
  // Make sure that Address and ImageSize is correct for the loaded image.
  //
  if (Address >= ImageContext->ImageSize + TeStrippedOffset) {
    ImageContext->ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS;
    return NULL;
  }

  return (CHAR8 *)((UINTN)ImageContext->DestinationAddress + Address - TeStrippedOffset);
}

/**
  Applies relocation fixups to a PE/COFF image that was loaded with PeCoffLoaderLoadImage().

  If the DestinationAddress field of ImageContext is 0, then use the ImageAddress field of
  ImageContext as the relocation base address.  Otherwise, use the DestinationAddress field
  of ImageContext as the relocation base address.  The caller must allocate the relocation
  fixup log buffer and fill in the FixupData field of ImageContext prior to calling this function.

  The ImageRead, Handle, PeCoffHeaderOffset,  IsTeImage, Machine, ImageType, ImageAddress,
  ImageSize, DestinationAddress, RelocationsStripped, SectionAlignment, SizeOfHeaders,
  DebugDirectoryEntryRva, EntryPoint, FixupDataSize, CodeView, PdbPointer, and FixupData of
  the ImageContext structure must be valid prior to invoking this service.

  If ImageContext is NULL, then ASSERT().

  Note that if the platform does not maintain coherency between the instruction cache(s) and the data
  cache(s) in hardware, then the caller is responsible for performing cache maintenance operations
  prior to transferring control to a PE/COFF image that is loaded using this library.

  @param  ImageContext        The pointer to the image context structure that describes the PE/COFF
                              image that is being relocated.

  @retval RETURN_SUCCESS      The PE/COFF image was relocated.
                              Extended status information is in the ImageError field of ImageContext.
  @retval RETURN_LOAD_ERROR   The image in not a valid PE/COFF image.
                              Extended status information is in the ImageError field of ImageContext.
  @retval RETURN_UNSUPPORTED  A relocation record type is not supported.
                              Extended status information is in the ImageError field of ImageContext.

**/
extern volatile BOOLEAN loop;
RETURN_STATUS
EFIAPI
PeCoffLoaderRevertRelocateImage (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  RETURN_STATUS                        Status;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_DATA_DIRECTORY             *RelocDir;
  UINT64                               Adjust;
  EFI_IMAGE_BASE_RELOCATION            *RelocBaseOrg;
  EFI_IMAGE_BASE_RELOCATION            *RelocBase;
  EFI_IMAGE_BASE_RELOCATION            *RelocBaseEnd;
  UINT16                               *Reloc;
  UINT16                               *RelocEnd;
  CHAR8                                *Fixup;
  CHAR8                                *FixupBase;
  UINT16                               *Fixup16;
  UINT32                               *Fixup32;
  UINT64                               *Fixup64;
  CHAR8                                *FixupData;
  PHYSICAL_ADDRESS                     BaseAddress;
  UINT32                               NumberOfRvaAndSizes;
  UINT32                               TeStrippedOffset;

  ASSERT (ImageContext != NULL);

  // TODO: Clean up
  // --------------------8<--------------------
  EFI_IMAGE_OPTIONAL_HEADER_UNION      HdrData;

  Hdr.Union = &HdrData;
  Status = PeCoffLoaderGetPeHeader (ImageContext, Hdr);
  if (RETURN_ERROR (Status)) {
    return Status;
  }
  // -------------------->8--------------------

  //
  // Assume success
  //
  ImageContext->ImageError = IMAGE_ERROR_SUCCESS;

  //
  // If there are no relocation entries, then we are done
  //
  if (ImageContext->RelocationsStripped) {
    // Applies additional environment specific actions to relocate fixups
    // to a PE/COFF image if needed
    PeCoffLoaderRelocateImageExtraAction (ImageContext);
    return RETURN_SUCCESS;
  }

  //
  // If the destination address is not 0, use that rather than the
  // image address as the relocation target.
  //
  if (ImageContext->DestinationAddress != 0) {
    BaseAddress = ImageContext->DestinationAddress;
  } else {
    BaseAddress = ImageContext->ImageAddress;
  }

  if (ImageContext->IsTeImage) {
    // This should have been rejected above, but if not, we still reject TE image here
    ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
    return RETURN_LOAD_ERROR;
  }

  // Grab the PE32+ header from the copied image
  Hdr.Pe32         = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)ImageContext->DestinationAddress + ImageContext->PeCoffHeaderOffset);
  TeStrippedOffset = 0;

  //
  // Use PE32+ offset
  //
  if ((UINT64)ImageContext->ImageAddress - Hdr.Pe32Plus->OptionalHeader.ImageBase != 0) {
    // We are working on some unrelocated image. This cannot be right.
    ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
    return RETURN_LOAD_ERROR;
  }

  // Revert 1: Revert the image base to 0.
  Hdr.Pe32Plus->OptionalHeader.ImageBase = 0;
  Adjust                                 = (UINT64)ImageContext->ImageAddress;

  NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
  RelocDir            = &Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];

  //
  // Find the relocation block
  // Per the PE/COFF spec, you can't assume that a given data directory
  // is present in the image. You have to check the NumberOfRvaAndSizes in
  // the optional header to verify a desired directory entry is there.
  //
  if ((NumberOfRvaAndSizes < EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
    RelocDir = NULL;
  }

  if ((RelocDir != NULL) && (RelocDir->Size > 0)) {
    RelocBase    = (EFI_IMAGE_BASE_RELOCATION *)PeCoffLoaderCopiedImageAddress (ImageContext, RelocDir->VirtualAddress, TeStrippedOffset);
    RelocBaseEnd = (EFI_IMAGE_BASE_RELOCATION *)PeCoffLoaderCopiedImageAddress (
                                                  ImageContext,
                                                  RelocDir->VirtualAddress + RelocDir->Size - 1,
                                                  TeStrippedOffset
                                                  );
    if ((RelocBase == NULL) || (RelocBaseEnd == NULL) || ((UINTN)RelocBaseEnd < (UINTN)RelocBase)) {
      ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
      return RETURN_LOAD_ERROR;
    }
  } else {
    //
    // Set base and end to bypass processing below.
    //
    RelocBase = RelocBaseEnd = NULL;
  }

  RelocBaseOrg = RelocBase;

  //
  // Run the reverse relocation information and apply the fixup reversions
  //
  FixupData = ImageContext->FixupData;
  while ((UINTN)RelocBase < (UINTN)RelocBaseEnd) {
    Reloc = (UINT16 *)((CHAR8 *)RelocBase + sizeof (EFI_IMAGE_BASE_RELOCATION));
    //
    // Add check for RelocBase->SizeOfBlock field.
    //
    if (RelocBase->SizeOfBlock == 0) {
      ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
      return RETURN_LOAD_ERROR;
    }

    if ((UINTN)RelocBase > MAX_ADDRESS - RelocBase->SizeOfBlock) {
      ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
      return RETURN_LOAD_ERROR;
    }

    RelocEnd = (UINT16 *)((CHAR8 *)RelocBase + RelocBase->SizeOfBlock);
    if ((UINTN)RelocEnd > (UINTN)RelocBaseOrg + RelocDir->Size) {
      ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
      return RETURN_LOAD_ERROR;
    }

    FixupBase = PeCoffLoaderCopiedImageAddress (ImageContext, RelocBase->VirtualAddress, TeStrippedOffset);
    if (FixupBase == NULL) {
      ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
      return RETURN_LOAD_ERROR;
    }

    //
    // Run this relocation record
    //
    while ((UINTN)Reloc < (UINTN)RelocEnd) {
      Fixup = PeCoffLoaderCopiedImageAddress (ImageContext, RelocBase->VirtualAddress + (*Reloc & 0xFFF), TeStrippedOffset);
      if (Fixup == NULL) {
        ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
        return RETURN_LOAD_ERROR;
      }

      switch ((*Reloc) >> 12) {
        case EFI_IMAGE_REL_BASED_ABSOLUTE:
          break;

        case EFI_IMAGE_REL_BASED_HIGH:
          Fixup16  = (UINT16 *)Fixup;
          *Fixup16 = (UINT16)(*Fixup16 - ((UINT16)((UINT32)Adjust >> 16)));
          if (FixupData != NULL) {
            *(UINT16 *)FixupData = *Fixup16;
            FixupData            = FixupData + sizeof (UINT16);
          }

          break;

        case EFI_IMAGE_REL_BASED_LOW:
          Fixup16  = (UINT16 *)Fixup;
          *Fixup16 = (UINT16)(*Fixup16 - (UINT16)Adjust);
          if (FixupData != NULL) {
            *(UINT16 *)FixupData = *Fixup16;
            FixupData            = FixupData + sizeof (UINT16);
          }

          break;

        case EFI_IMAGE_REL_BASED_HIGHLOW:
          Fixup32  = (UINT32 *)Fixup;
          *Fixup32 = *Fixup32 - (UINT32)Adjust;
          if (FixupData != NULL) {
            FixupData            = ALIGN_POINTER (FixupData, sizeof (UINT32));
            *(UINT32 *)FixupData = *Fixup32;
            FixupData            = FixupData + sizeof (UINT32);
          }

          break;

        case EFI_IMAGE_REL_BASED_DIR64:
          Fixup64  = (UINT64 *)Fixup;
          *Fixup64 = *Fixup64 - (UINT64)Adjust;
          if (FixupData != NULL) {
            FixupData              = ALIGN_POINTER (FixupData, sizeof (UINT64));
            *(UINT64 *)(FixupData) = *Fixup64;
            FixupData              = FixupData + sizeof (UINT64);
          }

          break;

        default:
          //
          // The common code does not handle some of the stranger IPF relocations
          // PeCoffLoaderRelocateImageEx () adds support for these complex fixups
          // on IPF and is a No-Op on other architectures.
          //
          Status = RETURN_UNSUPPORTED;
          if (RETURN_ERROR (Status)) {
            ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
            return Status;
          }
      }

      //
      // Next relocation record
      //
      Reloc += 1;
    }

    //
    // Next reloc block
    //
    RelocBase = (EFI_IMAGE_BASE_RELOCATION *)RelocEnd;
  }

  ASSERT ((UINTN)FixupData <= (UINTN)ImageContext->FixupData + ImageContext->FixupDataSize);

  return RETURN_SUCCESS;
}

/**
  Loads a PE/COFF image into memory.

  Loads the PE/COFF image accessed through the ImageRead service of ImageContext into the buffer
  specified by the ImageAddress and ImageSize fields of ImageContext.  The caller must allocate
  the load buffer and fill in the ImageAddress and ImageSize fields prior to calling this function.
  The EntryPoint, FixupDataSize, CodeView, PdbPointer and HiiResourceData fields of ImageContext are computed.
  The ImageRead, Handle, PeCoffHeaderOffset,  IsTeImage,  Machine, ImageType, ImageAddress, ImageSize,
  DestinationAddress, RelocationsStripped, SectionAlignment, SizeOfHeaders, and DebugDirectoryEntryRva
  fields of the ImageContext structure must be valid prior to invoking this service.

  If ImageContext is NULL, then ASSERT().

  Note that if the platform does not maintain coherency between the instruction cache(s) and the data
  cache(s) in hardware, then the caller is responsible for performing cache maintenance operations
  prior to transferring control to a PE/COFF image that is loaded using this library.

  @param  ImageContext              The pointer to the image context structure that describes the PE/COFF
                                    image that is being loaded.

  @retval RETURN_SUCCESS            The PE/COFF image was loaded into the buffer specified by
                                    the ImageAddress and ImageSize fields of ImageContext.
                                    Extended status information is in the ImageError field of ImageContext.
  @retval RETURN_BUFFER_TOO_SMALL   The caller did not provide a large enough buffer.
                                    Extended status information is in the ImageError field of ImageContext.
  @retval RETURN_LOAD_ERROR         The PE/COFF image is an EFI Runtime image with no relocations.
                                    Extended status information is in the ImageError field of ImageContext.
  @retval RETURN_INVALID_PARAMETER  The image address is invalid.
                                    Extended status information is in the ImageError field of ImageContext.

**/
RETURN_STATUS
EFIAPI
PeCoffLoaderRevertLoadImage (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT *ImageContext,
  OUT   UINTN                         *Buffer
  )
{
  RETURN_STATUS                        Status;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_SECTION_HEADER             *FirstSection;
  EFI_IMAGE_SECTION_HEADER             *Section;
  UINTN                                NumberOfSections;
  UINTN                                Index;
  CHAR8                                *Base;
  CHAR8                                *End;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;
  EFI_IMAGE_DEBUG_DIRECTORY_ENTRY      *DebugEntry;
  UINTN                                Size;
  UINT32                               TempDebugEntryRva;
  UINT32                               NumberOfRvaAndSizes;
  UINT32                               TeStrippedOffset;

  ASSERT (ImageContext != NULL);

  //
  // Assume success
  //
  ImageContext->ImageError = IMAGE_ERROR_SUCCESS;

  // TODO: Clean up
  // --------------------8<--------------------
  // //
  // // Make sure there is enough allocated space for the image being loaded
  // //
  // if (ImageContext->ImageSize < CheckContext.ImageSize) {
  //   ImageContext->ImageError = IMAGE_ERROR_INVALID_IMAGE_SIZE;
  //   return RETURN_BUFFER_TOO_SMALL;
  // }
  // -------------------->8--------------------


  if (ImageContext->ImageAddress == 0) {
    //
    // Image cannot be loaded into 0 address.
    //
    ImageContext->ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS;
    return RETURN_INVALID_PARAMETER;
  }

  //
  // If there's no relocations, then make sure it's not a runtime driver,
  // and that it's being loaded at the linked address.
  //
  if (ImageContext->RelocationsStripped) {
    //
    // If the image does not contain relocations and it is a runtime driver
    // then return an error.
    //
    if (ImageContext->ImageType == EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
      ImageContext->ImageError = IMAGE_ERROR_INVALID_SUBSYSTEM;
      return RETURN_LOAD_ERROR;
    }

    //
    // If the image does not contain relocations, and the requested load address
    // is not the linked address, then return an error.
    //
    if (ImageContext->ImageAddress != ImageContext->ImageAddress) {
      ImageContext->ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS;
      return RETURN_INVALID_PARAMETER;
    }
  }

  //
  // Make sure the allocated space has the proper section alignment
  //
  if (ImageContext->IsTeImage) {
    // We do not support TE image de-relocate
    ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
    return RETURN_LOAD_ERROR;
  }

  if ((ImageContext->ImageAddress & (ImageContext->SectionAlignment - 1)) != 0) {
    ImageContext->ImageError = IMAGE_ERROR_INVALID_SECTION_ALIGNMENT;
    return RETURN_INVALID_PARAMETER;
  }

  //
  // Read the entire PE/COFF header into memory
  //
  Status = ImageContext->ImageRead (
                            ImageContext->Handle,
                            0,
                            &ImageContext->SizeOfHeaders,
                            Buffer
                            );

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Buffer + ImageContext->PeCoffHeaderOffset);

  FirstSection = (EFI_IMAGE_SECTION_HEADER *)(
                                              (UINTN)ImageContext->DestinationAddress +
                                              ImageContext->PeCoffHeaderOffset +
                                              sizeof (UINT32) +
                                              sizeof (EFI_IMAGE_FILE_HEADER) +
                                              Hdr.Pe32->FileHeader.SizeOfOptionalHeader
                                              );
  NumberOfSections = (UINTN)(Hdr.Pe32->FileHeader.NumberOfSections);
  TeStrippedOffset = 0;

  if (RETURN_ERROR (Status)) {
    ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
    return RETURN_LOAD_ERROR;
  }

  //
  // Load each section of the image
  //
  Section = FirstSection;
  for (Index = 0; Index < NumberOfSections; Index++) {
    //
    // Read the section
    //
    Size = (UINTN)Section->Misc.VirtualSize;
    if ((Size == 0) || (Size > Section->SizeOfRawData)) {
      Size = (UINTN)Section->SizeOfRawData;
    }

    //
    // Compute sections address
    //
    Base = PeCoffLoaderCopiedImageAddress (ImageContext, Section->VirtualAddress, TeStrippedOffset);
    End  = PeCoffLoaderCopiedImageAddress (ImageContext, Section->VirtualAddress + Section->Misc.VirtualSize - 1, TeStrippedOffset);

    //
    // If the size of the section is non-zero and the base address or end address resolved to 0, then fail.
    //
    if ((Size > 0) && ((Base == NULL) || (End == NULL))) {
      ImageContext->ImageError = IMAGE_ERROR_SECTION_NOT_LOADED;
      return RETURN_LOAD_ERROR;
    }

    // MU_CHANGE - CodeQL change
    if ((Section->SizeOfRawData > 0) && (Base != NULL)) {
      // Now we copy the section data to the memory allocated for the image, compactly.
      Status = ImageContext->ImageRead (
                               ImageContext->Handle,
                               (UINTN)(Base - ImageContext->DestinationAddress),
                               &Size,
                               (VOID*)((UINTN)Buffer + Section->PointerToRawData - TeStrippedOffset)
                               );
      if (RETURN_ERROR (Status)) {
        ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
        return Status;
      }
    }

    //
    // If raw size is less then virtual size, zero fill the remaining
    //
    //
    // Next Section
    //
    Section += 1;
  }

  //
  // Determine the size of the fixup data
  //
  // Per the PE/COFF spec, you can't assume that a given data directory
  // is present in the image. You have to check the NumberOfRvaAndSizes in
  // the optional header to verify a desired directory entry is there.
  //
  //
  // Use PE32+ offset
  //
  NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
  DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];

  //
  // Consumer must allocate a buffer for the relocation fixup log.
  // Only used for runtime drivers.
  //
  ImageContext->FixupData = NULL;

  //
  // Load the Codeview information if present
  //
  if (ImageContext->DebugDirectoryEntryRva != 0) {
    DebugEntry = PeCoffLoaderCopiedImageAddress (
                   ImageContext,
                   ImageContext->DebugDirectoryEntryRva,
                   TeStrippedOffset
                   );
    if (DebugEntry == NULL) {
      ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
      return RETURN_LOAD_ERROR;
    }

    TempDebugEntryRva = DebugEntry->RVA;
    if ((DebugEntry->RVA == 0) && (DebugEntry->FileOffset != 0)) {
      Section--;
      if ((UINTN)Section->SizeOfRawData < Section->Misc.VirtualSize) {
        TempDebugEntryRva = Section->VirtualAddress + Section->Misc.VirtualSize;
      } else {
        TempDebugEntryRva = Section->VirtualAddress + Section->SizeOfRawData;
      }
    }

    if (TempDebugEntryRva != 0) {
      ImageContext->CodeView = PeCoffLoaderCopiedImageAddress (ImageContext, TempDebugEntryRva, TeStrippedOffset);
      if (ImageContext->CodeView == NULL) {
        ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
        return RETURN_LOAD_ERROR;
      }

      if (DebugEntry->RVA != 0) {
        Size   = DebugEntry->SizeOfData;
        Status = ImageContext->ImageRead (
                                 ImageContext->Handle,
                                 (UINTN)ImageContext->CodeView,
                                 &Size,
                                 (VOID*)(ImageContext->DestinationAddress + DebugEntry->FileOffset - TeStrippedOffset)
                                 );
        //
        // Should we apply fix up to this field according to the size difference between PE and TE?
        // Because now we maintain TE header fields unfixed, this field will also remain as they are
        // in original PE image.
        //

        if (RETURN_ERROR (Status)) {
          ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
          return RETURN_LOAD_ERROR;
        }

        DebugEntry->RVA = 0;
      }

      switch (*(UINT32 *)ImageContext->CodeView) {
        case CODEVIEW_SIGNATURE_NB10:
          if (DebugEntry->SizeOfData < sizeof (EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY)) {
            ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
            return RETURN_UNSUPPORTED;
          }

          ImageContext->PdbPointer = (CHAR8 *)ImageContext->CodeView + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY);
          break;

        case CODEVIEW_SIGNATURE_RSDS:
          if (DebugEntry->SizeOfData < sizeof (EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY)) {
            ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
            return RETURN_UNSUPPORTED;
          }

          ImageContext->PdbPointer = (CHAR8 *)ImageContext->CodeView + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY);
          break;

        case CODEVIEW_SIGNATURE_MTOC:
          if (DebugEntry->SizeOfData < sizeof (EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY)) {
            ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
            return RETURN_UNSUPPORTED;
          }

          ImageContext->PdbPointer = (CHAR8 *)ImageContext->CodeView + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY);
          break;

        default:
          break;
      }
    }
  }

  //
  // Ignore Image's HII resource section
  //
  ImageContext->HiiResourceData = 0;

  return Status;
}

/**
  Reads contents of a PE/COFF image from a buffer in system memory.

  This is the default implementation of a PE_COFF_LOADER_READ_FILE function
  that assumes FileHandle pointer to the beginning of a PE/COFF image.
  This function reads contents of the PE/COFF image that starts at the system memory
  address specified by FileHandle.  The read operation copies ReadSize bytes from the
  PE/COFF image starting at byte offset FileOffset into the buffer specified by Buffer.
  The size of the buffer actually read is returned in ReadSize.

  The caller must make sure the FileOffset and ReadSize within the file scope.

  If FileHandle is NULL, then ASSERT().
  If ReadSize is NULL, then ASSERT().
  If Buffer is NULL, then ASSERT().

  @param  FileHandle        The pointer to base of the input stream
  @param  FileOffset        Offset into the PE/COFF image to begin the read operation.
  @param  ReadSize          On input, the size in bytes of the requested read operation.
                            On output, the number of bytes actually read.
  @param  Buffer            Output buffer that contains the data read from the PE/COFF image.

  @retval RETURN_SUCCESS    Data is read from FileOffset from the Handle into
                            the buffer.
**/
RETURN_STATUS
EFIAPI
PeCoffLoaderImageNegativeReadFromMemory (
  IN     VOID   *FileHandle,
  IN     UINTN  FileOffset,
  IN OUT UINTN  *ReadSize,
  OUT    VOID   *Buffer
  )
{
  ASSERT (ReadSize != NULL);
  ASSERT (FileHandle != NULL);
  ASSERT (Buffer != NULL);

  // TODO: This function needs to take care of the boundary checking before reading.

  CopyMem (Buffer, ((UINT8 *)FileHandle) + FileOffset, *ReadSize);
  return RETURN_SUCCESS;
}

// TODO: When moving this over to Spam core, we need to make sure that the
//       following function is implemented in the Spam core and the page
//       table is fixed up to point to the one used in MM environment.
EFI_STATUS
EFIAPI
SmmGetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  OUT UINT64                *Attributes
  );

/**
  Revert fixups and global data changes to an executed PE/COFF image that was loaded
  with PeCoffLoaderLoadImage() and relocated with PeCoffLoaderRelocateImage().

  @param[in,out]  TargetImage        The pointer to the target image buffer.
  @param[in]      TargetImageSize    The size of the target image buffer.
  @param[in]      ReferenceData      The pointer to the reference data buffer to assist .
  @param[in]      ReferenceDataSize  The size of the reference data buffer.

  @return EFI_SUCCESS               The PE/COFF image was reverted.
  @return EFI_INVALID_PARAMETER     The parameter is invalid.
  @return EFI_COMPROMISED_DATA      The PE/COFF image is compromised.
**/
EFI_STATUS
EFIAPI
PeCoffImageDiffValidation (
  IN      VOID        *OriginalImageBaseAddress,
  IN OUT  VOID        *TargetImage,
  IN      UINTN       TargetImageSize,
  IN      CONST VOID  *ReferenceData,
  IN      UINTN       ReferenceDataSize
  )
{
  IMAGE_VALIDATION_DATA_HEADER  *ImageValidationHdr;
  IMAGE_VALIDATION_ENTRY_HEADER *ImageValidationEntryHdr;
  IMAGE_VALIDATION_ENTRY_HEADER *NextImageValidationEntryHdr;
  IMAGE_VALIDATION_MEM_ATTR     *ImageValidationEntryMemAttr;
  IMAGE_VALIDATION_SELF_REF     *ImageValidationEntrySelfRef;
  UINT64                        MemAttr;
  UINTN                         Index;
  EFI_STATUS                    Status;
  EFI_PHYSICAL_ADDRESS          AddrInTarget;
  EFI_PHYSICAL_ADDRESS          AddrInOrigin;

  if (TargetImageSize == 0 || ReferenceDataSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (TargetImage == NULL || ReferenceData == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ImageValidationHdr = (IMAGE_VALIDATION_DATA_HEADER*)ReferenceData;
  if (ImageValidationHdr->HeaderSignature != IMAGE_VALIDATION_DATA_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  if (ImageValidationHdr->Size != ReferenceDataSize) {
    return EFI_COMPROMISED_DATA;
  }

  ImageValidationEntryHdr = (IMAGE_VALIDATION_ENTRY_HEADER*)(ImageValidationHdr + 1);
  for (Index = 0; Index < ImageValidationHdr->EntryCount; Index++) {
    // TODO: Safe integer arithmetic
    if ((UINT8*)(ImageValidationEntryHdr) >= ((UINT8*)ReferenceData + ReferenceDataSize)) {
      return EFI_COMPROMISED_DATA;
    }

    if (ImageValidationEntryHdr->EntrySignature != IMAGE_VALIDATION_ENTRY_SIGNATURE) {
      return EFI_COMPROMISED_DATA;
    }

    if (ImageValidationEntryHdr->Offset + ImageValidationEntryHdr->Size > TargetImageSize) {
      return EFI_INVALID_PARAMETER;
    }

    if (ImageValidationEntryHdr->Offset + ImageValidationEntryHdr->Size > TargetImageSize) {
      return EFI_INVALID_PARAMETER;
    }

    switch (ImageValidationEntryHdr->ValidationType) {
      case IMAGE_VALIDATION_ENTRY_TYPE_NONE:
        NextImageValidationEntryHdr = (IMAGE_VALIDATION_ENTRY_HEADER*)(ImageValidationEntryHdr + 1);
        Status = EFI_SUCCESS;
        break;
      case IMAGE_VALIDATION_ENTRY_TYPE_NON_ZERO:
        if (IsZeroBuffer ((UINT8 *)TargetImage + ImageValidationEntryHdr->Offset, ImageValidationEntryHdr->Size)) {
          Status = EFI_SECURITY_VIOLATION;
        } else {
          NextImageValidationEntryHdr = (IMAGE_VALIDATION_ENTRY_HEADER*)((UINT8*)ImageValidationEntryHdr + sizeof (IMAGE_VALIDATION_MEM_ATTR));
        }
        break;
      case IMAGE_VALIDATION_ENTRY_TYPE_CONTENT:
        if (CompareMem ((UINT8 *)TargetImage + ImageValidationEntryHdr->Offset, (UINT8*)ReferenceData + ImageValidationEntryHdr->OffsetToDefault, ImageValidationEntryHdr->Size) != 0) {
          Status = EFI_COMPROMISED_DATA;
        } else {
          NextImageValidationEntryHdr = (IMAGE_VALIDATION_ENTRY_HEADER*)((UINT8*)(ImageValidationEntryHdr + 1) + ImageValidationEntryHdr->Size);
        }
        break;
      case IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR:
        ImageValidationEntryMemAttr = (IMAGE_VALIDATION_MEM_ATTR*)(ImageValidationEntryHdr);
        if (ImageValidationEntryMemAttr->TargetMemeoryAttributeMustHave == 0 && ImageValidationEntryMemAttr->TargetMemeoryAttributeMustNotHave == 0) {
          Status = EFI_INVALID_PARAMETER;
          break;
        }

        // Inspection of the memory attributes of the target image
        Status = SmmGetMemoryAttributes (
                   (EFI_PHYSICAL_ADDRESS)((UINTN)OriginalImageBaseAddress + ImageValidationEntryHdr->Offset),
                   ImageValidationEntryHdr->Size,
                   &MemAttr
                   );
        if (EFI_ERROR(Status)) {
          break;
        }
        // Check if the memory attributes of the target image meet the requirements
        if (((MemAttr & ImageValidationEntryMemAttr->TargetMemeoryAttributeMustHave) != ImageValidationEntryMemAttr->TargetMemeoryAttributeMustHave) &&
            ((MemAttr & ImageValidationEntryMemAttr->TargetMemeoryAttributeMustNotHave) != 0)) {
          Status = EFI_SECURITY_VIOLATION;
        } else {
          NextImageValidationEntryHdr = (IMAGE_VALIDATION_ENTRY_HEADER*)(ImageValidationEntryMemAttr + 1);
        }
        break;
      case IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF:
        ImageValidationEntrySelfRef = (IMAGE_VALIDATION_SELF_REF*)(ImageValidationEntryHdr);
        if (ImageValidationEntrySelfRef->Header.OffsetToDefault + ImageValidationEntrySelfRef->Header.Size > ReferenceDataSize) {
          Status = EFI_COMPROMISED_DATA;
          break;
        }

        // For now, self reference is only valid for address type in x64 mode
        if (ImageValidationEntrySelfRef->Header.Size != sizeof (EFI_PHYSICAL_ADDRESS)) {
          Status = EFI_INVALID_PARAMETER;
          break;
        }

        // Check if the self-reference data of the target image meet the requirements
        AddrInTarget = *(EFI_PHYSICAL_ADDRESS*)((UINTN)TargetImage + ImageValidationEntryHdr->Offset);
        AddrInOrigin = *(EFI_PHYSICAL_ADDRESS*)((UINTN)OriginalImageBaseAddress + ImageValidationEntrySelfRef->TargetOffset);
        if (AddrInTarget != AddrInOrigin) {
          Status = EFI_SECURITY_VIOLATION;
        } else {
          NextImageValidationEntryHdr = (IMAGE_VALIDATION_ENTRY_HEADER*)(ImageValidationEntrySelfRef + 1);
        }
        break;
      default:
        // Does not support unknown validation type
        Status = EFI_INVALID_PARAMETER;
        break;
    }

    if (EFI_ERROR(Status)) {
      break;
    }

    // We should not do this when the above validation fails
    CopyMem ((UINT8 *)TargetImage + ImageValidationEntryHdr->Offset, (UINT8*)ReferenceData + ImageValidationEntryHdr->OffsetToDefault, ImageValidationEntryHdr->Size);

    ImageValidationEntryHdr = NextImageValidationEntryHdr;
  }

  return Status;
}
