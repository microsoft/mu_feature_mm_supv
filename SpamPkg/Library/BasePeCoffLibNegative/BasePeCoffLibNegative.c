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

#include "BasePeCoffLibNegativeInternals.h"

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

  while (loop) {}
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

  if (!(ImageContext->IsTeImage)) {
    Hdr.Pe32         = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)ImageContext->ImageAddress + ImageContext->PeCoffHeaderOffset);
    TeStrippedOffset = 0;

    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      Adjust = (UINT64)BaseAddress - Hdr.Pe32->OptionalHeader.ImageBase;
      if (Adjust != 0) {
        Hdr.Pe32->OptionalHeader.ImageBase = (UINT32)BaseAddress;
      }

      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      RelocDir            = &Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
      //
      // Use PE32+ offset
      //
      Adjust = (UINT64)BaseAddress - Hdr.Pe32Plus->OptionalHeader.ImageBase;
      if (Adjust != 0) {
        Hdr.Pe32Plus->OptionalHeader.ImageBase = (UINT64)BaseAddress;
      }

      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      RelocDir            = &Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    //
    // Find the relocation block
    // Per the PE/COFF spec, you can't assume that a given data directory
    // is present in the image. You have to check the NumberOfRvaAndSizes in
    // the optional header to verify a desired directory entry is there.
    //
    if ((NumberOfRvaAndSizes < EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
      RelocDir = NULL;
    }
  } else {
    Hdr.Te           = (EFI_TE_IMAGE_HEADER *)(UINTN)(ImageContext->ImageAddress);
    TeStrippedOffset = (UINT32)Hdr.Te->StrippedSize - sizeof (EFI_TE_IMAGE_HEADER);
    Adjust           = (UINT64)(BaseAddress - (Hdr.Te->ImageBase + TeStrippedOffset));
    if (Adjust != 0) {
      Hdr.Te->ImageBase = (UINT64)(BaseAddress - TeStrippedOffset);
    }

    //
    // Find the relocation block
    //
    RelocDir = &Hdr.Te->DataDirectory[0];
  }

  if ((RelocDir != NULL) && (RelocDir->Size > 0)) {
    RelocBase    = (EFI_IMAGE_BASE_RELOCATION *)PeCoffLoaderImageAddress (ImageContext, RelocDir->VirtualAddress, TeStrippedOffset);
    RelocBaseEnd = (EFI_IMAGE_BASE_RELOCATION *)PeCoffLoaderImageAddress (
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
  // If Adjust is not zero, then apply fix ups to the image
  //
  if (Adjust != 0) {
    //
    // Run the relocation information and apply the fixups
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

      FixupBase = PeCoffLoaderImageAddress (ImageContext, RelocBase->VirtualAddress, TeStrippedOffset);
      if (FixupBase == NULL) {
        ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
        return RETURN_LOAD_ERROR;
      }

      //
      // Run this relocation record
      //
      while ((UINTN)Reloc < (UINTN)RelocEnd) {
        Fixup = PeCoffLoaderImageAddress (ImageContext, RelocBase->VirtualAddress + (*Reloc & 0xFFF), TeStrippedOffset);
        if (Fixup == NULL) {
          ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
          return RETURN_LOAD_ERROR;
        }

        switch ((*Reloc) >> 12) {
          case EFI_IMAGE_REL_BASED_ABSOLUTE:
            break;

          case EFI_IMAGE_REL_BASED_HIGH:
            Fixup16  = (UINT16 *)Fixup;
            *Fixup16 = (UINT16)(*Fixup16 + ((UINT16)((UINT32)Adjust >> 16)));
            if (FixupData != NULL) {
              *(UINT16 *)FixupData = *Fixup16;
              FixupData            = FixupData + sizeof (UINT16);
            }

            break;

          case EFI_IMAGE_REL_BASED_LOW:
            Fixup16  = (UINT16 *)Fixup;
            *Fixup16 = (UINT16)(*Fixup16 + (UINT16)Adjust);
            if (FixupData != NULL) {
              *(UINT16 *)FixupData = *Fixup16;
              FixupData            = FixupData + sizeof (UINT16);
            }

            break;

          case EFI_IMAGE_REL_BASED_HIGHLOW:
            Fixup32  = (UINT32 *)Fixup;
            *Fixup32 = *Fixup32 + (UINT32)Adjust;
            if (FixupData != NULL) {
              FixupData            = ALIGN_POINTER (FixupData, sizeof (UINT32));
              *(UINT32 *)FixupData = *Fixup32;
              FixupData            = FixupData + sizeof (UINT32);
            }

            break;

          case EFI_IMAGE_REL_BASED_DIR64:
            Fixup64  = (UINT64 *)Fixup;
            *Fixup64 = *Fixup64 + (UINT64)Adjust;
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
            Status = PeCoffLoaderRelocateImageEx (Reloc, Fixup, &FixupData, Adjust);
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

    //
    // Adjust the EntryPoint to match the linked-to address
    //
    if (ImageContext->DestinationAddress != 0) {
      ImageContext->EntryPoint -= (UINT64)ImageContext->ImageAddress;
      ImageContext->EntryPoint += (UINT64)ImageContext->DestinationAddress;
    }
  }

  // Applies additional environment specific actions to relocate fixups
  // to a PE/COFF image if needed
  PeCoffLoaderRelocateImageExtraAction (ImageContext);

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
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  RETURN_STATUS                        Status;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  PE_COFF_LOADER_IMAGE_CONTEXT         CheckContext;
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
  EFI_IMAGE_RESOURCE_DIRECTORY         *ResourceDirectory;
  EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY   *ResourceDirectoryEntry;
  EFI_IMAGE_RESOURCE_DIRECTORY_STRING  *ResourceDirectoryString;
  EFI_IMAGE_RESOURCE_DATA_ENTRY        *ResourceDataEntry;
  CHAR16                               *String;
  UINT32                               Offset;
  UINT32                               TeStrippedOffset;

  ASSERT (ImageContext != NULL);

  //
  // Assume success
  //
  ImageContext->ImageError = IMAGE_ERROR_SUCCESS;

  //
  // Copy the provided context information into our local version, get what we
  // can from the original image, and then use that to make sure everything
  // is legit.
  //
  CopyMem (&CheckContext, ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));

  Status = PeCoffLoaderGetImageInfo (&CheckContext);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  //
  // Make sure there is enough allocated space for the image being loaded
  //
  if (ImageContext->ImageSize < CheckContext.ImageSize) {
    ImageContext->ImageError = IMAGE_ERROR_INVALID_IMAGE_SIZE;
    return RETURN_BUFFER_TOO_SMALL;
  }

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
  if (CheckContext.RelocationsStripped) {
    //
    // If the image does not contain relocations and it is a runtime driver
    // then return an error.
    //
    if (CheckContext.ImageType == EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
      ImageContext->ImageError = IMAGE_ERROR_INVALID_SUBSYSTEM;
      return RETURN_LOAD_ERROR;
    }

    //
    // If the image does not contain relocations, and the requested load address
    // is not the linked address, then return an error.
    //
    if (CheckContext.ImageAddress != ImageContext->ImageAddress) {
      ImageContext->ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS;
      return RETURN_INVALID_PARAMETER;
    }
  }

  //
  // Make sure the allocated space has the proper section alignment
  //
  if (!(ImageContext->IsTeImage)) {
    if ((ImageContext->ImageAddress & (CheckContext.SectionAlignment - 1)) != 0) {
      ImageContext->ImageError = IMAGE_ERROR_INVALID_SECTION_ALIGNMENT;
      return RETURN_INVALID_PARAMETER;
    }
  }

  //
  // Read the entire PE/COFF or TE header into memory
  //
  if (!(ImageContext->IsTeImage)) {
    Status = ImageContext->ImageRead (
                             ImageContext->Handle,
                             0,
                             &ImageContext->SizeOfHeaders,
                             (VOID *)(UINTN)ImageContext->ImageAddress
                             );

    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)ImageContext->ImageAddress + ImageContext->PeCoffHeaderOffset);

    FirstSection = (EFI_IMAGE_SECTION_HEADER *)(
                                                (UINTN)ImageContext->ImageAddress +
                                                ImageContext->PeCoffHeaderOffset +
                                                sizeof (UINT32) +
                                                sizeof (EFI_IMAGE_FILE_HEADER) +
                                                Hdr.Pe32->FileHeader.SizeOfOptionalHeader
                                                );
    NumberOfSections = (UINTN)(Hdr.Pe32->FileHeader.NumberOfSections);
    TeStrippedOffset = 0;
  } else {
    Status = ImageContext->ImageRead (
                             ImageContext->Handle,
                             0,
                             &ImageContext->SizeOfHeaders,
                             (void *)(UINTN)ImageContext->ImageAddress
                             );

    Hdr.Te       = (EFI_TE_IMAGE_HEADER *)(UINTN)(ImageContext->ImageAddress);
    FirstSection = (EFI_IMAGE_SECTION_HEADER *)(
                                                (UINTN)ImageContext->ImageAddress +
                                                sizeof (EFI_TE_IMAGE_HEADER)
                                                );
    NumberOfSections = (UINTN)(Hdr.Te->NumberOfSections);
    TeStrippedOffset = (UINT32)Hdr.Te->StrippedSize - sizeof (EFI_TE_IMAGE_HEADER);
  }

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
    Base = PeCoffLoaderImageAddress (ImageContext, Section->VirtualAddress, TeStrippedOffset);
    End  = PeCoffLoaderImageAddress (ImageContext, Section->VirtualAddress + Section->Misc.VirtualSize - 1, TeStrippedOffset);

    //
    // If the size of the section is non-zero and the base address or end address resolved to 0, then fail.
    //
    if ((Size > 0) && ((Base == NULL) || (End == NULL))) {
      ImageContext->ImageError = IMAGE_ERROR_SECTION_NOT_LOADED;
      return RETURN_LOAD_ERROR;
    }

    // MU_CHANGE - CodeQL change
    if ((Section->SizeOfRawData > 0) && (Base != NULL)) {
      Status = ImageContext->ImageRead (
                               ImageContext->Handle,
                               Section->PointerToRawData - TeStrippedOffset,
                               &Size,
                               Base
                               );
      if (RETURN_ERROR (Status)) {
        ImageContext->ImageError = IMAGE_ERROR_IMAGE_READ;
        return Status;
      }
    }

    //
    // If raw size is less then virtual size, zero fill the remaining
    //
    // MU_CHANGE - CodeQL change - Assume Base is non-NULL if Size is non-zero
    if ((Size < Section->Misc.VirtualSize) && (Base != NULL)) {
      ZeroMem (Base + Size, Section->Misc.VirtualSize - Size);
    }

    //
    // Next Section
    //
    Section += 1;
  }

  //
  // Get image's entry point
  //
  if (!(ImageContext->IsTeImage)) {
    //
    // Sizes of AddressOfEntryPoint are different so we need to do this safely
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      ImageContext->EntryPoint = (PHYSICAL_ADDRESS)(UINTN)PeCoffLoaderImageAddress (
                                                            ImageContext,
                                                            (UINTN)Hdr.Pe32->OptionalHeader.AddressOfEntryPoint,
                                                            0
                                                            );
    } else {
      //
      // Use PE32+ offset
      //
      ImageContext->EntryPoint = (PHYSICAL_ADDRESS)(UINTN)PeCoffLoaderImageAddress (
                                                            ImageContext,
                                                            (UINTN)Hdr.Pe32Plus->OptionalHeader.AddressOfEntryPoint,
                                                            0
                                                            );
    }
  } else {
    ImageContext->EntryPoint = (PHYSICAL_ADDRESS)(UINTN)PeCoffLoaderImageAddress (
                                                          ImageContext,
                                                          (UINTN)Hdr.Te->AddressOfEntryPoint,
                                                          TeStrippedOffset
                                                          );
  }

  //
  // Determine the size of the fixup data
  //
  // Per the PE/COFF spec, you can't assume that a given data directory
  // is present in the image. You have to check the NumberOfRvaAndSizes in
  // the optional header to verify a desired directory entry is there.
  //
  if (!(ImageContext->IsTeImage)) {
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
      //
      // Use PE32+ offset
      //
      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    //
    // Must use UINT64 here, because there might a case that 32bit loader to load 64bit image.
    //
    if (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      ImageContext->FixupDataSize = DirectoryEntry->Size / sizeof (UINT16) * sizeof (UINT64);
    } else {
      ImageContext->FixupDataSize = 0;
    }
  } else {
    DirectoryEntry              = &Hdr.Te->DataDirectory[0];
    ImageContext->FixupDataSize = DirectoryEntry->Size / sizeof (UINT16) * sizeof (UINT64);
  }

  //
  // Consumer must allocate a buffer for the relocation fixup log.
  // Only used for runtime drivers.
  //
  ImageContext->FixupData = NULL;

  //
  // Load the Codeview information if present
  //
  if (ImageContext->DebugDirectoryEntryRva != 0) {
    DebugEntry = PeCoffLoaderImageAddress (
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
      ImageContext->CodeView = PeCoffLoaderImageAddress (ImageContext, TempDebugEntryRva, TeStrippedOffset);
      if (ImageContext->CodeView == NULL) {
        ImageContext->ImageError = IMAGE_ERROR_FAILED_RELOCATION;
        return RETURN_LOAD_ERROR;
      }

      if (DebugEntry->RVA == 0) {
        Size   = DebugEntry->SizeOfData;
        Status = ImageContext->ImageRead (
                                 ImageContext->Handle,
                                 DebugEntry->FileOffset - TeStrippedOffset,
                                 &Size,
                                 ImageContext->CodeView
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

        DebugEntry->RVA = TempDebugEntryRva;
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
  // Get Image's HII resource section
  //
  ImageContext->HiiResourceData = 0;
  if (!(ImageContext->IsTeImage)) {
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE];
    } else {
      //
      // Use PE32+ offset
      //
      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE];
    }

    if ((NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE) && (DirectoryEntry->Size != 0)) {
      Base = PeCoffLoaderImageAddress (ImageContext, DirectoryEntry->VirtualAddress, 0);
      if (Base != NULL) {
        ResourceDirectory = (EFI_IMAGE_RESOURCE_DIRECTORY *)Base;
        Offset            = sizeof (EFI_IMAGE_RESOURCE_DIRECTORY) + sizeof (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY) *
                            (ResourceDirectory->NumberOfNamedEntries + ResourceDirectory->NumberOfIdEntries);
        if (Offset > DirectoryEntry->Size) {
          ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
          return RETURN_UNSUPPORTED;
        }

        ResourceDirectoryEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY *)(ResourceDirectory + 1);

        for (Index = 0; Index < ResourceDirectory->NumberOfNamedEntries; Index++) {
          if (ResourceDirectoryEntry->u1.s.NameIsString) {
            //
            // Check the ResourceDirectoryEntry->u1.s.NameOffset before use it.
            //
            if (ResourceDirectoryEntry->u1.s.NameOffset >= DirectoryEntry->Size) {
              ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
              return RETURN_UNSUPPORTED;
            }

            ResourceDirectoryString = (EFI_IMAGE_RESOURCE_DIRECTORY_STRING *)(Base + ResourceDirectoryEntry->u1.s.NameOffset);
            String                  = &ResourceDirectoryString->String[0];

            if ((ResourceDirectoryString->Length == 3) &&
                (String[0] == L'H') &&
                (String[1] == L'I') &&
                (String[2] == L'I'))
            {
              //
              // Resource Type "HII" found
              //
              if (ResourceDirectoryEntry->u2.s.DataIsDirectory) {
                //
                // Move to next level - resource Name
                //
                if (ResourceDirectoryEntry->u2.s.OffsetToDirectory >= DirectoryEntry->Size) {
                  ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
                  return RETURN_UNSUPPORTED;
                }

                ResourceDirectory = (EFI_IMAGE_RESOURCE_DIRECTORY *)(Base + ResourceDirectoryEntry->u2.s.OffsetToDirectory);
                Offset            = ResourceDirectoryEntry->u2.s.OffsetToDirectory + sizeof (EFI_IMAGE_RESOURCE_DIRECTORY) +
                                    sizeof (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory->NumberOfNamedEntries + ResourceDirectory->NumberOfIdEntries);
                if (Offset > DirectoryEntry->Size) {
                  ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
                  return RETURN_UNSUPPORTED;
                }

                ResourceDirectoryEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY *)(ResourceDirectory + 1);

                if (ResourceDirectoryEntry->u2.s.DataIsDirectory) {
                  //
                  // Move to next level - resource Language
                  //
                  if (ResourceDirectoryEntry->u2.s.OffsetToDirectory >= DirectoryEntry->Size) {
                    ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
                    return RETURN_UNSUPPORTED;
                  }

                  ResourceDirectory = (EFI_IMAGE_RESOURCE_DIRECTORY *)(Base + ResourceDirectoryEntry->u2.s.OffsetToDirectory);
                  Offset            = ResourceDirectoryEntry->u2.s.OffsetToDirectory + sizeof (EFI_IMAGE_RESOURCE_DIRECTORY) +
                                      sizeof (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory->NumberOfNamedEntries + ResourceDirectory->NumberOfIdEntries);
                  if (Offset > DirectoryEntry->Size) {
                    ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
                    return RETURN_UNSUPPORTED;
                  }

                  ResourceDirectoryEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY *)(ResourceDirectory + 1);
                }
              }

              //
              // Now it ought to be resource Data
              //
              if (!ResourceDirectoryEntry->u2.s.DataIsDirectory) {
                if (ResourceDirectoryEntry->u2.OffsetToData >= DirectoryEntry->Size) {
                  ImageContext->ImageError = IMAGE_ERROR_UNSUPPORTED;
                  return RETURN_UNSUPPORTED;
                }

                ResourceDataEntry             = (EFI_IMAGE_RESOURCE_DATA_ENTRY *)(Base + ResourceDirectoryEntry->u2.OffsetToData);
                ImageContext->HiiResourceData = (PHYSICAL_ADDRESS)(UINTN)PeCoffLoaderImageAddress (ImageContext, ResourceDataEntry->OffsetToData, 0);
                break;
              }
            }
          }

          ResourceDirectoryEntry++;
        }
      }
    }
  }

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
