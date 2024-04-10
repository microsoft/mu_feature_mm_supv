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
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef BASE_PECOFF_LIB_NEGATIVE_H_
#define BASE_PECOFF_LIB_NEGATIVE_H_

#define IMAGE_VALIDATION_ENTRY_TYPE_NONE      0x00000000
#define IMAGE_VALIDATION_ENTRY_TYPE_NON_ZERO  0x00000001
#define IMAGE_VALIDATION_ENTRY_TYPE_CONTENT   0x00000002
#define IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR  0x00000003
#define IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF  0x00000004

#define IMAGE_VALIDATION_DATA_SIGNATURE    SIGNATURE_32 ('V', 'A', 'L', 'D')
#define IMAGE_VALIDATION_ENTRY_SIGNATURE   SIGNATURE_32 ('E', 'N', 'T', 'R')

#pragma pack(1)

typedef struct {
  UINT32 Signature;
  UINT32 Offset;
} KEY_SYMBOL;

typedef struct {
  UINT32  HeaderSignature;
  UINT32  Size;
  UINT32  EntryCount;
  UINT32  OffsetToFirstEntry;
  UINT32  OffsetToFirstDefault;
  UINT32  KeySymbolCount;
  UINT32  OffsetToFirstKeySymbol;
} IMAGE_VALIDATION_DATA_HEADER;

typedef struct {
  UINT32  EntrySignature;
  UINT32  Offset; // Offset to the start of the target image
  UINT32  Size; // Size of this entry
  UINT32  ValidationType;
  UINT32  OffsetToDefault;
} IMAGE_VALIDATION_ENTRY_HEADER;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER   Header;
  UINT8                           TargetContent[];
} IMAGE_VALIDATION_CONTENT;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER   Header;
  UINT64                          TargetMemeorySize;
  UINT64                          TargetMemeoryAttributeMustHave;
  UINT64                          TargetMemeoryAttributeMustNotHave;
} IMAGE_VALIDATION_MEM_ATTR;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER   Header;
  UINT32                          TargetOffset;
} IMAGE_VALIDATION_SELF_REF;

#pragma pack()

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
RETURN_STATUS
EFIAPI
PeCoffLoaderRevertRelocateImage (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  );

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
  @param  Buffer                    The pointer to the buffer used to host unloaded PE/COFF image.
  @param  BufferSizePtr             On input, this holds the size of Buffer. On output, it holds the size
                                    of the image that was actually unloaded into Buffer.

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
  IN OUT  PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  OUT     UINTN                         *Buffer,
  IN OUT  UINTN                         *BufferSizePtr
  );

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
  );

/**
  Revert fixups and global data changes to an executed PE/COFF image that was loaded
  with PeCoffLoaderLoadImage() and relocated with PeCoffLoaderRelocateImage().

  @param[in]      OriginalImageBaseAddress  The pointer to the executed image buffer, the implementation
                                            should not touch the content of this buffer.
  @param[in,out]  TargetImage               The pointer to the target image buffer.
  @param[in]      TargetImageSize           The size of the target image buffer.
  @param[in]      ReferenceData             The pointer to the reference data buffer to assist .
  @param[in]      ReferenceDataSize         The size of the reference data buffer.

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
  );

#endif // BASE_PECOFF_LIB_NEGATIVE_H_
