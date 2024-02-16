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
#ifndef BASE_PE_COFF_LIB_NEGATIVE_INT_H_
#define BASE_PE_COFF_LIB_NEGATIVE_INT_H_

#define IMAGE_VALIDATION_ENTRY_TYPE_NONE      0x00000000
#define IMAGE_VALIDATION_ENTRY_TYPE_NON_ZERO  0x00000001
#define IMAGE_VALIDATION_ENTRY_TYPE_CONTENT   0x00000002
#define IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR  0x00000003
#define IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF  0x00000004

#define IMAGE_VALIDATION_DATA_SIGNATURE    SIGNATURE_32 ('V', 'A', 'L', 'D')
#define IMAGE_VALIDATION_ENTRY_SIGNATURE   SIGNATURE_32 ('E', 'N', 'T', 'R')

#pragma pack(1)

typedef struct {
  UINT32  HeaderSignature;
  UINT32  Size;
  UINT32  EntryCount;
  UINT32  OffsetToFirstEntry;
  UINT32  OffsetToFirstDefault;
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
  UINT64                          TargetMemorySize;
  UINT32                          TargetMemeoryAttribute;
} IMAGE_VALIDATION_MEM_ATTR;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER   Header;
  UINT32                          TargetOffset;
} IMAGE_VALIDATION_SELF_REF;

#pragma pack()

#endif // BASE_PE_COFF_LIB_NEGATIVE_INT_H_
