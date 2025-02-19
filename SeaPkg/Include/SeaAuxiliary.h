/** @file -- SeaAuxiliary.h
  Defines necessary structures and constants for parsing auxiliary data for 
  PE/COFF image validation.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SEA_AUXILIARY_H_
#define SEA_AUXILIARY_H_

#define IMAGE_VALIDATION_ENTRY_TYPE_NONE      0x00000000
#define IMAGE_VALIDATION_ENTRY_TYPE_NON_ZERO  0x00000001
#define IMAGE_VALIDATION_ENTRY_TYPE_CONTENT   0x00000002
#define IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR  0x00000003
#define IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF  0x00000004
#define IMAGE_VALIDATION_ENTRY_TYPE_POINTER   0x00000005

#define IMAGE_VALIDATION_DATA_SIGNATURE   SIGNATURE_32 ('V', 'A', 'L', 'D')
#define IMAGE_VALIDATION_ENTRY_SIGNATURE  SIGNATURE_32 ('E', 'N', 'T', 'R')

#pragma pack(1)

typedef struct {
  UINT32    Signature;
  UINT32    Offset;
} KEY_SYMBOL;

typedef struct {
  UINT32    HeaderSignature;
  UINT32    Size;
  UINT32    EntryCount;
  UINT32    OffsetToFirstEntry;
  UINT32    OffsetToFirstDefault;
  UINT32    KeySymbolCount;
  UINT32    OffsetToFirstKeySymbol;
} IMAGE_VALIDATION_DATA_HEADER;

typedef struct {
  UINT32    EntrySignature;
  UINT32    Offset; // Offset to the start of the target image
  UINT32    Size;   // Size of this entry
  UINT32    ValidationType;
  UINT32    OffsetToDefault;
} IMAGE_VALIDATION_ENTRY_HEADER;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER    Header;
  UINT8                            TargetContent[];
} IMAGE_VALIDATION_CONTENT;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER    Header;
  UINT64                           TargetMemorySize;
  UINT64                           TargetMemoryAttributeMustHave;
  UINT64                           TargetMemoryAttributeMustNotHave;
} IMAGE_VALIDATION_MEM_ATTR;

typedef struct {
  IMAGE_VALIDATION_ENTRY_HEADER    Header;
  UINT32                           TargetOffset;
} IMAGE_VALIDATION_SELF_REF;

#pragma pack()

#endif // SEA_AUXILIARY_H_
