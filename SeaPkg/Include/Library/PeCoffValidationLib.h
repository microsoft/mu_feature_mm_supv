/** @file
  Defines function definitions for validating a loaded PE/COFF image post execution
  against an auxiliary file (defined in SeaAuxiliary.h) that contains auxiliary
  multiple validation entries. A validation entry specifies a specific region in the
  target image buffer to validate against, a validation type to perform, and any
  necessary data to assist in the validation.

  There currently exists five validation types:
  - Non-Zero: Validates that the specified region in the target image buffer is not all zero.
  - Content: Validates that the specified region in the target image buffer matches the content in the reference data.
  - MemAttr: Validates that the specified region in the target image buffer belongs to a user page that is mapped inside MM
             and the page attributes match the requirements specified by the validation entry.
  - SelfRef: Validates that the specified region in the target image buffer matches the content in the original image buffer as
             specified by TargetOffset in the validation entry.
  - Pointer: Validates that the specified region in the target image buffer is a pointer, and that the pointer is not NULL.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef PECOFF_VALIDATION_LIB_H_
#define PECOFF_VALIDATION_LIB_H_

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is not a zero buffer.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_SECURITY_VIOLATION  The specified buffer in the target image is all zero.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationNonZero (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr
  );

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is the same as the content in the reference data.

  @param[in] TargetImage         The pointer to the target image buffer.
  @param[in] Hdr                 The header of the validation entry.
  @param[in] ImageValidationHdr  The pointer to the auxiliary file data buffer to assist.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_COMPROMISED_DATA    The content to match against overflows the auxiliary file.
  @retval EFI_SECURITY_VIOLATION  The specified buffer in the target image does not match the reference data.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationContent (
  IN VOID                                *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER       *Hdr,
  IN CONST IMAGE_VALIDATION_DATA_HEADER  *ImageValidationHdr
  );

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  belongs to a user page that is mapped inside MM and teh page attributes match the requirements specified
  by the validation entry.

  @param[in] TargetImage    The pointer to the target image buffer.
  @param[in] Hdr            The header of the validation entry.
  @param[in] PageTableBase  The base address of the page table.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   The validation entry has invalid must have and must not have attributes.
  @retval EFI_INVALID_PARAMETER   The validation entry data size is invalid. It must be a pointer size.
  @retval EFI_SECURITY_VIOLATION  The target image does not meet the memory attribute requirements.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationMemAttr (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN EFI_PHYSICAL_ADDRESS           PageTableBase
  );

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  matches the content in the original image buffer as specified by TargetOffset in the validation entry.

  @param[in] TargetImage               The pointer to the target image buffer.
  @param[in] Hdr                       The header of the validation entry.
  @param[in] OriginalImageBaseAddress  The pointer to the original image buffer.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   The validation entry has invalid size.
  @retval EFI_SECURITY_VIOLATION  The target image does not match the content in the original image buffer.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationSelfRef (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN VOID                           *OriginalImageBaseAddress
  );

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is a pointer, and that the pointer is not NULL.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   The validation entry has invalid size.
  @retval EFI_SECURITY_VIOLATION  The target image does not match the content in the original image buffer.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationPointer (
  IN VOID                           *TargetImage,
  IN IMAGE_VALIDATION_ENTRY_HEADER  *Hdr
  );

#endif // PECOFF_VALIDATION_LIB_H_
