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
#include <Uefi.h>
#include <Base.h>
#include <SeaAuxiliary.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffValidationLib.h>
#include <Library/SafeIntLib.h>

EFI_STATUS
EFIAPI
GetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  PageTableBase,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  OUT UINT64                *Attributes
  );

/**
  Helper function that will evaluate the page where the input address is located belongs to a
  user page that is mapped inside MM.

  @param[in]  PageTableBase  The base address of the page table.
  @param[in]  Address        Target address to be inspected.
  @param[in]  Size           Address range to be inspected.
  @param[out] MemAttribute   Pointer to hold inspection result, TRUE if the region is in User pages, FALSE if
                             the page is in supervisor pages. Should not be used if return value is not EFI_SUCCESS.

  @return The result of inspection operation.
**/
EFI_STATUS
InspectTargetRangeAttribute (
  IN  EFI_PHYSICAL_ADDRESS  PageTableBase,
  IN  EFI_PHYSICAL_ADDRESS  Address,
  IN  UINTN                 Size,
  OUT UINT64                *MemAttribute
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  AlignedAddress;
  UINT64                Attributes;

  if ((Address < EFI_PAGE_SIZE) || (Size == 0) || (MemAttribute == NULL)) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  AlignedAddress = ALIGN_VALUE (Address - EFI_PAGE_SIZE + 1, EFI_PAGE_SIZE);

  // To cover head portion from "Address" alignment adjustment
  Status = SafeUintnAdd (Size, Address - AlignedAddress, &Size);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // To cover the tail portion of requested buffer range
  Status = SafeUintnAdd (Size, EFI_PAGE_SIZE - 1, &Size);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Size &= ~(EFI_PAGE_SIZE - 1);

  // Go through page table and grab the entry attribute
  Status = GetMemoryAttributes (PageTableBase, AlignedAddress, Size, &Attributes);
  if (!EFI_ERROR (Status)) {
    *MemAttribute = Attributes;
    goto Done;
  }

Done:
  return Status;
}

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
  )
{
  EFI_STATUS  Status;

  if (IsZeroBuffer ((UINT8 *)TargetImage + Hdr->Offset, Hdr->Size)) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry range 0x%p: 0x%x is all 0s\n", __func__, (UINT8 *)TargetImage + Hdr->Offset, Hdr->Size));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

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
  )
{
  IMAGE_VALIDATION_CONTENT  *ContentHdr;
  EFI_STATUS                Status;

  ContentHdr = (IMAGE_VALIDATION_CONTENT *)Hdr;
  // Ensure "Content" in the header (TargetContent) does not overflow the Auxiliary file buffer.
  if ((UINT8 *)ContentHdr + sizeof (*ContentHdr) + Hdr->Size > (UINT8 *)ImageValidationHdr + ImageValidationHdr->Size) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Current entry range 0x%p: 0x%x exceeds reference data limit 0x%x\n",
      __func__,
      ContentHdr,
      sizeof (*ContentHdr) + Hdr->Size,
      (UINT8 *)ImageValidationHdr + ImageValidationHdr->Size
      ));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

  if (CompareMem ((UINT8 *)TargetImage + Hdr->Offset, ContentHdr->TargetContent, Hdr->Size) != 0) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry range 0x%p: 0x%x does not match input content at 0x%p\n", __func__, ContentHdr, Hdr->Size, ContentHdr->TargetContent));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

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
  )
{
  UINT64                     MemAttr;
  IMAGE_VALIDATION_MEM_ATTR  *MemAttrHdr;
  EFI_PHYSICAL_ADDRESS       AddrInTarget;
  EFI_STATUS                 Status;

  MemAttrHdr = (IMAGE_VALIDATION_MEM_ATTR *)Hdr;
  if ((MemAttrHdr->TargetMemoryAttributeMustHave == 0) && (MemAttrHdr->TargetMemoryAttributeMustNotHave == 0)) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p has invalid must have 0x%x and must not have 0x%x\n", __func__, MemAttrHdr, MemAttrHdr->TargetMemoryAttributeMustHave, MemAttrHdr->TargetMemoryAttributeMustNotHave));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (Hdr->Size > sizeof (AddrInTarget)) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p has invalid size: 0x%x\n", __func__, Hdr, Hdr->Size));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  AddrInTarget = 0;
  CopyMem (&AddrInTarget, (UINT8 *)TargetImage + Hdr->Offset, Hdr->Size);
  Status = InspectTargetRangeAttribute (PageTableBase, AddrInTarget, MemAttrHdr->TargetMemorySize, &MemAttr);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to read memory attribute of 0x%p: 0x%x for entry at 0x%p - %r\n", __func__, AddrInTarget, MemAttrHdr->TargetMemorySize, MemAttrHdr, Status));
    goto Done;
  }

  // Check if the memory attributes of the target image meet the requirements
  if (((MemAttr & MemAttrHdr->TargetMemoryAttributeMustHave) != MemAttrHdr->TargetMemoryAttributeMustHave) &&
      ((MemAttr & MemAttrHdr->TargetMemoryAttributeMustNotHave) != 0))
  {
    DEBUG ((DEBUG_ERROR, "%a: Current entry range 0x%p: 0x%x attribute 0x%x violated aux file specification must have 0x%x and must not have 0x%x\n", __func__, Hdr, Hdr->Size, MemAttr, MemAttrHdr->TargetMemoryAttributeMustHave, MemAttrHdr->TargetMemoryAttributeMustNotHave));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

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
  )
{
  IMAGE_VALIDATION_SELF_REF  *SelfRefHdr;
  EFI_STATUS                 Status;
  EFI_PHYSICAL_ADDRESS       AddrInTarget;
  EFI_PHYSICAL_ADDRESS       AddrInOrigin;

  SelfRefHdr = (IMAGE_VALIDATION_SELF_REF *)Hdr;
  // For now, self reference is only valid for address type in x64 mode or below
  if (Hdr->Size > sizeof (EFI_PHYSICAL_ADDRESS)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Current entry 0x%p is self reference type but not 64 bit value %d\n",
      __func__,
      SelfRefHdr,
      Hdr->Size
      ));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  AddrInTarget = 0;
  CopyMem (&AddrInTarget, (UINT8 *)TargetImage + Hdr->Offset, Hdr->Size);
  AddrInOrigin = (EFI_PHYSICAL_ADDRESS)(UINTN)((UINT8 *)OriginalImageBaseAddress + SelfRefHdr->TargetOffset);

  if (AddrInTarget != AddrInOrigin) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Current entry at 0x%p regarding 0x%x should self reference 0x%x\n",
      __func__,
      Hdr,
      AddrInTarget,
      AddrInOrigin
      ));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

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
  )
{
  EFI_STATUS  Status;

  if (Hdr->Size > sizeof (UINTN)) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p is expected to be a pointer but has size 0x%x\n", __func__, Hdr, Hdr->Size));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if ((UINT8 *)((UINT8 *)TargetImage + Hdr->Offset) == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p is a NULL ptr\n", __func__, Hdr));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}
