/** @file
  Defines function definitions for validating a loaded PE/COFF image post execution
  against an auxiliary file (defined in SeaAuxiliary.h) that contains multiple
  auxiliary validation entries. A validation entry specifies a specific region in the
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
#include <IndustryStandard/PeImage.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffValidationLib.h>
#include <Library/SafeIntLib.h>

#define CODE_SECTION_MUST_HAVE_ATTRIBUTES     (EFI_MEMORY_RO | EFI_MEMORY_SP)
#define CODE_SECTION_MUST_NOT_ATTRIBUTES      (EFI_MEMORY_XP | EFI_MEMORY_RP)
#define RW_DATA_SECTION_MUST_HAVE_ATTRIBUTES  (EFI_MEMORY_SP | EFI_MEMORY_XP)
#define RW_DATA_SECTION_MUST_NOT_ATTRIBUTES   (EFI_MEMORY_RO | EFI_MEMORY_RP)
#define R_DATA_SECTION_MUST_HAVE_ATTRIBUTES   (EFI_MEMORY_RO | EFI_MEMORY_SP | EFI_MEMORY_XP)
#define R_DATA_SECTION_MUST_NOT_ATTRIBUTES    (EFI_MEMORY_RP)

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
  @param[out] MemAttribute   Pointer to hold inspection result. Should not be used if return
                             value is not EFI_SUCCESS.

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
  Status = SafeUintnAdd (Size, (UINTN)(Address - AlignedAddress), &Size);
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
  Inspect the PE/COFF image to check if it is valid.

  @param ImageBase      The base address of the image.
  @param ImageSize      The size of the image.
  @param PageTableBase  The base address of the page table.

  @return EFI_STATUS    The status of the inspection.
                        EFI_SUCCESS if the image is valid.
**/
EFI_STATUS
EFIAPI
PeCoffInspectImageMemory (
  IN EFI_PHYSICAL_ADDRESS  ImageBase,
  IN UINT64                ImageSize,
  IN UINT64                PageTableBase
  )
{
  UINTN                                Index;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT32                               SectionAlignment;
  EFI_IMAGE_SECTION_HEADER             *Section;
  EFI_STATUS                           Status;
  UINT64                               SectionStart;
  UINT64                               SectionEnd;
  UINT64                               PageTableAttributes;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;

  DosHdr             = (EFI_IMAGE_DOS_HEADER *)(UINTN)ImageBase;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  if (PeCoffHeaderOffset >= ImageSize) {
    DEBUG ((DEBUG_ERROR, "%a PeCoffHeaderOffset invalid - 0x%x\n", __func__, PeCoffHeaderOffset));
    Status = EFI_COMPROMISED_DATA;
    goto Exit;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(UINTN)(ImageBase + PeCoffHeaderOffset);

  // Get SectionAlignment
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    SectionAlignment = Hdr.Pe32->OptionalHeader.SectionAlignment;
  } else {
    SectionAlignment = Hdr.Pe32Plus->OptionalHeader.SectionAlignment;
  }

  if (SectionAlignment & (RUNTIME_PAGE_ALLOCATION_GRANULARITY - 1)) {
    DEBUG ((DEBUG_ERROR, "%a SectionAlignment invalid - 0x%x\n", __func__, SectionAlignment));
    Status = EFI_COMPROMISED_DATA;
    goto Exit;
  }

  Section = (EFI_IMAGE_SECTION_HEADER *)(
                                         (UINT8 *)(UINTN)ImageBase +
                                         PeCoffHeaderOffset +
                                         sizeof (UINT32) +
                                         sizeof (EFI_IMAGE_FILE_HEADER) +
                                         Hdr.Pe32->FileHeader.SizeOfOptionalHeader
                                         );

  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    SectionStart = (UINT64)ImageBase + Section[Index].VirtualAddress;
    SectionEnd   = SectionStart + ALIGN_VALUE (Section[Index].SizeOfRawData, SectionAlignment);

    if ((SectionStart < ImageBase) || (SectionEnd > ImageBase + ImageSize) || (SectionEnd < SectionStart)) {
      DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx is invalid\n", __func__, SectionStart, SectionEnd));
      Status = EFI_COMPROMISED_DATA;
      goto Exit;
    }

    DEBUG_CODE_BEGIN ();
    DEBUG ((DEBUG_INFO, "  Section - '%c%c%c%c%c%c%c%c'\n", Section[Index].Name[0], Section[Index].Name[1], Section[Index].Name[2], Section[Index].Name[3], Section[Index].Name[4], Section[Index].Name[5], Section[Index].Name[6], Section[Index].Name[7]));
    DEBUG ((DEBUG_INFO, "  Characteristics      - 0x%08x\n", Section[Index].Characteristics));
    DEBUG ((DEBUG_INFO, "  VirtualSize          - 0x%08x\n", Section[Index].Misc.VirtualSize));
    DEBUG ((DEBUG_INFO, "  SizeOfRawData        - 0x%08x\n", Section[Index].SizeOfRawData));
    DEBUG ((DEBUG_INFO, "  PointerToRawData     - 0x%08x\n", Section[Index].PointerToRawData));
    DEBUG ((DEBUG_INFO, "  VirtualAddress       - 0x%08x\n", Section[Index].VirtualAddress));
    DEBUG ((DEBUG_INFO, "  PointerToRelocations - 0x%08x\n", Section[Index].PointerToRelocations));
    DEBUG ((DEBUG_INFO, "  PointerToLinenumbers - 0x%08x\n", Section[Index].PointerToLinenumbers));
    DEBUG ((DEBUG_INFO, "  NumberOfRelocations  - 0x%08x\n", Section[Index].NumberOfRelocations));
    DEBUG ((DEBUG_INFO, "  NumberOfLinenumbers  - 0x%08x\n", Section[Index].NumberOfLinenumbers));
    DEBUG_CODE_END ();

    // Check each section
    if (Section[Index].Characteristics & EFI_IMAGE_SCN_CNT_CODE) {
      // Code section, it should not contain data
      if ((Section[Index].Characteristics &
           (EFI_IMAGE_SCN_CNT_INITIALIZED_DATA | EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA)) != 0)
      {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx contains code and data\n", __func__, SectionStart, SectionEnd));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      // Check if the section is executable
      if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) == 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx is not executable\n", __func__, SectionStart, SectionEnd));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      // Check if the section is writable
      if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_WRITE) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx is writable\n", __func__, SectionStart, SectionEnd));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      // Check the section memory attribute
      Status = GetMemoryAttributes (PageTableBase, SectionStart, SectionEnd - SectionStart, &PageTableAttributes);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a GetMemoryAttributes failed - %r\n", __func__, Status));
        goto Exit;
      }

      if ((PageTableAttributes & CODE_SECTION_MUST_NOT_ATTRIBUTES) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx has invalid attributes - 0x%llx\n", __func__, SectionStart, SectionEnd, PageTableAttributes));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      if ((PageTableAttributes & CODE_SECTION_MUST_HAVE_ATTRIBUTES) != CODE_SECTION_MUST_HAVE_ATTRIBUTES) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx has invalid attributes - 0x%llx\n", __func__, SectionStart, SectionEnd, PageTableAttributes));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }
    } else if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_WRITE) == 0) {
      // Read-only data section, it should not contain executable memory
      if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx contains data and code\n", __func__, SectionStart, SectionEnd));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      // Read-only data section, should not have uninitialized data
      if ((Section[Index].Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx contains uninitialized data\n", __func__, SectionStart, SectionEnd));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      // Check the section memory attribute
      Status = GetMemoryAttributes (PageTableBase, SectionStart, SectionEnd - SectionStart, &PageTableAttributes);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a GetMemoryAttributes failed - %r\n", __func__, Status));
        goto Exit;
      }

      if ((PageTableAttributes & R_DATA_SECTION_MUST_NOT_ATTRIBUTES) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx has invalid attributes - 0x%llx\n", __func__, SectionStart, SectionEnd, PageTableAttributes));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      if ((PageTableAttributes & R_DATA_SECTION_MUST_HAVE_ATTRIBUTES) != R_DATA_SECTION_MUST_HAVE_ATTRIBUTES) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx has invalid attributes - 0x%llx\n", __func__, SectionStart, SectionEnd, PageTableAttributes));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }
    } else {
      // RW data section, should not have executable memory
      if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx contains data and code\n", __func__, SectionStart, SectionEnd));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      // Check the section memory attribute
      Status = GetMemoryAttributes (PageTableBase, SectionStart, SectionEnd - SectionStart, &PageTableAttributes);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a GetMemoryAttributes failed - %r\n", __func__, Status));
        goto Exit;
      }

      if ((PageTableAttributes & RW_DATA_SECTION_MUST_NOT_ATTRIBUTES) != 0) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx has invalid attributes - 0x%llx\n", __func__, SectionStart, SectionEnd, PageTableAttributes));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }

      if ((PageTableAttributes & RW_DATA_SECTION_MUST_HAVE_ATTRIBUTES) != RW_DATA_SECTION_MUST_HAVE_ATTRIBUTES) {
        DEBUG ((DEBUG_ERROR, "%a Section 0x%llx-0x%llx has invalid attributes - 0x%llx\n", __func__, SectionStart, SectionEnd, PageTableAttributes));
        Status = EFI_COMPROMISED_DATA;
        goto Exit;
      }
    }
  }

Exit:
  return Status;
}

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is not a zero buffer.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   One of the input parameters is a null pointer.
  @retval EFI_COMPROMISED_DATA    The provided header has an invalid signature
  @retval EFI_SECURITY_VIOLATION  The specified buffer in the target image is all zero.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationNonZero (
  IN CONST VOID                           *TargetImage,
  IN CONST IMAGE_VALIDATION_ENTRY_HEADER  *Hdr
  )
{
  EFI_STATUS  Status;

  if ((TargetImage == NULL) || (Hdr == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a: At least one invalid input parameter: TargetImage 0x%p, Hdr 0x%p\n", __func__, TargetImage, Hdr));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if ((Hdr->EntrySignature != IMAGE_VALIDATION_ENTRY_SIGNATURE) || (Hdr->ValidationType != IMAGE_VALIDATION_ENTRY_TYPE_NON_ZERO)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Invalid entry signature 0x%x or type 0x%x at 0x%p\n",
      __func__,
      Hdr->EntrySignature,
      Hdr->ValidationType,
      Hdr
      ));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

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
  @retval EFI_INVALID_PARAMETER   One of the input parameters is a null pointer.
  @retval EFI_COMPROMISED_DATA    The provided header has an invalid signature
  @retval EFI_COMPROMISED_DATA    The content to match against overflows the auxiliary file.
  @retval EFI_SECURITY_VIOLATION  The specified buffer in the target image does not match the reference data.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationContent (
  IN CONST VOID                           *TargetImage,
  IN CONST IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN CONST IMAGE_VALIDATION_DATA_HEADER   *ImageValidationHdr
  )
{
  IMAGE_VALIDATION_CONTENT  *ContentHdr;
  EFI_STATUS                Status;

  if ((TargetImage == NULL) || (Hdr == NULL) || (ImageValidationHdr == NULL)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: At least one invalid input parameter: TargetImage 0x%p, Hdr 0x%p, ImageValidationHdr 0x%p\n",
      __func__,
      TargetImage,
      Hdr,
      ImageValidationHdr
      ));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if ((Hdr->EntrySignature != IMAGE_VALIDATION_ENTRY_SIGNATURE) || (Hdr->ValidationType != IMAGE_VALIDATION_ENTRY_TYPE_CONTENT)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Invalid entry signature 0x%x or type 0x%x at 0x%p\n",
      __func__,
      Hdr->EntrySignature,
      Hdr->ValidationType,
      Hdr
      ));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

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
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p: Content mismatch in image at address 0x%p\n", __func__, ContentHdr, ContentHdr->TargetContent));

    DEBUG ((DEBUG_ERROR, "%a: Expected content: ", __func__));
    for (UINTN Index = 0; Index < Hdr->Size; Index++) {
      DEBUG ((DEBUG_ERROR, "%02x ", ContentHdr->TargetContent[Index]));
    }

    DEBUG ((DEBUG_ERROR, "\n"));

    DEBUG ((DEBUG_ERROR, "%a: Actual content: ", __func__));
    for (UINTN Index = 0; Index < Hdr->Size; Index++) {
      DEBUG ((DEBUG_ERROR, "%02x ", ((UINT8 *)TargetImage + Hdr->Offset)[Index]));
    }

    DEBUG ((DEBUG_ERROR, "\n"));

    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  belongs to a user page that is mapped inside MM and the page attributes match the requirements specified
  by the validation entry.

  @param[in] TargetImage    The pointer to the target image buffer.
  @param[in] Hdr            The header of the validation entry.
  @param[in] PageTableBase  The base address of the page table.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   One of the input parameters is a null pointer.
  @retval EFI_INVALID_PARAMETER   The validation entry has invalid must have and must not have attributes.
  @retval EFI_INVALID_PARAMETER   The validation entry data size is invalid. It must be a pointer size.
  @retval EFI_COMPROMISED_DATA   The validation entry has invalid signature.
  @retval EFI_SECURITY_VIOLATION  The target image does not meet the memory attribute requirements.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationMemAttr (
  IN CONST VOID                           *TargetImage,
  IN CONST IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN EFI_PHYSICAL_ADDRESS                 PageTableBase
  )
{
  UINT64                     MemAttr;
  IMAGE_VALIDATION_MEM_ATTR  *MemAttrHdr;
  EFI_PHYSICAL_ADDRESS       AddrInTarget;
  EFI_STATUS                 Status;

  if ((TargetImage == NULL) || (Hdr == NULL)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: At least one invalid input parameter: TargetImage 0x%p, Hdr 0x%p\n",
      __func__,
      TargetImage,
      Hdr
      ));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if ((Hdr->EntrySignature != IMAGE_VALIDATION_ENTRY_SIGNATURE) || (Hdr->ValidationType != IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR)) {
    DEBUG ((DEBUG_ERROR, "%a: Invalid entry signature 0x%x or type 0x%x at 0x%p\n", __func__, Hdr->EntrySignature, Hdr->ValidationType, Hdr));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

  MemAttrHdr = (IMAGE_VALIDATION_MEM_ATTR *)Hdr;
  if ((MemAttrHdr->TargetMemoryAttributeMustHave == 0) && (MemAttrHdr->TargetMemoryAttributeMustNotHave == 0)) {
    DEBUG ((DEBUG_ERROR, "%a: Entry 0x%p cannot have zero for must and must not have attribute values\n", __func__, MemAttrHdr));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (Hdr->Size > sizeof (AddrInTarget)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Current entry 0x%p has invalid size of0x%x, max is 0x%x\n",
      __func__,
      Hdr,
      Hdr->Size,
      sizeof (AddrInTarget)
      ));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  AddrInTarget = 0;
  CopyMem (&AddrInTarget, (UINT8 *)TargetImage + Hdr->Offset, Hdr->Size);
  Status = InspectTargetRangeAttribute (PageTableBase, AddrInTarget, (UINTN)MemAttrHdr->TargetMemorySize, &MemAttr);
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

  @param[in] OriginalImageBaseAddress  The pointer to the original image buffer.
  @param[in] Hdr                       The header of the validation entry.
  @param[in] OriginalImageLoadAddress  The load address of the original image buffer. Should be the same as
                                       the pointer value of OriginalImageBaseAddress for runtime validation.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   One of the input parameters is a null pointer.
  @retval EFI_INVALID_PARAMETER   The validation entry has an invalid size.
  @retval EFI_COMPROMISED_DATA    The validation entry has an invalid signature.
  @retval EFI_SECURITY_VIOLATION  The target image does not match the content in the original image buffer.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationSelfRef (
  IN CONST VOID                           *OriginalImageBaseAddress,
  IN CONST IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN EFI_PHYSICAL_ADDRESS                 OriginalImageLoadAddress
  )
{
  IMAGE_VALIDATION_SELF_REF  *SelfRefHdr;
  EFI_STATUS                 Status;
  EFI_PHYSICAL_ADDRESS       AddrInTarget;
  EFI_PHYSICAL_ADDRESS       AddrInOrigin;

  if ((Hdr == NULL) || (OriginalImageBaseAddress == NULL)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: At least one invalid input parameter: OriginalImageBaseAddress 0x%p, Hdr 0x%p\n",
      __func__,
      OriginalImageBaseAddress,
      Hdr
      ));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if ((Hdr->EntrySignature != IMAGE_VALIDATION_ENTRY_SIGNATURE) || (Hdr->ValidationType != IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF)) {
    DEBUG ((DEBUG_ERROR, "%a: Invalid entry signature 0x%x or type 0x%x at 0x%p\n", __func__, Hdr->EntrySignature, Hdr->ValidationType, Hdr));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

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
  CopyMem (&AddrInTarget, (UINT8 *)OriginalImageBaseAddress + Hdr->Offset, Hdr->Size);

  // Compare the addresses RVAs rather than the actual addresses, to support runtime and host-based validation.
  AddrInOrigin = (EFI_PHYSICAL_ADDRESS)SelfRefHdr->TargetOffset;
  AddrInTarget = AddrInTarget - OriginalImageLoadAddress;

  if (AddrInTarget != AddrInOrigin) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p: Pointer mismatch:\n", __func__, Hdr));
    DEBUG ((DEBUG_ERROR, "%a: Expected pointer RVA: 0x%p\n", __func__, AddrInOrigin));
    DEBUG ((DEBUG_ERROR, "%a: Actual pointer RVA: 0x%p\n", __func__, AddrInTarget));

    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  Validates a specific region in the target image buffer denoted by [Hdr->Offset: Hdr->Offset + Hdr->Size]
  is a pointer, and that the pointer is not NULL. Will validate if the pointer is within the MSEG, which will
  pass or fail based on the validation entry's `in_mseg` field.

  @param[in] TargetImage  The pointer to the target image buffer.
  @param[in] Hdr          The header of the validation entry.
  @param[in] MsegBase     The base address of the MSEG.
  @param[in] MsegSize     The size of the MSEG.

  @retval EFI_SUCCESS             The target image passes the validation.
  @retval EFI_INVALID_PARAMETER   One of the input parameters is a null pointer.
  @retval EFI_INVALID_PARAMETER   The validation entry has an invalid size.
  @retval EFI_COMPROMISED_DATA    The validation entry has invalid signature.
  @retval EFI_SECURITY_VIOLATION  The target image does not match the content in the original image buffer.
**/
EFI_STATUS
EFIAPI
PeCoffImageValidationPointer (
  IN CONST VOID                           *TargetImage,
  IN CONST IMAGE_VALIDATION_ENTRY_HEADER  *Hdr,
  IN EFI_PHYSICAL_ADDRESS                 MsegBase,
  IN UINTN                                MsegSize
  )
{
  EFI_STATUS                Status;
  IMAGE_VALIDATION_POINTER  *PointerHdr;
  BOOLEAN                   InMseg;
  EFI_PHYSICAL_ADDRESS      AddrInTarget;

  if ((TargetImage == NULL) || (Hdr == NULL)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: At least one invalid input parameter: TargetImage 0x%p, Hdr 0x%p\n",
      __func__,
      TargetImage,
      Hdr
      ));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if ((Hdr->EntrySignature != IMAGE_VALIDATION_ENTRY_SIGNATURE) || (Hdr->ValidationType != IMAGE_VALIDATION_ENTRY_TYPE_POINTER)) {
    DEBUG ((DEBUG_ERROR, "%a: Invalid entry signature 0x%x or type 0x%x at 0x%p\n", __func__, Hdr->EntrySignature, Hdr->ValidationType, Hdr));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

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

  PointerHdr = (IMAGE_VALIDATION_POINTER *)Hdr;
  if (PointerHdr->InMseg > 1) {
    DEBUG ((DEBUG_ERROR, "%a: Current entry 0x%p is of type pointer but InMseg value is not 0 or 1: 0x%x\n", __func__, Hdr, PointerHdr->InMseg));
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

  AddrInTarget = 0;
  CopyMem (&AddrInTarget, (UINT8 *)TargetImage + Hdr->Offset, Hdr->Size);
  InMseg = ((UINTN)AddrInTarget >= MsegBase) && ((UINTN)AddrInTarget < MsegBase + MsegSize);
  if ((BOOLEAN)PointerHdr->InMseg != InMseg) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: Current entry 0x%p is expected to be a pointer either inside or outside of MSEG. MSEG Start: 0x%x, MSEG Size: 0x%x, Pointer: 0x%p, Expected InMSEG?: %x\n",
      __func__,
      Hdr,
      MsegBase,
      MsegSize,
      (UINT8 *)TargetImage + Hdr->Offset,
      PointerHdr->InMseg
      ));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}
