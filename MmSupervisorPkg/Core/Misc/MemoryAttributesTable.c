/** @file
  PI SMM MemoryAttributes support

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Base.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/ImagePropertiesRecordLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffGetEntryPointLib.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"

#define PREVIOUS_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) - (Size)))

#define IMAGE_PROPERTIES_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('I','P','P','D')

typedef struct {
  UINT32        Signature;
  UINTN         ImageRecordCount;
  UINTN         CodeSegmentCountMax;
  LIST_ENTRY    ImageRecordList;
} IMAGE_PROPERTIES_PRIVATE_DATA;

IMAGE_PROPERTIES_PRIVATE_DATA  mImagePropertiesPrivateData = {
  IMAGE_PROPERTIES_PRIVATE_DATA_SIGNATURE,
  0,
  0,
  INITIALIZE_LIST_HEAD_VARIABLE (mImagePropertiesPrivateData.ImageRecordList)
};

#define EFI_MEMORY_ATTRIBUTES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA  BIT0

UINT64  mMemoryProtectionAttribute = EFI_MEMORY_ATTRIBUTES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA;

//
// Below functions are for MemoryMap
//

/**
  Merge continuous memory map entries whose have same attributes.

  @param[in, out]  MemoryMap              A pointer to the buffer in which firmware places
                                          the current memory map.
  @param[in, out]  MemoryMapSize          A pointer to the size, in bytes, of the
                                          MemoryMap buffer. On input, this is the size of
                                          the current memory map.  On output,
                                          it is the size of new memory map after merge.
  @param[in]       DescriptorSize         Size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.
**/
STATIC
VOID
MergeMemoryMap (
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN OUT UINTN                  *MemoryMapSize,
  IN UINTN                      DescriptorSize
  )
{
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEnd;
  UINT64                 MemoryBlockLength;
  EFI_MEMORY_DESCRIPTOR  *NewMemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *NextMemoryMapEntry;

  MemoryMapEntry    = MemoryMap;
  NewMemoryMapEntry = MemoryMap;
  MemoryMapEnd      = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + *MemoryMapSize);
  while ((UINTN)MemoryMapEntry < (UINTN)MemoryMapEnd) {
    CopyMem (NewMemoryMapEntry, MemoryMapEntry, sizeof (EFI_MEMORY_DESCRIPTOR));
    NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);

    do {
      MemoryBlockLength = LShiftU64 (MemoryMapEntry->NumberOfPages, EFI_PAGE_SHIFT);
      if (((UINTN)NextMemoryMapEntry < (UINTN)MemoryMapEnd) &&
          (MemoryMapEntry->Type == NextMemoryMapEntry->Type) &&
          (MemoryMapEntry->Attribute == NextMemoryMapEntry->Attribute) &&
          ((MemoryMapEntry->PhysicalStart + MemoryBlockLength) == NextMemoryMapEntry->PhysicalStart))
      {
        MemoryMapEntry->NumberOfPages += NextMemoryMapEntry->NumberOfPages;
        if (NewMemoryMapEntry != MemoryMapEntry) {
          NewMemoryMapEntry->NumberOfPages += NextMemoryMapEntry->NumberOfPages;
        }

        NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (NextMemoryMapEntry, DescriptorSize);
        continue;
      } else {
        MemoryMapEntry = PREVIOUS_MEMORY_DESCRIPTOR (NextMemoryMapEntry, DescriptorSize);
        break;
      }
    } while (TRUE);

    MemoryMapEntry    = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);
    NewMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (NewMemoryMapEntry, DescriptorSize);
  }

  *MemoryMapSize = (UINTN)NewMemoryMapEntry - (UINTN)MemoryMap;

  return;
}

/**
  Enforce memory map attributes.
  This function will set EfiRuntimeServicesData/EfiMemoryMappedIO/EfiMemoryMappedIOPortSpace to be EFI_MEMORY_XP.

  @param[in, out]  MemoryMap              A pointer to the buffer in which firmware places
                                          the current memory map.
  @param[in]       MemoryMapSize          Size, in bytes, of the MemoryMap buffer.
  @param[in]       DescriptorSize         Size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.
**/
STATIC
VOID
EnforceMemoryMapAttribute (
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN UINTN                      MemoryMapSize,
  IN UINTN                      DescriptorSize
  )
{
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEnd;

  MemoryMapEntry = MemoryMap;
  MemoryMapEnd   = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + MemoryMapSize);
  while ((UINTN)MemoryMapEntry < (UINTN)MemoryMapEnd) {
    if (MemoryMapEntry->Attribute != 0) {
      // It is PE image, the attribute is already set.
    } else {
      switch (MemoryMapEntry->Type) {
        case EfiRuntimeServicesCode:
          MemoryMapEntry->Attribute = EFI_MEMORY_RO;
          break;
        case EfiRuntimeServicesData:
        default:
          MemoryMapEntry->Attribute |= EFI_MEMORY_XP;
          break;
      }
    }

    MemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);
  }

  return;
}

/**
  This function for GetMemoryMap() with memory attributes table.

  It calls original GetMemoryMap() to get the original memory map information. Then
  plus the additional memory map entries for PE Code/Data separation.

  @param[in, out]  MemoryMapSize          A pointer to the size, in bytes, of the
                                          MemoryMap buffer. On input, this is the size of
                                          the buffer allocated by the caller.  On output,
                                          it is the size of the buffer returned by the
                                          firmware  if the buffer was large enough, or the
                                          size of the buffer needed  to contain the map if
                                          the buffer was too small.
  @param[in, out]  MemoryMap              A pointer to the buffer in which firmware places
                                          the current memory map.
  @param[out]      MapKey                 A pointer to the location in which firmware
                                          returns the key for the current memory map.
  @param[out]      DescriptorSize         A pointer to the location in which firmware
                                          returns the size, in bytes, of an individual
                                          EFI_MEMORY_DESCRIPTOR.
  @param[out]      DescriptorVersion      A pointer to the location in which firmware
                                          returns the version number associated with the
                                          EFI_MEMORY_DESCRIPTOR.

  @retval EFI_SUCCESS            The memory map was returned in the MemoryMap
                                 buffer.
  @retval EFI_BUFFER_TOO_SMALL   The MemoryMap buffer was too small. The current
                                 buffer size needed to hold the memory map is
                                 returned in MemoryMapSize.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.

**/
STATIC
EFI_STATUS
EFIAPI
SmmCoreGetMemoryMapMemoryAttributesTable (
  IN OUT UINTN                  *MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  OUT UINTN                     *MapKey,
  OUT UINTN                     *DescriptorSize,
  OUT UINT32                    *DescriptorVersion
  )
{
  EFI_STATUS  Status;
  UINTN       OldMemoryMapSize;
  UINTN       AdditionalRecordCount;

  //
  // If PE code/data is not aligned, just return.
  //
  if ((mMemoryProtectionAttribute & EFI_MEMORY_ATTRIBUTES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA) == 0) {
    return MmCoreGetMemoryMap (MemoryMapSize, MemoryMap, MapKey, DescriptorSize, DescriptorVersion);
  }

  if (MemoryMapSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  AdditionalRecordCount = (2 * mImagePropertiesPrivateData.CodeSegmentCountMax + 3) * mImagePropertiesPrivateData.ImageRecordCount;

  OldMemoryMapSize = *MemoryMapSize;
  Status           = MmCoreGetMemoryMap (MemoryMapSize, MemoryMap, MapKey, DescriptorSize, DescriptorVersion);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    *MemoryMapSize = *MemoryMapSize + (*DescriptorSize) * AdditionalRecordCount;
  } else if (Status == EFI_SUCCESS) {
    if (OldMemoryMapSize - *MemoryMapSize < (*DescriptorSize) * AdditionalRecordCount) {
      *MemoryMapSize = *MemoryMapSize + (*DescriptorSize) * AdditionalRecordCount;
      //
      // Need update status to buffer too small
      //
      Status = EFI_BUFFER_TOO_SMALL;
    } else {
      //
      // Split PE code/data
      //
      ASSERT (MemoryMap != NULL);
      SplitTable (MemoryMapSize, MemoryMap, *DescriptorSize, &mImagePropertiesPrivateData.ImageRecordList, AdditionalRecordCount);

      //
      // Set RuntimeData to XP
      //
      EnforceMemoryMapAttribute (MemoryMap, *MemoryMapSize, *DescriptorSize);

      //
      // Merge same type to save entry size
      //
      MergeMemoryMap (MemoryMap, MemoryMapSize, *DescriptorSize);
    }
  }

  return Status;
}

//
// Below functions are for ImageRecord
//

/**
  Create image record.

  @param[in]    DriverEntry         Driver information
  @param[in]    NeedInsert          Indicator on whether to add this driver entry into the
                                    existing driver record database or not.
  @param[out]   ReturnImageRecord   Optional pointer to hold created image record entry.

  @retval       EFI_SUCCESS             The image record is created successfully.
  @retval       EFI_OUT_OF_RESOURCES    Failed to allocate memory for new image record sections.
  @retval       EFI_SECURITY_VIOLATION  Failed to validate PE header signature, or PE image is not
                                        EFI_PAGE_SIZE aligned, or PE image code segment count is 0.
**/
EFI_STATUS
SmmCreateImageRecordInternal (
  IN  EFI_MM_DRIVER_ENTRY      *DriverEntry,
  IN  BOOLEAN                  NeedInsert,
  OUT IMAGE_PROPERTIES_RECORD  **ReturnImageRecord   OPTIONAL
  )
{
  EFI_STATUS               Status;
  IMAGE_PROPERTIES_RECORD  *ImageRecord;
  CHAR8                    *PdbPointer;
  UINT32                   RequiredAlignment;

  DEBUG ((DEBUG_VERBOSE, "SMM InsertImageRecord - 0x%x\n", DriverEntry));

  ImageRecord = AllocatePool (sizeof (*ImageRecord));
  if (ImageRecord == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  InitializeListHead (&ImageRecord->Link);
  InitializeListHead (&ImageRecord->CodeSegmentList);

  PdbPointer = PeCoffLoaderGetPdbPointer ((VOID *)(UINTN)DriverEntry->ImageBuffer);
  if (PdbPointer != NULL) {
    DEBUG ((DEBUG_VERBOSE, "SMM   Image - %a\n", PdbPointer));
  }

  RequiredAlignment = RUNTIME_PAGE_ALLOCATION_GRANULARITY;
  Status            = CreateImagePropertiesRecord (
                        (VOID *)(UINTN)DriverEntry->ImageBuffer,
                        LShiftU64 (DriverEntry->NumberOfPage, EFI_PAGE_SHIFT),
                        &RequiredAlignment,
                        ImageRecord
                        );

  if (EFI_ERROR (Status)) {
    if (Status == EFI_ABORTED) {
      mMemoryProtectionAttribute &=
        ~((UINT64)EFI_MEMORY_ATTRIBUTES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA);
    }

    Status = EFI_SECURITY_VIOLATION;
    goto Finish;
  }

  if (ImageRecord->CodeSegmentCount == 0) {
    mMemoryProtectionAttribute &=
      ~((UINT64)EFI_MEMORY_ATTRIBUTES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA);
    DEBUG ((DEBUG_ERROR, "SMM !!!!!!!!  InsertImageRecord - CodeSegmentCount is 0  !!!!!!!!\n"));
    if (PdbPointer != NULL) {
      DEBUG ((DEBUG_ERROR, "SMM !!!!!!!!  Image - %a  !!!!!!!!\n", PdbPointer));
    }

    Status = EFI_ABORTED;
    goto Finish;
  }

  //
  // Check overlap all section in ImageBase/Size
  //
  if (!IsImageRecordCodeSectionValid (ImageRecord)) {
    DEBUG ((DEBUG_ERROR, "SMM IsImageRecordCodeSectionValid - FAIL\n"));
    Status = EFI_ABORTED;
    goto Finish;
  }

  if (ReturnImageRecord != NULL) {
    *ReturnImageRecord = ImageRecord;
  }

  if (NeedInsert) {
    InsertTailList (&mImagePropertiesPrivateData.ImageRecordList, &ImageRecord->Link);
    mImagePropertiesPrivateData.ImageRecordCount++;

    if (mImagePropertiesPrivateData.CodeSegmentCountMax < ImageRecord->CodeSegmentCount) {
      mImagePropertiesPrivateData.CodeSegmentCountMax = ImageRecord->CodeSegmentCount;
    }
  }

  Status = EFI_SUCCESS;

Finish:
  if (EFI_ERROR (Status) && (ImageRecord != NULL)) {
    DeleteImagePropertiesRecord (ImageRecord);
  }

  return Status;
}

/**
  This function sets the memory attributes of the read-only data sections of a
  Pe/Coff image to RO.

  @param[in]  DriverEntry           Driver information
  @param[in]  IsSupervisorImage     Indicator of whether the DriverEntry represents a supervisor image.

  @retval   EFI_SUCCESS             Image attribute was set up successfully.
  @retval   EFI_INVALID_PARAMETER   DriverEntry is NULL pointer.
**/
EFI_STATUS
EFIAPI
ProtectReadonlyData (
  IN CONST EFI_MM_DRIVER_ENTRY  *DriverEntry,
  IN BOOLEAN                    IsSupervisorImage
  )
{
  UINTN                                Index;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT32                               SectionAlignment;
  EFI_IMAGE_SECTION_HEADER             *Section;
  UINT64                               SectionStart;
  UINT64                               SectionEnd;
  EFI_PHYSICAL_ADDRESS                 ImageBase;

  if (DriverEntry == NULL) {
    ASSERT (DriverEntry != NULL);
    return EFI_INVALID_PARAMETER;
  }

  ImageBase          = DriverEntry->ImageBuffer;
  DosHdr             = (EFI_IMAGE_DOS_HEADER *)ImageBase;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)ImageBase + PeCoffHeaderOffset);
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    SectionAlignment = Hdr.Pe32->OptionalHeader.SectionAlignment;
  } else {
    SectionAlignment = Hdr.Pe32Plus->OptionalHeader.SectionAlignment;
  }

  Section = (EFI_IMAGE_SECTION_HEADER *)(
                                         (UINT8 *)ImageBase +
                                         PeCoffHeaderOffset +
                                         sizeof (UINT32) +
                                         sizeof (EFI_IMAGE_FILE_HEADER) +
                                         Hdr.Pe32->FileHeader.SizeOfOptionalHeader
                                         );

  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    SectionStart = (UINT64)ImageBase + Section[Index].VirtualAddress;
    SectionEnd   = SectionStart + ALIGN_VALUE (Section[Index].SizeOfRawData, SectionAlignment);

    if ((Section[Index].Characteristics & (EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_CNT_CODE)) == 0) {
      // Not writable, so set it to RO
      // Note that we don't need to set it to XP, as the image is already marked as XP.
      DEBUG ((
        DEBUG_INFO,
        "%a Marking 0x%11p - 0x%11p to RO\n",
        __func__,
        SectionStart,
        SectionEnd
        ));
      SmmSetMemoryAttributes (
        SectionStart,
        SectionEnd - SectionStart,
        EFI_MEMORY_RO | (IsSupervisorImage ? EFI_MEMORY_SP : 0)
        );
    }
  }

  return EFI_SUCCESS;
}

/**
  This function allows supervisor to mark the target image page attributes after loading.

  @param[in]  DriverEntry           Driver information
  @param[in]  IsSupervisorImage     Indicator of whether the DriverEntry represents a supervisor image.

  @retval   EFI_SUCCESS             Image attribute was set up successfully.
  @retval   EFI_INVALID_PARAMETER   DriverEntry is NULL pointer.
  @retval   EFI_SECURITY_VIOLATION  Internal routines, such as SmmCreateImageRecordInternal,
                                    returned error codes.
**/
EFI_STATUS
EFIAPI
SmmSetImagePageAttributes (
  IN EFI_MM_DRIVER_ENTRY  *DriverEntry,
  IN BOOLEAN              IsSupervisorImage
  )
{
  IMAGE_PROPERTIES_RECORD               *ReturnImageRecord = NULL;
  IMAGE_PROPERTIES_RECORD_CODE_SECTION  *ImageRecordCodeSection;
  LIST_ENTRY                            *ImageRecordCodeSectionLink;
  LIST_ENTRY                            *ImageRecordCodeSectionEndLink;
  LIST_ENTRY                            *ImageRecordCodeSectionList;
  UINTN                                 SupervisorPageAttr;
  EFI_PHYSICAL_ADDRESS                  TempDataAddressStart;
  EFI_PHYSICAL_ADDRESS                  ImageEnd;
  EFI_STATUS                            Status;

  if (DriverEntry == NULL) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  Status = SmmCreateImageRecordInternal (DriverEntry, TRUE, &ReturnImageRecord);

  if (EFI_ERROR (Status) || (ReturnImageRecord == NULL)) {
    ASSERT (FALSE);
    return EFI_SECURITY_VIOLATION;
  }

  if (IsSupervisorImage) {
    SupervisorPageAttr = EFI_MEMORY_SP;
  } else {
    SupervisorPageAttr = 0;
  }

  DEBUG ((
    DEBUG_INFO,
    "Pre-processing MM driver at 0x%11p Length=0x%11p\n",
    ReturnImageRecord->ImageBase,
    ReturnImageRecord->ImageSize
    ));

  // Mark the entire image region as RO and non-XP first
  SmmClearMemoryAttributes (ReturnImageRecord->ImageBase, ReturnImageRecord->ImageSize, EFI_MEMORY_XP);
  SmmSetMemoryAttributes (ReturnImageRecord->ImageBase, ReturnImageRecord->ImageSize, EFI_MEMORY_RO | SupervisorPageAttr);

  ImageRecordCodeSectionList = &ReturnImageRecord->CodeSegmentList;
  TempDataAddressStart       = ReturnImageRecord->ImageBase;
  ImageEnd                   = ReturnImageRecord->ImageBase + ReturnImageRecord->ImageSize;

  ImageRecordCodeSectionLink    = ImageRecordCodeSectionList->ForwardLink;
  ImageRecordCodeSectionEndLink = ImageRecordCodeSectionList;
  while (ImageRecordCodeSectionLink != ImageRecordCodeSectionEndLink) {
    ImageRecordCodeSection = CR (
                               ImageRecordCodeSectionLink,
                               IMAGE_PROPERTIES_RECORD_CODE_SECTION,
                               Link,
                               IMAGE_PROPERTIES_RECORD_CODE_SECTION_SIGNATURE
                               );
    ImageRecordCodeSectionLink = ImageRecordCodeSectionLink->ForwardLink;
    if (TempDataAddressStart < ImageRecordCodeSection->CodeSegmentBase) {
      DEBUG ((
        DEBUG_INFO,
        "Marking 0x%11p - 0x%11p to XP and WR\n",
        TempDataAddressStart,
        ImageRecordCodeSection->CodeSegmentBase
        ));
      //
      // DATA
      //
      SmmSetMemoryAttributes (
        TempDataAddressStart,
        ImageRecordCodeSection->CodeSegmentBase - TempDataAddressStart,
        EFI_MEMORY_XP | SupervisorPageAttr
        );
      SmmClearMemoryAttributes (
        TempDataAddressStart,
        ImageRecordCodeSection->CodeSegmentBase - TempDataAddressStart,
        EFI_MEMORY_RO
        );

      TempDataAddressStart = ImageRecordCodeSection->CodeSegmentBase + ALIGN_VALUE (ImageRecordCodeSection->CodeSegmentSize, EFI_PAGE_SIZE);
      if (EFI_SIZE_TO_PAGES (ImageEnd - TempDataAddressStart) == 0) {
        break;
      }
    }
  }

  //
  // Final DATA
  //
  if (TempDataAddressStart < ImageEnd) {
    DEBUG ((
      DEBUG_INFO,
      "Marking 0x%11p - 0x%11p to XP and WR\n",
      TempDataAddressStart,
      ImageEnd
      ));
    SmmSetMemoryAttributes (
      TempDataAddressStart,
      ImageEnd - TempDataAddressStart,
      EFI_MEMORY_XP | SupervisorPageAttr
      );
    SmmClearMemoryAttributes (
      TempDataAddressStart,
      ImageEnd - TempDataAddressStart,
      EFI_MEMORY_RO
      );
  }

  Status = ProtectReadonlyData (DriverEntry, IsSupervisorImage);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  return Status;
}

/**
  Collect MemoryAttributesTable to SMM configuration table.
**/
EFI_MEMORY_DESCRIPTOR *
CollectMemoryAttributesTable (
  OUT UINTN  *RetMemoryMapSize,
  OUT UINTN  *RetDescriptorSize
  )
{
  UINTN                  MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  UINTN                  MapKey;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
  EFI_STATUS             Status;

  if ((RetMemoryMapSize == NULL) ||
      (RetDescriptorSize == NULL))
  {
    DEBUG ((DEBUG_ERROR, "%a Invalid input parameters!\n", __FUNCTION__));
    return NULL;
  }

  MemoryMapSize = 0;
  MemoryMap     = NULL;
  Status        = SmmCoreGetMemoryMapMemoryAttributesTable (
                    &MemoryMapSize,
                    MemoryMap,
                    &MapKey,
                    &DescriptorSize,
                    &DescriptorVersion
                    );
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);

  do {
    DEBUG ((DEBUG_VERBOSE, "MemoryMapSize - 0x%x\n", MemoryMapSize));
    MemoryMap = AllocatePool (MemoryMapSize);
    if (MemoryMap == NULL) {
      DEBUG ((DEBUG_ERROR, "Failed to allocate memory for memory map (0x%x bytes)\n", MemoryMapSize));
      Status = EFI_OUT_OF_RESOURCES;
      break;
    }

    DEBUG ((DEBUG_VERBOSE, "MemoryMap - 0x%x\n", MemoryMap));

    Status = SmmCoreGetMemoryMapMemoryAttributesTable (
               &MemoryMapSize,
               MemoryMap,
               &MapKey,
               &DescriptorSize,
               &DescriptorVersion
               );
    if (EFI_ERROR (Status)) {
      FreePool (MemoryMap);
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return NULL;
  } else {
    *RetMemoryMapSize  = MemoryMapSize;
    *RetDescriptorSize = DescriptorSize;
    return MemoryMap;
  }
}

/**
  Initialize MemoryAttributesTable.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification runs successfully.
**/
EFI_STATUS
EFIAPI
SmmInitializeMemoryAttributesTable (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  DEBUG ((DEBUG_VERBOSE, "SMM MemoryProtectionAttribute - 0x%016lx\n", mMemoryProtectionAttribute));
  if ((mMemoryProtectionAttribute & EFI_MEMORY_ATTRIBUTES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA) == 0) {
    return EFI_SUCCESS;
  }

  DEBUG_CODE_BEGIN ();
  if ( mImagePropertiesPrivateData.ImageRecordCount > 0) {
    DEBUG ((DEBUG_INFO, "SMM - Total Runtime Image Count - 0x%x\n", mImagePropertiesPrivateData.ImageRecordCount));
    DEBUG ((DEBUG_INFO, "SMM - Dump Runtime Image Records:\n"));
    DumpImageRecords (&mImagePropertiesPrivateData.ImageRecordList);
  }

  DEBUG_CODE_END ();

  mInitMemoryMap = CollectMemoryAttributesTable (&mInitMemoryMapSize, &mInitDescriptorSize);

  return EFI_SUCCESS;
}
