/** @file
  MM Core Main Entry Point

  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <IndustryStandard/Tpm20.h>
#include <Register/Msr.h>
#include <Register/Cpuid.h>
#include <Register/SmramSaveStateMap.h>
#include <SpamResponder.h>
#include <SmmSecurePolicy.h>
#include <x64/Smx.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffLibNegative.h>
#include <Library/SafeIntLib.h>
#include <Library/TpmMeasurementLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/HashLib.h>
#include <Library/SecurePolicyLib.h>

#define SPAM_PCR_INDEX  17

/**
  Helper function to check if two ranges overlap.

  @param[in] Start1    Start address of the first range.
  @param[in] Size1     Size of the first range.
  @param[in] Start2    Start address of the second range.
  @param[in] Size2     Size of the second range.
  @param[out] Overlap  TRUE if the two ranges overlap, FALSE otherwise.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  Overlap is NULL.
  @retval other error value
**/
EFI_STATUS
EFIAPI
TwoRangesOverlap (
  IN UINT64    Start1,
  IN UINT64    Size1,
  IN UINT64    Start2,
  IN UINT64    Size2,
  OUT BOOLEAN  *Overlap
  )
{
  UINT64      End1;
  UINT64      End2;
  EFI_STATUS  Status;

  if (Overlap == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SafeUint64Add (Start1, Size1, &End1);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Status = SafeUint64Add (Start2, Size2, &End2);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  *Overlap = FALSE;

  // For two ranges to overlap, one of the following conditions must be true:
  // 1. Start1 falls into range 2
  // 2. Start2 falls into range 1
  if ((Start1 <= Start2) && (Start2 < End1)) {
    *Overlap = TRUE;
  }

  if ((Start2 <= Start1) && (Start1 < End2)) {
    *Overlap = TRUE;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  Helper function to check if one range is inside another.

  @param[in] Start1     Start address of the first range.
  @param[in] Size1      Size of the first range.
  @param[in] Start2     Start address of the second range.
  @param[in] Size2      Size of the second range.
  @param[out] IsInside  TRUE if the first range is inside the second range, FALSE otherwise.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  IsInside is NULL.
  @retval other error value
**/
EFI_STATUS
EFIAPI
Range1InsideRange2 (
  IN UINT64    Start1,
  IN UINT64    Size1,
  IN UINT64    Start2,
  IN UINT64    Size2,
  OUT BOOLEAN  *IsInside
  )
{
  EFI_STATUS  Status;
  UINT64      End1;
  UINT64      End2;

  if (IsInside == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Size1 > Size2) {
    *IsInside = FALSE;
    Status    = EFI_SUCCESS;
  }

  Status = SafeUint64Add (Start1, Size1, &End1);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Status = SafeUint64Add (Start2, Size2, &End2);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  *IsInside = FALSE;
  if ((Start2 <= Start1) && (End1 <= End2)) {
    *IsInside = TRUE;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length in bytes to be checked.

  @retval TRUE  This buffer is not part of MMRAM.
  @retval FALSE This buffer is from MMRAM.
**/
BOOLEAN
EFIAPI
IsBufferInsideMmram (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  UINT64                          MmRamBase;
  UINT64                          MmRamLength;
  UINT64                          MmrrMask;
  UINT32                          MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX  VirPhyAddressSize;
  UINT64                          MtrrValidBitsMask;
  UINT64                          MtrrValidAddressMask;
  BOOLEAN                         IsInside;
  EFI_STATUS                      Status;

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunction, NULL, NULL, NULL);

  if (MaxExtendedFunction >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  MtrrValidBitsMask    = LShiftU64 (1, VirPhyAddressSize.Bits.PhysicalAddressBits) - 1;
  MtrrValidAddressMask = MtrrValidBitsMask & 0xfffffffffffff000ULL;

  MmRamBase = AsmReadMsr64 (MSR_IA32_SMRR_PHYSBASE);
  MmrrMask  = AsmReadMsr64 (MSR_IA32_SMRR_PHYSMASK);
  // Extend the mask to account for the reserved bits.
  MmrrMask    |= 0xffffffff00000000ULL;
  MmRamLength = ((~(MmrrMask & MtrrValidAddressMask)) & MtrrValidBitsMask) + 1;

  Status = Range1InsideRange2 (Buffer, Length, MmRamBase, MmRamLength, &IsInside);
  if (EFI_ERROR (Status)) {
    IsInside = FALSE;
  }

  return IsInside;
}

/**
  Measure PE image into TPM log based on the authenticode image hashing in
  PE/COFF Specification 8.0 Appendix A.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  Notes: PE/COFF image is checked by BasePeCoffLib PeCoffLoaderGetImageInfo().

  @param[in]  PCRIndex       TPM PCR index
  @param[in]  ImageAddress   Start address of image buffer.
  @param[in]  ImageSize      Image size
  @param[out] DigestList     Digest list of this image.

  @retval EFI_SUCCESS            Successfully measure image.
  @retval EFI_OUT_OF_RESOURCES   No enough resource to measure image.
  @retval other error value
**/
EFI_STATUS
MeasurePeImageAndExtend (
  IN  UINT32                PCRIndex,
  IN  EFI_PHYSICAL_ADDRESS  ImageAddress,
  IN  UINTN                 ImageSize,
  OUT TPML_DIGEST_VALUES    *DigestList
  )
{
  EFI_STATUS                           Status;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_SECTION_HEADER             *Section;
  UINT8                                *HashBase;
  UINTN                                HashSize;
  UINTN                                SumOfBytesHashed;
  EFI_IMAGE_SECTION_HEADER             *SectionHeader;
  UINTN                                Index;
  UINTN                                Pos;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT32                               NumberOfRvaAndSizes;
  UINT32                               CertSize;
  HASH_HANDLE                          HashHandle;
  PE_COFF_LOADER_IMAGE_CONTEXT         ImageContext;

  HashHandle = 0xFFFFFFFF; // Know bad value

  Status        = EFI_UNSUPPORTED;
  SectionHeader = NULL;

  //
  // Check PE/COFF image
  //
  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.Handle    = (VOID *)(UINTN)ImageAddress;
  ImageContext.ImageRead = (PE_COFF_LOADER_READ_FILE)PeCoffLoaderImageReadFromMemory;

  //
  // Get information about the image being loaded
  //
  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    //
    // The information can't be got from the invalid PeImage
    //
    DEBUG ((DEBUG_INFO, "Tcg2Dxe: PeImage invalid. Cannot retrieve image information.\n"));
    goto Finish;
  }

  DosHdr             = (EFI_IMAGE_DOS_HEADER *)(UINTN)ImageAddress;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *)(UINTN)ImageAddress + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    Status = EFI_UNSUPPORTED;
    goto Finish;
  }

  //
  // PE/COFF Image Measurement
  //
  //    NOTE: The following codes/steps are based upon the authenticode image hashing in
  //      PE/COFF Specification 8.0 Appendix A.
  //
  //

  // 1.  Load the image header into memory.

  // 2.  Initialize a SHA hash context.

  Status = HashStart (&HashHandle);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

  //
  // Measuring PE/COFF Image Header;
  // But CheckSum field and SECURITY data directory (certificate) are excluded
  //

  //
  // 3.  Calculate the distance from the base of the image header to the image checksum address.
  // 4.  Hash the image header from its base to beginning of the image checksum.
  //
  HashBase = (UINT8 *)(UINTN)ImageAddress;
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset
    //
    NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    HashSize            = (UINTN)(&Hdr.Pe32->OptionalHeader.CheckSum) - (UINTN)HashBase;
  } else {
    //
    // Use PE32+ offset
    //
    NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    HashSize            = (UINTN)(&Hdr.Pe32Plus->OptionalHeader.CheckSum) - (UINTN)HashBase;
  }

  Status = HashUpdate (HashHandle, HashBase, HashSize);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

  //
  // 5.  Skip over the image checksum (it occupies a single ULONG).
  //
  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    //
    // 6.  Since there is no Cert Directory in optional header, hash everything
    //     from the end of the checksum to the end of image header.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - ImageAddress);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - ImageAddress);
    }

    if (HashSize != 0) {
      Status = HashUpdate (HashHandle, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    }
  } else {
    //
    // 7.  Hash everything from the end of the checksum to the start of the Cert Directory.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *)&Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN)(&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
    } else {
      //
      // Use PE32+ offset
      //
      HashBase = (UINT8 *)&Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN)(&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
    }

    if (HashSize != 0) {
      Status = HashUpdate (HashHandle, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    }

    //
    // 8.  Skip over the Cert Directory. (It is sizeof(IMAGE_DATA_DIRECTORY) bytes.)
    // 9.  Hash everything from the end of the Cert Directory to the end of image header.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *)&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - ImageAddress);
    } else {
      //
      // Use PE32+ offset
      //
      HashBase = (UINT8 *)&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN)(HashBase - ImageAddress);
    }

    if (HashSize != 0) {
      Status = HashUpdate (HashHandle, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    }
  }

  //
  // 10. Set the SUM_OF_BYTES_HASHED to the size of the header
  //
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset
    //
    SumOfBytesHashed = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
  } else {
    //
    // Use PE32+ offset
    //
    SumOfBytesHashed = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
  }

  //
  // 11. Build a temporary table of pointers to all the IMAGE_SECTION_HEADER
  //     structures in the image. The 'NumberOfSections' field of the image
  //     header indicates how big the table should be. Do not include any
  //     IMAGE_SECTION_HEADERs in the table whose 'SizeOfRawData' field is zero.
  //
  SectionHeader = (EFI_IMAGE_SECTION_HEADER *)AllocatePages (EFI_SIZE_TO_PAGES (sizeof (EFI_IMAGE_SECTION_HEADER) * Hdr.Pe32->FileHeader.NumberOfSections));
  if (SectionHeader == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Finish;
  }

  //
  // 12.  Using the 'PointerToRawData' in the referenced section headers as
  //      a key, arrange the elements in the table in ascending order. In other
  //      words, sort the section headers according to the disk-file offset of
  //      the section.
  //
  Section = (EFI_IMAGE_SECTION_HEADER *)(
                                         (UINT8 *)(UINTN)ImageAddress +
                                         PeCoffHeaderOffset +
                                         sizeof (UINT32) +
                                         sizeof (EFI_IMAGE_FILE_HEADER) +
                                         Hdr.Pe32->FileHeader.SizeOfOptionalHeader
                                         );
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Pos = Index;
    while ((Pos > 0) && (Section->PointerToRawData < SectionHeader[Pos - 1].PointerToRawData)) {
      CopyMem (&SectionHeader[Pos], &SectionHeader[Pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
      Pos--;
    }

    CopyMem (&SectionHeader[Pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
    Section += 1;
  }

  //
  // 13.  Walk through the sorted table, bring the corresponding section
  //      into memory, and hash the entire section (using the 'SizeOfRawData'
  //      field in the section header to determine the amount of data to hash).
  // 14.  Add the section's 'SizeOfRawData' to SUM_OF_BYTES_HASHED .
  // 15.  Repeat steps 13 and 14 for all the sections in the sorted table.
  //
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Section = (EFI_IMAGE_SECTION_HEADER *)&SectionHeader[Index];
    if (Section->SizeOfRawData == 0) {
      continue;
    }

    HashBase = (UINT8 *)(UINTN)ImageAddress + Section->PointerToRawData;
    HashSize = (UINTN)Section->SizeOfRawData;

    Status = HashUpdate (HashHandle, HashBase, HashSize);
    if (EFI_ERROR (Status)) {
      goto Finish;
    }

    SumOfBytesHashed += HashSize;
  }

  //
  // 16.  If the file size is greater than SUM_OF_BYTES_HASHED, there is extra
  //      data in the file that needs to be added to the hash. This data begins
  //      at file offset SUM_OF_BYTES_HASHED and its length is:
  //             FileSize  -  (CertDirectory->Size)
  //
  if (ImageSize > SumOfBytesHashed) {
    HashBase = (UINT8 *)(UINTN)ImageAddress + SumOfBytesHashed;

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      CertSize = 0;
    } else {
      if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        //
        // Use PE32 offset.
        //
        CertSize = Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      } else {
        //
        // Use PE32+ offset.
        //
        CertSize = Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      }
    }

    if (ImageSize > CertSize + SumOfBytesHashed) {
      HashSize = (UINTN)(ImageSize - CertSize - SumOfBytesHashed);

      Status = HashUpdate (HashHandle, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Finish;
      }
    } else if (ImageSize < CertSize + SumOfBytesHashed) {
      Status = EFI_UNSUPPORTED;
      goto Finish;
    }
  }

  //
  // 17.  Finalize the SHA hash.
  //
  Status = HashCompleteAndExtend (HashHandle, PCRIndex, NULL, 0, DigestList);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

Finish:
  if (SectionHeader != NULL) {
    FreePages (SectionHeader, EFI_SIZE_TO_PAGES (sizeof (EFI_IMAGE_SECTION_HEADER) * Hdr.Pe32->FileHeader.NumberOfSections));
  }

  return Status;
}

// TODO: Place them in a common place?
UINT8  DrtmSmmPolicyData[0x1000];

EFI_STATUS
EFIAPI
VerifyAndMeasureImage (
  IN UINTN   ImageBase,
  IN UINT64  ImageSize,
  IN UINT64  AuxFileBase,
  IN UINT64  AuxFileLength
  )
{
  EFI_STATUS          Status;
  VOID                *InternalCopy;
  TPML_DIGEST_VALUES  DigestList[HASH_COUNT];

  // First need to make sure if this image is inside the MMRAM region
  if (!IsBufferInsideMmram (ImageBase, ImageSize)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // TODO: Also need to make sure the ImageBase and ImageSize are page aligned

  // Then need to copy the image over to MSEG
  InternalCopy = AllocatePages (
                   EFI_SIZE_TO_PAGES (ImageSize + EFI_PAGE_SIZE - 1)
                   );

  //
  // Get information about the image being loaded
  //
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

  ZeroMem (&ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));
  VOID  *Buffer = AllocatePages (EFI_SIZE_TO_PAGES (ImageSize));

  CopyMem (Buffer, (VOID *)ImageBase, ImageSize);

  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
  ImageContext.Handle    = (VOID *)Buffer;

  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  ImageContext.DestinationAddress = (EFI_PHYSICAL_ADDRESS)(VOID *)Buffer;
  Status                          = PeCoffLoaderRevertRelocateImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = PeCoffImageDiffValidation ((VOID *)ImageBase, Buffer, ImageSize, (VOID *)AuxFileBase, AuxFileLength);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // Now prepare a new buffer to revert loading operations.
  UINTN  NewBufferSize = ImageSize;
  VOID   *NewBuffer    = AllocatePages (EFI_SIZE_TO_PAGES (NewBufferSize));

  ZeroMem (NewBuffer, NewBufferSize);

  DEBUG ((DEBUG_INFO, "%p %p %p\n", ImageBase, Buffer, NewBuffer));

  // At this point we dealt with the relocation, some data are still off.
  // Next we unload the image in the copy.
  Status = PeCoffLoaderRevertLoadImage (&ImageContext, NewBuffer, &NewBufferSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a Reverted image at %p of size %x\n", __func__, NewBuffer, NewBufferSize));

  Status = MeasurePeImageAndExtend (
             SPAM_PCR_INDEX,
             (EFI_PHYSICAL_ADDRESS)(UINTN)NewBuffer,
             (UINTN)NewBufferSize,
             DigestList
             );
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Measured image at %p of size %x successfully.\n", __func__, NewBuffer, NewBufferSize));
  } else {
    DEBUG ((DEBUG_ERROR, "%a Failed to measure image at %p of size %x - %r\n", __func__, NewBuffer, NewBufferSize, Status));
  }

Exit:
  if (InternalCopy != NULL) {
    FreePages (InternalCopy, EFI_SIZE_TO_PAGES (ImageSize + EFI_PAGE_SIZE - 1));
  }

  return Status;
}

/**
  The main validation routine for the SPAM Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then measure
  the content into TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and measure into TPM.

  @param[in]  SpamResponderData  The pointer to the SPAM_RESPONDER_DATA structure.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SpamResponderReport (
  IN SPAM_RESPONDER_DATA  *SpamResponderData
  )
{
  EFI_STATUS                      Status;
  UINT64                          MmBase;
  UINT64                          MmRamBase;
  UINT64                          MmrrMask;
  UINT32                          MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX  VirPhyAddressSize;
  UINT64                          Length;
  UINT64                          MtrrValidBitsMask;
  UINT64                          MtrrValidAddressMask;
  UINT32                          *Fixup32Ptr;
  UINT64                          *Fixup64Ptr;
  BOOLEAN                         IsInside;
  UINTN                           Index;
  PER_CORE_MMI_ENTRY_STRUCT_HDR   *MmiEntryStructHdr;
  UINT32                          MmiEntryStructHdrSize;
  UINT64                          MmSupervisorBase;
  UINT64                          FirmwarePolicyBase;
  UINT64                          SupvPageTableBase;
  TPML_DIGEST_VALUES              DigestList[HASH_COUNT];

  KEY_SYMBOL  *FirmwarePolicySymbol = NULL;
  KEY_SYMBOL  *PageTableSymbol      = NULL;
  KEY_SYMBOL  *MmiRendezvousSymbol  = NULL;

  // TODO: Step 0: Disable MMI

  // Step 1: Basic check on the validity of SpamResponderData
  // TODO: How do we know if the input stack is safe to access?
  if (SpamResponderData == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  if (SpamResponderData->Signature != SPAM_RESPONDER_STRUCT_SIGNATURE) {
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

  if (SpamResponderData->VersionMajor > SPAM_REPSONDER_STRUCT_MAJOR_VER) {
    Status = EFI_UNSUPPORTED;
    goto Exit;
  } else if ((SpamResponderData->VersionMajor == SPAM_REPSONDER_STRUCT_MAJOR_VER) &&
             (SpamResponderData->VersionMinor > SPAM_REPSONDER_STRUCT_MINOR_VER))
  {
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

  // Step 2: Check MM Entry code base and size to be inside the MMRAM region

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunction, NULL, NULL, NULL);

  if (MaxExtendedFunction >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  MtrrValidBitsMask    = LShiftU64 (1, VirPhyAddressSize.Bits.PhysicalAddressBits) - 1;
  MtrrValidAddressMask = MtrrValidBitsMask & 0xfffffffffffff000ULL;

  MmRamBase = AsmReadMsr64 (MSR_IA32_SMRR_PHYSBASE);
  MmrrMask  = AsmReadMsr64 (MSR_IA32_SMRR_PHYSMASK);
  // Extend the mask to account for the reserved bits.
  MmrrMask |= 0xffffffff00000000ULL;
  Length    = ((~(MmrrMask & MtrrValidAddressMask)) & MtrrValidBitsMask) + 1;
  MmBase    = AsmReadMsr64 (MSR_IA32_SMBASE);
  if (MmBase == 0) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (!IsBufferInsideMmram (MmBase + SMM_HANDLER_OFFSET, SpamResponderData->MmEntrySize)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if ((IMAGE_VALIDATION_DATA_HEADER *)(VOID *)SpamResponderData->MmSupervisorAuxBase == 0) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (!IsBufferInsideMmram (SpamResponderData->MmSupervisorAuxBase, SpamResponderData->MmSupervisorAuxSize)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (((IMAGE_VALIDATION_DATA_HEADER *)SpamResponderData->MmSupervisorAuxBase)->HeaderSignature != IMAGE_VALIDATION_DATA_SIGNATURE) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  ZeroMem (DigestList, sizeof (DigestList));
  Status = HashAndExtend (
             SPAM_PCR_INDEX,
             (VOID *)(UINTN)(SpamResponderData->MmSupervisorAuxBase),
             (UINTN)SpamResponderData->MmSupervisorAuxSize,
             DigestList
             );
  if (EFI_ERROR (Status)) {
    goto Exit;
  } else {
    Status = EFI_NOT_FOUND;
    for (Index = 0; Index < HASH_COUNT; Index++) {
      if (DigestList[Index].count == 0) {
        continue;
      }

      if (DigestList[Index].digests[0].hashAlg == TPM_ALG_SHA256) {
        if (CompareMem (DigestList[Index].digests[0].digest.sha256, (VOID *)PatchPcdGetPtr (PcdAuxBinHash), SHA256_DIGEST_SIZE) != 0) {
          DEBUG ((DEBUG_ERROR, "Hash mismatch for aux file!!!\n"));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        } else {
          Status = EFI_SUCCESS;
          break;
        }
      }
    }

    if (EFI_ERROR (Status)) {
      goto Exit;
    }
  }

  KEY_SYMBOL  *KeySymbols = (KEY_SYMBOL *)(SpamResponderData->MmSupervisorAuxBase + ((IMAGE_VALIDATION_DATA_HEADER *)SpamResponderData->MmSupervisorAuxBase)->OffsetToFirstKeySymbol);

  for (Index = 0; Index < ((IMAGE_VALIDATION_DATA_HEADER *)SpamResponderData->MmSupervisorAuxBase)->KeySymbolCount; Index++) {
    switch (KeySymbols[Index].Signature) {
      case KEY_SYMBOL_FW_POLICY_SIGNATURE:
        FirmwarePolicySymbol = &KeySymbols[Index];
        break;
      case KEY_SYMBOL_PAGE_TBL_SIGNATURE:
        PageTableSymbol = &KeySymbols[Index];
        break;
      case KEY_SYMBOL_MMI_RDV_SIGNATURE:
        MmiRendezvousSymbol = &KeySymbols[Index];
        break;
    }
  }

  if ((FirmwarePolicySymbol == NULL) || (PageTableSymbol == NULL) || (MmiRendezvousSymbol == NULL)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 2.1: Measure MMI entry code
  // Record SMI_ENTRY_HASH to PCR 0, just in case it is NOT TXT launch, we still need provide the evidence.
  // TCG_PCR_EVENT_HDR   NewEventHdr;

  Status = HashAndExtend (
             SPAM_PCR_INDEX,
             (VOID *)(UINTN)(MmBase + SMM_HANDLER_OFFSET),
             (UINTN)SpamResponderData->MmEntrySize,
             DigestList
             );
  if (!EFI_ERROR (Status)) {
    // TODO: Do we want to message with the event log?
    // ZeroMem (&NewEventHdr, sizeof (NewEventHdr));
    // NewEventHdr.PCRIndex  = SPAM_PCR_INDEX;
    // NewEventHdr.EventType = SPAM_EVTYPE_MM_ENTRY_HASH;
    // NewEventHdr.EventSize = sizeof (EFI_TCG2_EVENT) - sizeof (NewEventHdr.Event) - sizeof (UINT32) - sizeof (EFI_TCG2_EVENT_HEADER);;

    // Status = TcgDxeLogHashEvent (DigestList, NewEventHdr, NewEventHdr.Event);
  } else {
    goto Exit;
  }

  // Step 3: Check MM Core code base and size to be inside the MMRAM region
  // Step 3.1: Check entry fix up data region to be pointing inside the MMRAM region
  MmiEntryStructHdrSize = *(UINT32 *)(UINTN)(MmBase + SMM_HANDLER_OFFSET + SpamResponderData->MmEntrySize - sizeof (MmiEntryStructHdrSize));
  MmiEntryStructHdr     = (PER_CORE_MMI_ENTRY_STRUCT_HDR *)(UINTN)(MmBase + SMM_HANDLER_OFFSET + SpamResponderData->MmEntrySize - MmiEntryStructHdrSize - sizeof (MmiEntryStructHdrSize));

  if ((MmiEntryStructHdr->HeaderVersion > MMI_ENTRY_STRUCT_VERSION) ||
      (MmiEntryStructHdrSize >= SpamResponderData->MmEntrySize))
  {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Fixup32Ptr = (UINT32 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp32Offset);
  Fixup64Ptr = (UINT64 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp64Offset);

  // Step 3.1.1: Pick a few entries to verify that they are pointing inside the MM CORE or MMRAM region
  // Reverse engineer MM core region with MM rendezvous
  MmSupervisorBase = Fixup64Ptr[FIXUP64_SMI_RDZ_ENTRY] - MmiRendezvousSymbol->Offset;

  if (!IsBufferInsideMmram (MmSupervisorBase, SpamResponderData->MmSupervisorSize)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // GDTR and its content should be pointing inside the MMRAM region
  if (!IsBufferInsideMmram (Fixup32Ptr[FIXUP32_GDTR], sizeof (IA32_DESCRIPTOR))) {
    DEBUG ((DEBUG_ERROR, "GDTR is not inside MMRAM region %x %x %x %x\n", Fixup32Ptr[FIXUP32_GDTR], sizeof (IA32_DESCRIPTOR), MmRamBase, Length));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (!IsBufferInsideMmram (((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Base, ((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Limit + 1)) {
    DEBUG ((DEBUG_ERROR, "GDTR base is not inside MMRAM region %x %x %x %x\n", ((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Base, ((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Limit + 1, MmBase, Length));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // CR3 should be pointing to the page table from symbol list in the aux file
  SupvPageTableBase = *(UINT64 *)(MmSupervisorBase + PageTableSymbol->Offset);
  if (Fixup32Ptr[FIXUP32_CR3_OFFSET] != SupvPageTableBase) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // CR3 should be pointing inside the MMRAM region
  if (!IsBufferInsideMmram (Fixup32Ptr[FIXUP32_CR3_OFFSET], sizeof (UINT32))) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Supervisor stack should be pointing inside the MMRAM region
  if (!IsBufferInsideMmram (Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0], sizeof (UINT32))) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // SMM BASE... should be MMBASE...
  if (Fixup32Ptr[FIXUP32_MSR_SMM_BASE] != MmBase) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM debug entry should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY], sizeof (UINT64), MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM debug exit should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMM_DBG_EXIT], sizeof (UINT64), MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM IDTR should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMI_HANDLER_IDTR], sizeof (UINT64), MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Then also verify that the firmware policy is inside the MMRAM
  FirmwarePolicyBase = *(UINT64 *)(MmSupervisorBase + FirmwarePolicySymbol->Offset);
  if (!IsBufferInsideMmram (FirmwarePolicyBase, sizeof (UINT64))) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 3.2: Measure MM Core code
  Status = VerifyAndMeasureImage (
             MmSupervisorBase,
             SpamResponderData->MmSupervisorSize,
             SpamResponderData->MmSupervisorAuxBase,
             SpamResponderData->MmSupervisorAuxSize
             );
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *FirmwarePolicy = (SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)FirmwarePolicyBase;

  // Step 4: Report MM Secure Policy code
  ZeroMem (DrtmSmmPolicyData, sizeof (DrtmSmmPolicyData));

  // First off, copy the firmware policy to the buffer
  CopyMem (DrtmSmmPolicyData, FirmwarePolicy, FirmwarePolicy->Size);

  // Then leave the heavy lifting job to the library
  Status = PopulateMemoryPolicyEntries ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)DrtmSmmPolicyData, sizeof (DrtmSmmPolicyData));
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Fail to PopulateMemoryPolicyEntries %r\n", __FUNCTION__, Status));
    goto Exit;
  }

  Status = SecurityPolicyCheck ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)DrtmSmmPolicyData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Policy check failed - %r\n", __FUNCTION__, Status));
    goto Exit;
  }

  DEBUG_CODE_BEGIN ();
  DumpSmmPolicyData ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)DrtmSmmPolicyData);
  DEBUG_CODE_END ();
  // TODO: How to do this? I would like to keep the structure the same though...

Exit:
  return Status;
}
