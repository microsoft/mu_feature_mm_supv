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
#include <SeaResponder.h>
#include <SeaAuxiliary.h>
#include <SmmSecurePolicy.h>
#include <x64/Smx.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffLibNegative.h>
#include <Library/SafeIntLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/HashLibRaw.h>
#include <Library/SecurePolicyLib.h>
#include <Library/PeCoffValidationLib.h>

#include "StmRuntimeUtil.h"

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
  Verify and hash an executed PeCoff image in MMRAM based on the provided aux buffer.

  @param[in] ImageBase      The base address of the image.
  @param[in] ImageSize      The size of the image.
  @param[in] AuxFileHdr     The header of the auxiliary file.
  @param[in] PageTableBase  The base address of the page table.
  @param[out] DigestList    The digest list of the image.

  @retval EFI_SUCCESS            The image is verified and hashed successfully.
  @retval EFI_SECURITY_VIOLATION The image is not inside MMRAM.
  @retval other error value
**/
EFI_STATUS
EFIAPI
VerifyAndHashImage (
  IN  EFI_PHYSICAL_ADDRESS          ImageBase,
  IN  UINT64                        ImageSize,
  IN  IMAGE_VALIDATION_DATA_HEADER  *AuxFileHdr,
  IN  EFI_PHYSICAL_ADDRESS          PageTableBase,
  OUT TPML_DIGEST_VALUES            *DigestList
  )
{
  EFI_STATUS                    Status;
  VOID                          *InternalCopy;
  VOID                          *Buffer    = NULL;
  VOID                          *NewBuffer = NULL;
  UINTN                         NewBufferSize;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

  // First need to make sure if this image is inside the MMRAM region
  if (!IsBufferInsideMmram (ImageBase, ImageSize)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (((ImageBase & EFI_PAGE_MASK) != 0) || ((ImageSize & EFI_PAGE_MASK) != 0)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Then need to copy the image over to MSEG
  InternalCopy = AllocatePages (
                   EFI_SIZE_TO_PAGES (ImageSize + EFI_PAGE_SIZE - 1)
                   );

  Status = PeCoffInspectImageMemory (ImageBase, ImageSize, PageTableBase);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: PeCoffInspectImageMemory failed - %r\n", __func__, Status));
    goto Exit;
  }

  //
  // Get information about the image being loaded
  //
  ZeroMem (&ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));
  Buffer = AllocatePages (EFI_SIZE_TO_PAGES (ImageSize));

  CopyMem (Buffer, (VOID *)ImageBase, ImageSize);

  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
  ImageContext.Handle    = (VOID *)Buffer;

  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - ImageContext->ImageError = 0x%x.\n", __func__, ImageContext.ImageError));
    goto Exit;
  }

  ImageContext.DestinationAddress = (EFI_PHYSICAL_ADDRESS)(VOID *)Buffer;
  Status                          = PeCoffLoaderRevertRelocateImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = PeCoffImageDiffValidation ((VOID *)ImageBase, Buffer, ImageSize, AuxFileHdr, PageTableBase);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // Now prepare a new buffer to revert loading operations.
  NewBufferSize = ImageSize;
  NewBuffer     = AllocatePages (EFI_SIZE_TO_PAGES (NewBufferSize));

  ZeroMem (NewBuffer, NewBufferSize);

  DEBUG ((DEBUG_INFO, "%p %p %p\n", ImageBase, Buffer, NewBuffer));

  // At this point we dealt with the relocation, some data are still off.
  // Next we unload the image in the copy.
  Status = PeCoffLoaderRevertLoadImage (&ImageContext, NewBuffer, &NewBufferSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a Reverted image at %p of size %x\n", __func__, NewBuffer, NewBufferSize));

  Status = HashOnly (
             NewBuffer,
             (UINTN)NewBufferSize,
             DigestList
             );
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Hashed image at %p of size %x successfully.\n", __func__, NewBuffer, NewBufferSize));
  } else {
    DEBUG ((DEBUG_ERROR, "%a Failed to hash image at %p of size %x - %r\n", __func__, NewBuffer, NewBufferSize, Status));
  }

Exit:
  if (InternalCopy != NULL) {
    FreePages (InternalCopy, EFI_SIZE_TO_PAGES (ImageSize + EFI_PAGE_SIZE - 1));
  }

  if (Buffer != NULL) {
    FreePages (Buffer, EFI_SIZE_TO_PAGES (ImageSize));
  }

  if (NewBuffer != NULL) {
    FreePages (NewBuffer, EFI_SIZE_TO_PAGES (NewBufferSize));
  }

  return Status;
}

/**
  Helper function to compare two digests inside TPML_DIGEST_VALUES.

  @param[in] DigestList1    The first digest to compare.
  @param[in] DigestList2    The second digest to compare.
  @param[in] TargetAlg      The algorithm to compare.

  @retval TRUE  The two digests are identical.
  @retval FALSE The two digests are different.
**/
BOOLEAN
EFIAPI
CompareDigest (
  IN TPML_DIGEST_VALUES  *DigestList1,
  IN TPML_DIGEST_VALUES  *DigestList2,
  IN TPMI_ALG_HASH       TargetAlgHash
  )
{
  UINTN    Index1;
  UINTN    Index2;
  BOOLEAN  Result;

  if ((DigestList1 == NULL) || (DigestList2 == NULL)) {
    Result = FALSE;
    goto Done;
  }

  Result = FALSE;
  for (Index1 = 0; Index1 < DigestList1->count; Index1++) {
    if (DigestList1->digests[Index1].hashAlg == TargetAlgHash) {
      break;
    }
  }

  if (Index1 == DigestList1->count) {
    Result = FALSE;
    goto Done;
  }

  for (Index2 = 0; Index2 < DigestList2->count; Index2++) {
    if (DigestList2->digests[Index2].hashAlg == TargetAlgHash) {
      break;
    }
  }

  if (Index2 == DigestList2->count) {
    Result = FALSE;
    goto Done;
  }

  switch (TargetAlgHash) {
    case TPM_ALG_SHA256:
      Result = CompareMem (DigestList1->digests[Index1].digest.sha256, DigestList2->digests[Index2].digest.sha256, SHA256_DIGEST_SIZE) == 0;
      break;
    case TPM_ALG_SHA384:
      Result = CompareMem (DigestList1->digests[Index1].digest.sha384, DigestList2->digests[Index2].digest.sha384, SHA384_DIGEST_SIZE) == 0;
      break;
    case TPM_ALG_SHA512:
      Result = CompareMem (DigestList1->digests[Index1].digest.sha512, DigestList2->digests[Index2].digest.sha512, SHA512_DIGEST_SIZE) == 0;
      break;
    default:
      Result = FALSE;
  }

Done:
  return Result;
}

/**
  The main validation routine for the SEA Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then hash
  the content using TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and hash using TPM.

  @param[in]  CpuIndex           The index of the CPU.
  @param[in]  AuxFileBase        The base address of the auxiliary file.
  @param[in]  AuxFileSize        The size of the auxiliary file.
  @param[in]  MmiEntryFileSize   The size of the MMI entry file.
  @param[in]  GoldDigestList     The digest list of the MMI entry and supervisor core.
  @param[in]  GoldDigestListCnt  The count of the digest list.
  @param[out] NewPolicy          The new policy populated by this routine.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SeaResponderReport (
  IN  UINTN                 CpuIndex,
  IN  EFI_PHYSICAL_ADDRESS  AuxFileBase,
  IN  UINT64                AuxFileSize,
  IN  UINT64                MmiEntryFileSize,
  IN  TPML_DIGEST_VALUES    *GoldDigestList,
  IN  UINTN                 GoldDigestListCnt,
  OUT VOID                  **NewPolicy  OPTIONAL
  )
{
  EFI_STATUS                        Status;
  UINT64                            MmBase;
  UINT32                            MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX    VirPhyAddressSize;
  UINT16                            *FixStructPtr;
  UINT32                            *Fixup32Ptr;
  UINT64                            *Fixup64Ptr;
  BOOLEAN                           IsInside;
  UINTN                             Index;
  UINT8                             *LocalMmiEntryBase = NULL;
  PER_CORE_MMI_ENTRY_STRUCT_HDR     *MmiEntryStructHdr;
  UINT32                            MmiEntryStructHdrSize;
  EFI_PHYSICAL_ADDRESS              MmSupervisorBase;
  UINT64                            MmSupervisorImageSize;
  UINT64                            FirmwarePolicyBase;
  EFI_PHYSICAL_ADDRESS              SupvPageTableBase;
  TPML_DIGEST_VALUES                DigestList;
  UINT8                             *DrtmSmmPolicyData;
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *FirmwarePolicy;
  KEY_SYMBOL                        *KeySymbols;
  PE_COFF_LOADER_IMAGE_CONTEXT      ImageContext;
  IMAGE_VALIDATION_DATA_HEADER      *AuxFileHdr;

  KEY_SYMBOL  *FirmwarePolicySymbol = NULL;
  KEY_SYMBOL  *PageTableSymbol      = NULL;
  KEY_SYMBOL  *MmiRendezvousSymbol  = NULL;

  // Step 1: Basic check on the validity of inputs
  if ((GoldDigestList == NULL) || (GoldDigestListCnt != SUPPORTED_DIGEST_COUNT)) {
    DEBUG ((DEBUG_ERROR, "%a Input is not supported GoldDigestList: %p and GoldDigestListCnt: %d\n", __func__, GoldDigestList, GoldDigestListCnt));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  // Step 2: Check MM Entry code base and size to be inside the MMRAM region

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunction, NULL, NULL, NULL);

  if (MaxExtendedFunction >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  MmBase = AsmReadMsr64 (MSR_IA32_SMBASE);
  if (MmBase == 0) {
    DEBUG ((DEBUG_ERROR, "%a Host system has NULL MMBASE for core 0x%x\n", __func__, CpuIndex));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (!IsBufferInsideMmram (MmBase + SMM_HANDLER_OFFSET, MmiEntryFileSize)) {
    DEBUG ((DEBUG_ERROR, "%a Reported MM entry code (0x%p: 0x%x) does not reside inside MMRAM region\n", __func__, MmBase + SMM_HANDLER_OFFSET, MmiEntryFileSize));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  AuxFileHdr = (IMAGE_VALIDATION_DATA_HEADER *)(VOID *)AuxFileBase;
  if (AuxFileHdr == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Reported aux file base address is NULL!\n", __func__));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (AuxFileHdr->Size > AuxFileSize) {
    DEBUG ((DEBUG_ERROR, "%a Reported aux file size is larger than the actual size 0x%x 0x%x\n", __func__, AuxFileHdr->Size, AuxFileSize));
    Status = EFI_COMPROMISED_DATA;
    goto Exit;
  }

  if (!IsBufferInsideMmram (AuxFileBase, AuxFileHdr->Size)) {
    DEBUG ((DEBUG_ERROR, "%a Reported aux file (0x%p: 0x%x) does not reside in MMRAM region!\n", __func__, AuxFileBase, AuxFileHdr->Size));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (AuxFileHdr->HeaderSignature != IMAGE_VALIDATION_DATA_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "%a Reported aux file does not have valid signature 0x%p 0x%x\n", __func__, AuxFileHdr, AuxFileHdr->HeaderSignature));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  KeySymbols = (KEY_SYMBOL *)((UINT8 *)AuxFileHdr + AuxFileHdr->OffsetToFirstKeySymbol);

  for (Index = 0; Index < AuxFileHdr->KeySymbolCount; Index++) {
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
    DEBUG ((DEBUG_ERROR, "%a Some key symbols of the supervisor core are not found policy: 0x%p, page table: 0x%p, rendezvous 0x%p.\n", __func__, FirmwarePolicySymbol, PageTableSymbol, MmiRendezvousSymbol));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 2.1: Check basic entry fix up data region to be pointing inside the MMRAM region
  LocalMmiEntryBase = AllocatePages (EFI_SIZE_TO_PAGES (MmiEntryFileSize));
  if (LocalMmiEntryBase == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate memory for local MM entry code.\n", __func__));
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  CopyMem (LocalMmiEntryBase, (VOID *)(UINTN)(MmBase + SMM_HANDLER_OFFSET), MmiEntryFileSize);

  MmiEntryStructHdrSize = *(UINT32 *)(UINTN)(LocalMmiEntryBase + MmiEntryFileSize - sizeof (MmiEntryStructHdrSize));
  MmiEntryStructHdr     = (PER_CORE_MMI_ENTRY_STRUCT_HDR *)(UINTN)(LocalMmiEntryBase + MmiEntryFileSize - MmiEntryStructHdrSize - sizeof (MmiEntryStructHdrSize));

  if ((MmiEntryStructHdrSize >= MmiEntryFileSize) ||
      (MmiEntryStructHdr->HeaderVersion > MMI_ENTRY_STRUCT_VERSION))
  {
    DEBUG ((DEBUG_ERROR, "%a MM entry code has unrecognized version %x or invalid size %x.\n", __func__, MmiEntryStructHdr->HeaderVersion, MmiEntryStructHdrSize));
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

  // We need to revert some regions before making the hash
  FixStructPtr = (UINT16 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUpStructOffset);
  for (Index = 0; Index < (MmiEntryStructHdr->FixUpStructNum * 2); Index += 2) {
    // Do not let the data in structure go wild...
    if (FixStructPtr[Index + 1] + FixStructPtr[Index] < MmiEntryFileSize - MmiEntryStructHdrSize) {
      ZeroMem ((VOID *)(UINTN)(LocalMmiEntryBase + FixStructPtr[Index + 1]), FixStructPtr[Index]);
    }
  }

  // Step 2.2: Hash MMI entry code block
  ZeroMem (&DigestList, sizeof (DigestList));
  Status = HashOnly (
             (VOID *)(UINTN)(LocalMmiEntryBase),
             (UINTN)MmiEntryFileSize - MmiEntryStructHdrSize - sizeof (MmiEntryStructHdrSize),
             &DigestList
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a HashOnly of MM entry code failed %r.\n", __func__, Status));
    goto Exit;
  } else {
    if (!CompareDigest (&GoldDigestList[MMI_ENTRY_DIGEST_INDEX], &DigestList, TPM_ALG_SHA256)) {
      DEBUG ((DEBUG_ERROR, "%a Hash of MM entry code does not match expectation! Calculated:\n", __func__));
      DUMP_HEX (DEBUG_ERROR, 0, &DigestList, sizeof (TPML_DIGEST_VALUES), "    ");
      Status = EFI_SECURITY_VIOLATION;
      goto Exit;
    }
  }

  // Step 3: Check MM Core code base and size to be inside the MMRAM region
  Fixup32Ptr = (UINT32 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp32Offset);
  Fixup64Ptr = (UINT64 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp64Offset);

  // Step 3.1: Pick a few entries to verify that they are pointing inside the MM CORE or MMRAM region
  // Reverse engineer MM core region with MM rendezvous
  MmSupervisorBase = Fixup64Ptr[FIXUP64_SMI_RDZ_ENTRY] - MmiRendezvousSymbol->Offset;
  ZeroMem (&ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));
  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
  ImageContext.Handle    = (VOID *)MmSupervisorBase;

  DEBUG ((DEBUG_ERROR, "%a AuxFileBase: 0x%x, MmiRendezvousSymbol: 0x%x\n", __func__, AuxFileBase, MmiRendezvousSymbol));
  DEBUG ((DEBUG_ERROR, "%a MmiRendezvousSymbol Offset: 0x%x\n", __func__, MmiRendezvousSymbol->Offset));
  DEBUG ((DEBUG_ERROR, "%a MmBase + SMM_HANDLER_OFFSET: 0x%x:\n", __func__, MmBase + SMM_HANDLER_OFFSET));
  DEBUG ((DEBUG_ERROR, "%a LocalMmiEntryBase: 0x%p:\n", __func__, LocalMmiEntryBase));
  DEBUG ((DEBUG_ERROR, "%a MmSupervisorBase: 0x%x:\n", __func__, MmSupervisorBase));

  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - ImageContext->ImageError = 0x%x.\n", __func__, ImageContext.ImageError));
    DEBUG ((DEBUG_ERROR, "%a Failed to get MM supervisor image info %r.\n", __func__, Status));
    goto Exit;
  }

  MmSupervisorImageSize = ImageContext.ImageSize;

  if (!IsBufferInsideMmram (MmSupervisorBase, MmSupervisorImageSize)) {
    DEBUG ((DEBUG_ERROR, "%a Calculated MM supervisor core image (0x%p: 0x%x) does not reside inside MMRAM.\n", __func__, MmSupervisorBase, MmSupervisorImageSize));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // GDTR and its content should be pointing inside the MMRAM region
  if (!IsBufferInsideMmram (Fixup32Ptr[FIXUP32_GDTR], sizeof (IA32_DESCRIPTOR))) {
    DEBUG ((DEBUG_ERROR, "%a GDTR is not inside MMRAM region %x %x.\n", __func__, Fixup32Ptr[FIXUP32_GDTR], sizeof (IA32_DESCRIPTOR)));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (!IsBufferInsideMmram (((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Base, ((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Limit + 1)) {
    DEBUG ((DEBUG_ERROR, "%a GDTR base is not inside MMRAM region %x %x.\n", __func__, ((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Base, ((IA32_DESCRIPTOR *)(UINTN)Fixup32Ptr[FIXUP32_GDTR])->Limit + 1));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // CR3 should be pointing to the page table from symbol list in the aux file
  SupvPageTableBase = *(EFI_PHYSICAL_ADDRESS *)(MmSupervisorBase + PageTableSymbol->Offset);
  if (Fixup32Ptr[FIXUP32_CR3_OFFSET] != SupvPageTableBase) {
    DEBUG ((DEBUG_ERROR, "%a Calculated page table 0x%p does not match MM entry code populated value 0x%p.\n", __func__, SupvPageTableBase, Fixup32Ptr[FIXUP32_CR3_OFFSET]));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // CR3 should be pointing inside the MMRAM region
  if (!IsBufferInsideMmram (Fixup32Ptr[FIXUP32_CR3_OFFSET], sizeof (UINT32))) {
    DEBUG ((DEBUG_ERROR, "%a Page table pointer 0x%p does not reside inside MMRAM!!!.\n", __func__, Fixup32Ptr[FIXUP32_CR3_OFFSET]));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Supervisor stack should be pointing inside the MMRAM region
  if (!IsBufferInsideMmram (Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0], sizeof (UINT32))) {
    DEBUG ((DEBUG_ERROR, "%a Poplated supervisor stack 0x%p does not reside inside MMRAM!!!.\n", __func__, Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0]));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // SMM BASE... should be MMBASE...
  if (Fixup32Ptr[FIXUP32_MSR_SMM_BASE] != MmBase) {
    DEBUG ((DEBUG_ERROR, "%a Poplated MMBASE 0x%p does not match MSR value 0x%p!!!.\n", __func__, Fixup32Ptr[FIXUP32_MSR_SMM_BASE], MmBase));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM debug entry should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY], sizeof (UINT64), MmSupervisorBase, MmSupervisorImageSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    DEBUG ((DEBUG_ERROR, "%a MM debug entry 0x%p does not reside inside MM supervisor 0x%p - 0x%x!!!.\n", __func__, Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY], MmSupervisorBase, MmSupervisorImageSize));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM debug exit should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMM_DBG_EXIT], sizeof (UINT64), MmSupervisorBase, MmSupervisorImageSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    DEBUG ((DEBUG_ERROR, "%a MM debug exit 0x%p does not reside inside MM supervisor 0x%p - 0x%x!!!.\n", __func__, Fixup64Ptr[FIXUP64_SMM_DBG_EXIT], MmSupervisorBase, MmSupervisorImageSize));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM IDTR should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMI_HANDLER_IDTR], sizeof (IA32_DESCRIPTOR), MmSupervisorBase, MmSupervisorImageSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    DEBUG ((DEBUG_ERROR, "%a MM hander IDTR 0x%p does not reside inside MM supervisor 0x%p - 0x%x!!!.\n", __func__, Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY], MmSupervisorBase, MmSupervisorImageSize));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Then also verify that the firmware policy is inside the MMRAM
  FirmwarePolicyBase = *(UINT64 *)(MmSupervisorBase + FirmwarePolicySymbol->Offset);
  if (!IsBufferInsideMmram (FirmwarePolicyBase, sizeof (UINT64))) {
    DEBUG ((DEBUG_ERROR, "%a Reported firmware policy 0x%p does not reside inside MMRAM!!!.\n", __func__, FirmwarePolicyBase));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 3.2: Hash MM Core code
  Status = VerifyAndHashImage (
             MmSupervisorBase,
             MmSupervisorImageSize,
             AuxFileHdr,
             SupvPageTableBase,
             &DigestList
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to VerifyAndHashImage %r!!!.\n", __func__, Status));
    goto Exit;
  }

  if (!CompareDigest (&GoldDigestList[MM_SUPV_DIGEST_INDEX], &DigestList, TPM_ALG_SHA256)) {
    DEBUG ((DEBUG_ERROR, "%a Hash of MM core does not match expectation! Calculated:\n", __func__));
    DUMP_HEX (DEBUG_ERROR, 0, &DigestList, sizeof (TPML_DIGEST_VALUES), "    ");
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (GoldDigestList != NULL) {
    CopyMem (GoldDigestList + 1, &DigestList, sizeof (DigestList));
  }

  FirmwarePolicy = (SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)FirmwarePolicyBase;

  // Step 4: Report MM Secure Policy code
  DrtmSmmPolicyData = AllocatePages (EFI_SIZE_TO_PAGES (FirmwarePolicy->Size + MEM_POLICY_SNAPSHOT_SIZE));
  if (DrtmSmmPolicyData == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate for policy data!!!.\n", __func__));
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  ZeroMem (DrtmSmmPolicyData, FirmwarePolicy->Size + MEM_POLICY_SNAPSHOT_SIZE);

  // First off, copy the firmware policy to the buffer
  CopyMem (DrtmSmmPolicyData, FirmwarePolicy, FirmwarePolicy->Size);

  // Then leave the heavy lifting job to the library
  Status = PopulateMemoryPolicyEntries ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)DrtmSmmPolicyData, FirmwarePolicy->Size + MEM_POLICY_SNAPSHOT_SIZE, SupvPageTableBase);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Fail to PopulateMemoryPolicyEntries %r\n", __func__, Status));
    goto Exit;
  }

  Status = SecurityPolicyCheck ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)DrtmSmmPolicyData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Policy check failed - %r\n", __func__, Status));
    goto Exit;
  }

  DEBUG_CODE_BEGIN ();
  DumpSmmPolicyData ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(UINTN)DrtmSmmPolicyData);
  DEBUG_CODE_END ();

  if (NewPolicy != NULL) {
    *NewPolicy = DrtmSmmPolicyData;
  }

Exit:
  if (LocalMmiEntryBase != NULL) {
    FreePages (LocalMmiEntryBase, EFI_SIZE_TO_PAGES (MmiEntryFileSize));
  }

  return Status;
}
