/** @file
  MM Core Main Entry Point

  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Register/Msr.h>
#include <Register/CpuId.h>
#include <Register/SmramSaveStateMap.h>
#include <SpamResponder.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffLibNegative.h>
#include <Library/Smx.h>
#include <Library/SafeIntLib.h>
#include <Library/TpmMeasurementLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

// TODO: What is this PCR?
#define SPAM_PCR_INDEX 0

EFI_STATUS
EFIAPI
TwoRangesOverlap (
  IN UINT64  Start1,
  IN UINT64  Size1,
  IN UINT64  Start2,
  IN UINT64  Size2,
  OUT BOOLEAN *Overlap
  )
{
  UINT64 End1;
  UINT64 End2;
  EFI_STATUS Status;

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

EFI_STATUS
EFIAPI
Range1InsideRange2 (
  IN UINT64  Start1,
  IN UINT64  Size1,
  IN UINT64  Start2,
  IN UINT64  Size2,
  OUT BOOLEAN *IsInside
  )
{
  EFI_STATUS Status;
  UINT64 End1;
  UINT64 End2;

  if (IsInside == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Size1 > Size2) {
    *IsInside = FALSE;
    Status = EFI_SUCCESS;
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

EFI_STATUS
EFIAPI
VerifyAndMeasureImage (
  IN UINTN    ImageBase,
  IN UINT64   ImageSize,
  IN UINT64   MmBase,
  IN UINT64   MmLength
  )
{
  EFI_STATUS Status;
  BOOLEAN    IsInside;
  VOID       *InternalCopy;

  // First need to make sure if this image is inside the MMRAM region
  Status = Range1InsideRange2 (ImageBase, ImageSize, MmBase, MmLength, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // TODO: Also need to make sure the ImageBase and ImageSize are page aligned

  // Then need to copy the image over to MSEG
  InternalCopy = AllocatePages (
    EFI_SIZE_TO_PAGES (ImageSize + EFI_PAGE_SIZE - 1)
    );

  // TODO: Now need to unrelocate the image...


Exit:
  if (InternalCopy != NULL) {
    FreePages (InternalCopy, EFI_SIZE_TO_PAGES (ImageSize + EFI_PAGE_SIZE - 1));
  }
  return Status;
}

// TODO: Consume newly created key symbols
extern UINT64 MmSupvEfiFileBase;
extern UINT64 MmSupvEfiFileSize;
extern UINT64 MmSupvAuxFileBase;
extern UINT64 MmSupvAuxFileSize;

EFI_STATUS
EFIAPI
SpamResponderReport (
  IN SPAM_RESPONDER_DATA *SpamResponderData
  )
{
  EFI_STATUS                      Status;
  UINT64                          MmBase;
  UINT64                          MmRamBase;
  UINT64                          MmrrMask;
  UINT32                          MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX  VirPhyAddressSize;
  UINT64      Length;
  UINT64      MtrrValidBitsMask;
  UINT64      MtrrValidAddressMask;
  // UINT64      Index;
  UINT16                    *FixStructPtr;
  UINT8                     *Fixup8Ptr;
  UINT32                    *Fixup32Ptr;
  UINT64                    *Fixup64Ptr;
  BOOLEAN                   IsInside;

  PER_CORE_MMI_ENTRY_STRUCT_HDR   *MmiEntryStructHdr;
  UINT32                          MmiEntryStructHdrSize;

  // USER_MODULE_INFO                *UserModuleInfoArray;

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
            (SpamResponderData->VersionMinor > SPAM_REPSONDER_STRUCT_MINOR_VER)) {
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
  MmrrMask = AsmReadMsr64 (MSR_IA32_SMRR_PHYSMASK);
  // Extend the mask to account for the reserved bits.
  MmrrMask |= 0xffffffff00000000ULL;
  Length = ((~(MmrrMask & MtrrValidAddressMask)) & MtrrValidBitsMask) + 1;
  MmBase = AsmReadMsr64 (MSR_IA32_SMBASE);
  if ((MmBase == 0) ||
      (MmBase + SMM_HANDLER_OFFSET != SpamResponderData->MmEntryBase)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Status = Range1InsideRange2 (SpamResponderData->MmEntryBase, SpamResponderData->MmEntrySize, MmBase, Length, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 2.1: Measure MMI entry code
  // Record SMI_ENTRY_HASH to PCR 0, just in case it is NOT TXT launch, we still need provide the evidence.
  Status = TpmMeasureAndLogData (
              SPAM_PCR_INDEX,                                 // PcrIndex
              SPAM_EVTYPE_MM_ENTRY_HASH,                      // EventType
              NULL,                                           // EventLog
              0,                                              // LogLen
              (VOID *)(UINTN)SpamResponderData->MmEntryBase,  // HashData
              SpamResponderData->MmEntrySize                  // HashDataLen
              );
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // Step 3: Check MM Core code base and size to be inside the MMRAM region
  if ((MmRamBase > SpamResponderData->MmSupervisorBase) ||
      (MmRamBase + Length < SpamResponderData->MmSupervisorBase + SpamResponderData->MmSupervisorSize)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 3.1: Check entry fix up data region to be pointing inside the MMRAM region
  MmiEntryStructHdrSize = *(UINT32*)(UINTN)(SpamResponderData->MmEntryBase + SpamResponderData->MmEntrySize - sizeof (MmiEntryStructHdrSize));
  MmiEntryStructHdr = (PER_CORE_MMI_ENTRY_STRUCT_HDR*)(UINTN)(SpamResponderData->MmEntryBase + SpamResponderData->MmEntrySize - MmiEntryStructHdrSize);

  if (MmiEntryStructHdr->HeaderVersion > MMI_ENTRY_STRUCT_VERSION) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  FixStructPtr = (UINT16 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUpStructOffset);
  Fixup32Ptr = (UINT32 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp32Offset);
  Fixup64Ptr = (UINT64 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp64Offset);
  Fixup8Ptr = (UINT8 *)(UINTN)((UINTN)MmiEntryStructHdr + MmiEntryStructHdr->FixUp8Offset);

  // Step 3.1.1: Pick a few entries to verify that they are pointing inside the MM CORE or MMRAM region

  // GDTR should be pointing inside the MM CORE region
  Status = Range1InsideRange2 (Fixup32Ptr[FIXUP32_GDTR], sizeof (UINT32), SpamResponderData->MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // CR3 should be pointing inside the MMRAM region
  Status = Range1InsideRange2 (Fixup32Ptr[FIXUP32_CR3_OFFSET], sizeof (UINT32), MmBase, Length, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Supervisor stack should be pointing inside the MMRAM region
  Status = Range1InsideRange2 (Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0], sizeof (UINT32), MmBase, Length, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // SMM BASE... should be MMBASE...
  if (Fixup32Ptr[FIXUP32_MSR_SMM_BASE] != MmBase) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM debug entry should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY], sizeof (UINT64), SpamResponderData->MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM rendezvous should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMI_RDZ_ENTRY], sizeof (UINT64), SpamResponderData->MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM debug exit should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMM_DBG_EXIT], sizeof (UINT64), SpamResponderData->MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // MM IDTR should be in the MM CORE region
  Status = Range1InsideRange2 (Fixup64Ptr[FIXUP64_SMI_HANDLER_IDTR], sizeof (UINT64), SpamResponderData->MmSupervisorBase, SpamResponderData->MmSupervisorSize, &IsInside);
  if (EFI_ERROR (Status) || !IsInside) {
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Step 3.2: Measure MM Core code
  //
  // Get information about the image being loaded
  //
  PE_COFF_LOADER_IMAGE_CONTEXT ImageContext;

  ZeroMem (&ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));
  VOID *Buffer = AllocatePages (EFI_SIZE_TO_PAGES (SpamResponderData->MmSupervisorSize));
  CopyMem (Buffer, (VOID*)(UINTN)SpamResponderData->MmSupervisorBase, SpamResponderData->MmSupervisorSize);

  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
  ImageContext.Handle    = (VOID*)Buffer;

  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  ImageContext.DestinationAddress = (EFI_PHYSICAL_ADDRESS)(VOID*)Buffer;
  Status = PeCoffLoaderRevertRelocateImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = PeCoffImageDiffValidation ((VOID*)SpamResponderData->MmSupervisorBase, Buffer, SpamResponderData->MmSupervisorSize, (VOID*)(UINTN)MmSupvAuxFileBase, MmSupvAuxFileSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // Now prepare a new buffer to revert loading operations.
  UINTN NewBufferSize = SpamResponderData->MmSupervisorSize;
  VOID *NewBuffer = AllocatePages (EFI_SIZE_TO_PAGES (NewBufferSize));
  ZeroMem (NewBuffer, NewBufferSize);

  DEBUG ((DEBUG_INFO, "%p %p %p\n", SpamResponderData->MmSupervisorBase, Buffer, NewBuffer));

  // At this point we dealt with the relocation, some data are still off.
  // Next we unload the image in the copy.
  Status = PeCoffLoaderRevertLoadImage (&ImageContext, NewBuffer, &NewBufferSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a Reverted image at %p of size %x\n", __func__, NewBuffer, NewBufferSize));
  ASSERT (MmSupvEfiFileSize == NewBufferSize);
  ASSERT (CompareMem (NewBuffer, (VOID*)(UINTN)MmSupvEfiFileBase, MmSupvEfiFileSize) == 0);

  Status = VerifyAndMeasureImage (
             SpamResponderData->MmSupervisorBase,
             SpamResponderData->MmSupervisorSize,
             SPAM_PCR_INDEX,
             SPAM_EVTYPE_MM_CORE_HASH
             );
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // // Step 4: Measure User mode MM code
  // UserModuleInfoArray = (USER_MODULE_INFO*)((UINTN)SpamResponderData + SpamResponderData->UserModuleOffset);
  // for (Index = 0; Index < SpamResponderData->UserModuleCount; Index++) {
  //   Status = VerifyAndMeasureImage (
  //              UserModuleInfoArray[Index].UserModuleBase,
  //              UserModuleInfoArray[Index].UserModuleSize,
  //              SPAM_PCR_INDEX,
  //              SPAM_EVTYPE_MM_USER_MODULE_HASH
  //              );
  //   if (EFI_ERROR (Status)) {
  //     goto Exit;
  //   }
  // }

  // Step 5: Report MM Secure Policy code
  // TODO: How to do this? I would like to keep the structure the same though...

Exit:
  return Status;
}
