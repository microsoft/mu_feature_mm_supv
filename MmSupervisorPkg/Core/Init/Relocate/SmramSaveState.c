/** @file
Provides services to access SMRAM Save State Map

Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <SmmSecurePolicy.h>
#include <SeaResponder.h>

#include <Library/SmmCpuFeaturesLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/SysCallLib.h>
#include <Library/IhvSmmSaveStateSupervisionLib.h>

#include "Relocate.h"
#include "Mem/Mem.h"
#include "../../Common/MpService.h"
#include "MmSupervisorCore.h"

typedef struct {
  UINT64    Signature;                                      // Offset 0x00
  UINT16    Reserved1;                                      // Offset 0x08
  UINT16    Reserved2;                                      // Offset 0x0A
  UINT16    Reserved3;                                      // Offset 0x0C
  UINT16    SmmCs;                                          // Offset 0x0E
  UINT16    SmmDs;                                          // Offset 0x10
  UINT16    SmmSs;                                          // Offset 0x12
  UINT16    SmmOtherSegment;                                // Offset 0x14
  UINT16    Reserved4;                                      // Offset 0x16
  UINT64    Reserved5;                                      // Offset 0x18
  UINT64    Reserved6;                                      // Offset 0x20
  UINT64    Reserved7;                                      // Offset 0x28
  UINT64    SmmGdtPtr;                                      // Offset 0x30
  UINT32    SmmGdtSize;                                     // Offset 0x38
  UINT32    Reserved8;                                      // Offset 0x3C
  UINT64    Reserved9;                                      // Offset 0x40
  UINT64    Reserved10;                                     // Offset 0x48
  UINT16    Reserved11;                                     // Offset 0x50
  UINT16    Reserved12;                                     // Offset 0x52
  UINT32    Reserved13;                                     // Offset 0x54
  UINT64    Reserved14;                                     // Offset 0x58
} PROCESSOR_SMM_DESCRIPTOR;

extern CONST PROCESSOR_SMM_DESCRIPTOR  gcPsd;

//
// EFER register LMA bit
//
#define LMA  BIT10

///
/// Structure used to build a lookup table for the IOMisc width information
///
typedef struct {
  UINT8                          Width;
  EFI_SMM_SAVE_STATE_IO_WIDTH    IoWidth;
} CPU_SMM_SAVE_STATE_IO_WIDTH;

typedef struct {
  EFI_MM_CPU_PROTOCOL           *UserMmCpuProtocol;
  EFI_MM_SAVE_STATE_REGISTER    Register;
  UINTN                         CpuIndex;
  UINTN                         Width;
  VOID                          *Buffer;
  UINTN                         CompletedSyscall;
} USER_SAVE_STATE_ACCESS_STRUCT;

USER_SAVE_STATE_ACCESS_STRUCT  UserSaveStateAccessHolder;

// ///
// /// Variables from SMI Handler
// ///
// X86_ASSEMBLY_PATCH_LABEL  gPatchSmbase;
// X86_ASSEMBLY_PATCH_LABEL  gPatchSmiStack;
// X86_ASSEMBLY_PATCH_LABEL  gPatchSmiCr3;
// // TODO: This should not be here
// X86_ASSEMBLY_PATCH_LABEL  mSmiHandlerIdtr;
// X86_ASSEMBLY_PATCH_LABEL  gSmiRendezvous;
// X86_ASSEMBLY_PATCH_LABEL  gMmSupvHobStart;

extern VOID *SmiRendezvous;
// extern volatile UINT8     gcSmiHandlerTemplate[];
// extern CONST UINT16       gcSmiHandlerSize;

//
// Variables used by SMI Handler
//
IA32_DESCRIPTOR  *gSmiHandlerIdtr = NULL;
IA32_DESCRIPTOR  *mGdtrPtr = NULL;

///
/// The mode of the CPU at the time an SMI occurs
///
UINT8  mSmmSaveStateRegisterLma;

EFI_PHYSICAL_ADDRESS  mMmiEntryBaseAddress;
UINTN                 mMmiEntrySize;
extern UINT32         mCetPl0Ssp;
extern UINT32         mCetInterruptSsp;
extern UINT32         mCetInterruptSspTable;

/**
  Get the size of the SMI Handler in bytes.

  @retval The size, in bytes, of the SMI Handler.

**/
UINTN
EFIAPI
GetSmiHandlerSize (
  VOID
  )
{
  UINTN  Size;

  Size = SmmCpuFeaturesGetSmiHandlerSize ();
  if (Size != 0) {
    return Size;
  }

  if (mMmiEntrySize != 0) {
    return mMmiEntrySize;
  }

  return 0;
}

/**
  Lookup the MMI entry in the FV HOBs.

  @param[out] BaseAddress  The base address of the MMI entry.
  @param[out] Size         The size of the MMI entry.

  @retval EFI_SUCCESS           The MMI entry was found.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
  @retval EFI_NOT_FOUND         The MMI entry was not found.
**/
EFI_STATUS
LookupMmiEntryInFvHobs (
  OUT UINTN  *BaseAddress,
  OUT UINTN  *Size
  )
{
  UINT16                          ExtHeaderOffset;
  EFI_FIRMWARE_VOLUME_HEADER      *FwVolHeader;
  EFI_FIRMWARE_VOLUME_EXT_HEADER  *ExtHeader;
  EFI_FFS_FILE_HEADER             *FileHeader;
  EFI_PEI_HOB_POINTERS            Hob;
  EFI_STATUS                      Status;
  BOOLEAN                         MmiEntryFound     = FALSE;
  VOID                            *RawMmiEntryFileData;

  if (BaseAddress == NULL || Size == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Hob.Raw = GetHobList ();
  if (Hob.Raw == NULL) {
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  do {
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, Hob.Raw);
    if (Hob.Raw != NULL) {
      FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)(Hob.FirmwareVolume->BaseAddress);

      DEBUG ((
        DEBUG_INFO,
        "[%a] Found FV HOB referencing FV at 0x%x. Size is 0x%x.\n",
        __func__,
        (UINTN)FwVolHeader,
        FwVolHeader->FvLength
        ));

      ExtHeaderOffset = ReadUnaligned16 (&FwVolHeader->ExtHeaderOffset);
      if (ExtHeaderOffset != 0) {
        ExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)((UINT8 *)FwVolHeader + ExtHeaderOffset);
        DEBUG ((DEBUG_INFO, "[%a]   FV GUID = {%g}.\n", __func__, &ExtHeader->FvName));
      }

      //
      // If a MM_STANDALONE or MM_CORE_STANDALONE driver is in the FV. Add the drivers
      // to the dispatch list. Mark the FV with this driver as the Standalone BFV.
      //
      FileHeader = NULL;
      do {
        Status =  FfsFindNextFile (
                    EFI_FV_FILETYPE_FREEFORM,
                    FwVolHeader,
                    &FileHeader
                    );
        if (!EFI_ERROR (Status)) {
          if (CompareGuid (&FileHeader->Name, &gMmiEntrySeaFileGuid)) {
            if (MmiEntryFound) {
              Status = EFI_ALREADY_STARTED;
              break;
            }

            Status = FfsFindSectionData (EFI_SECTION_RAW, FileHeader, &RawMmiEntryFileData, &mMmiEntrySize);
            if (!EFI_ERROR (Status)) {
              *BaseAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)RawMmiEntryFileData;
              *Size = mMmiEntrySize;
            } else {
              DEBUG ((DEBUG_ERROR, "[%a]   Failed to load MmiEntry [%g] in FV at 0x%p of %x bytes - %r.\n", __func__, &gMmiEntrySeaFileGuid, FileHeader, FileHeader->Size, Status));
              break;
            }

            DEBUG ((
              DEBUG_INFO,
              "[%a]   Discovered MMI Entry for SEA [%g] in FV at 0x%p of %x bytes.\n",
              __func__,
              &gMmiEntrySeaFileGuid,
              *BaseAddress,
              *Size
              ));
            MmiEntryFound = TRUE;
          }

          if (MmiEntryFound) {
            // Job done, break out of the loop
            Status = EFI_SUCCESS;
            break;
          }
        }
      } while (!EFI_ERROR (Status));

      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);

  if (!MmiEntryFound) {
    DEBUG ((DEBUG_ERROR, "[%a]   Required entries for SEA not found in any FV.\n", __func__));
    Status = EFI_NOT_FOUND;
  } else {
    Status = EFI_SUCCESS;
  }

Done:
  return Status;
}

/**
  Install the SMI handler for the CPU specified by CpuIndex.  This function
  is called by the CPU that was elected as monarch during System Management
  Mode initialization.

  @param[in] CpuIndex   The index of the CPU to install the custom SMI handler.
                        The value must be between 0 and the NumberOfCpus field
                        in the System Management System Table (SMST).
  @param[in] SmBase     The SMBASE address for the CPU specified by CpuIndex.
  @param[in] SmiStack   The stack to use when an SMI is processed by the
                        the CPU specified by CpuIndex.
  @param[in] StackSize  The size, in bytes, if the stack used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtBase    The base address of the GDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtSize    The size, in bytes, of the GDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtBase    The base address of the IDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtSize    The size, in bytes, of the IDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] Cr3        The base address of the page tables to use when an SMI
                        is processed by the CPU specified by CpuIndex.
**/
VOID
EFIAPI
InstallSmiHandler (
  IN UINTN   CpuIndex,
  IN UINT32  SmBase,
  IN VOID    *SmiStack,
  IN UINTN   StackSize,
  IN UINTN   GdtBase,
  IN UINTN   GdtSize,
  IN UINTN   IdtBase,
  IN UINTN   IdtSize,
  IN UINT32  Cr3
  )
{
  PROCESSOR_SMM_DESCRIPTOR  *Psd;
  UINT32                    CpuSmiStack;
  EFI_STATUS                Status;
  PER_CORE_MMI_ENTRY_STRUCT_HDR  *SmiEntryStructHdrPtr = NULL;
  UINT32                         SmiEntryStructHdrAddr;
  UINT32                         WholeStructSize;
  UINT32                         *Fixup32Ptr;
  UINT64                         *Fixup64Ptr;
  UINT8                          *Fixup8Ptr;

  //
  // Initialize PROCESSOR_SMM_DESCRIPTOR
  //
  Psd = (PROCESSOR_SMM_DESCRIPTOR *)(VOID *)((UINTN)SmBase + SMM_PSD_OFFSET);
  CopyMem (Psd, &gcPsd, sizeof (gcPsd));
  Psd->SmmGdtPtr  = (UINT64)GdtBase;
  Psd->SmmGdtSize = (UINT32)GdtSize;

  if (SmmCpuFeaturesGetSmiHandlerSize () != 0) {
    //
    // Install SMI handler provided by library
    //
    SmmCpuFeaturesInstallSmiHandler (
      CpuIndex,
      SmBase,
      SmiStack,
      StackSize,
      GdtBase,
      GdtSize,
      IdtBase,
      IdtSize,
      Cr3
      );
    return;
  }

  InitShadowStack (CpuIndex, (VOID *)((UINTN)SmiStack + StackSize));

  //
  // Initialize values in template before copy
  //
  CpuSmiStack = (UINT32)((UINTN)SmiStack + StackSize - sizeof (UINTN));
  DEBUG ((DEBUG_ERROR, "[%a] - CpuSmiStack at 0x%x.\n", __func__, CpuSmiStack));

  // TODO: These values are marked as code page, but not read only.
  if (mGdtrPtr == NULL) {
    mGdtrPtr = AllocateCodePages (1);
  }

  if (gSmiHandlerIdtr == NULL) {
    gSmiHandlerIdtr = AllocateCodePages (1);
    gSmiHandlerIdtr->Base  = IdtBase;
    gSmiHandlerIdtr->Limit = (UINT16)(IdtSize - 1);
  }

  //
  // Set the value at the top of the CPU stack to the CPU Index
  //
  *(UINTN *)(UINTN)CpuSmiStack = CpuIndex;
  DEBUG ((DEBUG_ERROR, "[%a] - Set stack address (0x%x) to 0x%lx.\n", __func__, CpuSmiStack, CpuIndex));

  if (mMmiEntryBaseAddress == 0 || mMmiEntrySize == 0) {
    //
    // Lookup the MMI entry in the FV HOBs if not done before.
    //
    Status = LookupMmiEntryInFvHobs (&mMmiEntryBaseAddress, &mMmiEntrySize);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] Failed to find MMI entry in FV HOBs - %r.\n", __func__, Status));
      CpuDeadLoop ();
    }
  }

  //
  // Copy template to CPU specific SMI handler location from what is located from the FV
  //
  CopyMem (
    (VOID *)((UINTN)SmBase + SMM_HANDLER_OFFSET),
    (VOID *)mMmiEntryBaseAddress,
    mMmiEntrySize
    );

  mGdtrPtr[CpuIndex].Limit = (UINT16)GdtSize - 1;
  mGdtrPtr[CpuIndex].Base  = (UINTN)GdtBase;

  // Populate the fix up addresses
  // Get Whole structure size
  WholeStructSize = (UINT32)*(EFI_PHYSICAL_ADDRESS *)(UINTN)(SmBase + SMM_HANDLER_OFFSET + mMmiEntrySize - sizeof (UINT32));

  // Get header address
  SmiEntryStructHdrAddr = (UINT32)(SmBase + SMM_HANDLER_OFFSET + mMmiEntrySize - sizeof (UINT32) - WholeStructSize);
  SmiEntryStructHdrPtr  = (PER_CORE_MMI_ENTRY_STRUCT_HDR *)(UINTN)(SmiEntryStructHdrAddr);

  // Navigate to the fixup arrays
  Fixup32Ptr = (UINT32 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp32Offset);
  Fixup64Ptr = (UINT64 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp64Offset);
  Fixup8Ptr  = (UINT8 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp8Offset);

  // Do the fixup
  Fixup32Ptr[FIXUP32_mPatchCetPl0Ssp]            = mCetPl0Ssp;
  Fixup32Ptr[FIXUP32_GDTR]                       = (UINT32)(UINTN)&mGdtrPtr[CpuIndex];
  Fixup32Ptr[FIXUP32_CR3_OFFSET]                 = Cr3;
  Fixup32Ptr[FIXUP32_mPatchCetInterruptSsp]      = mCetInterruptSsp;
  Fixup32Ptr[FIXUP32_mPatchCetInterruptSspTable] = mCetInterruptSspTable;
  Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0]          = (UINT32)(UINTN)CpuSmiStack;
  Fixup32Ptr[FIXUP32_MSR_SMM_BASE]               = SmBase;

  Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY]    = 0;
  Fixup64Ptr[FIXUP64_SMM_DBG_EXIT]     = 0;
  Fixup64Ptr[FIXUP64_SMI_RDZ_ENTRY]    = (UINT64)SmiRendezvous;
  Fixup64Ptr[FIXUP64_XD_SUPPORTED]     = 0;
  Fixup64Ptr[FIXUP64_CET_SUPPORTED]    = 0;
  Fixup64Ptr[FIXUP64_SMI_HANDLER_IDTR] = (UINT64)gSmiHandlerIdtr;
  Fixup64Ptr[FIXUP64_HOB_START]         = (UINT64)(UINTN)mMmHobStart;

  Fixup8Ptr[FIXUP8_gPatchXdSupported] = TRUE;
  if (StandardSignatureIsAuthenticAMD ()) {
    //
    // AMD processors do not support MSR_IA32_MISC_ENABLE
    //
    Fixup8Ptr[FIXUP8_gPatchMsrIa32MiscEnableSupported] = FALSE;
  } else {
    Fixup8Ptr[FIXUP8_gPatchMsrIa32MiscEnableSupported] = TRUE;
  }

  Fixup8Ptr[FIXUP8_m5LevelPagingNeeded] = m5LevelPagingNeeded;
  Fixup8Ptr[FIXUP8_mPatchCetSupported]  = FALSE;

  // //
  // // Initialize values in template before copy
  // //
  // CpuSmiStack = (UINT32)((UINTN)SmiStack + StackSize - sizeof (UINTN));
  // PatchInstructionX86 (gPatchSmiStack, CpuSmiStack, 4);
  // PatchInstructionX86 (gPatchSmiCr3, Cr3, 4);
  // PatchInstructionX86 (gPatchSmbase, SmBase, 4);
  // gSmiHandlerIdtr = AllocateCodePages (1);
  // gSmiHandlerIdtr->Base  = IdtBase;
  // gSmiHandlerIdtr->Limit = (UINT16)(IdtSize - 1);
  // PatchInstructionX86 (mSmiHandlerIdtr, (UINTN)gSmiHandlerIdtr, 8);

  // PatchInstructionX86 (gSmiRendezvous, (UINTN)SmiRendezvous, 8);
  // PatchInstructionX86 (gMmSupvHobStart, (UINTN)mMmHobStart, 8);

  // //
  // // Set the value at the top of the CPU stack to the CPU Index
  // //
  // *(UINTN *)(UINTN)CpuSmiStack = CpuIndex;

  // //
  // // Copy template to CPU specific SMI handler location
  // //
  // CopyMem (
  //   (VOID *)((UINTN)SmBase + SMM_HANDLER_OFFSET),
  //   (VOID *)gcSmiHandlerTemplate,
  //   gcSmiHandlerSize
  //   );
}
