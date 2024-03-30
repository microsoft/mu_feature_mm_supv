/** @file
  SMM STM support functions

  Copyright (c) 2015 - 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>
#include <SpamResponder.h>
#include <Library/FvLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/TpmMeasurementLib.h>
#include <Guid/MpInformation.h>
#include <Guid/MmCoreData.h>
#include <Protocol/MmEndOfDxe.h>
#include <Register/Intel/Cpuid.h>
#include <Register/Intel/ArchitecturalMsr.h>
#include <Register/Intel/SmramSaveStateMap.h>

#include <Protocol/LoadedImage.h>

#include "CpuFeaturesLib.h"
#include "SmmStm.h"

#define TXT_EVTYPE_BASE      0x400
#define TXT_EVTYPE_STM_HASH  (TXT_EVTYPE_BASE + 14)

#define CODE_SEL  0x38
#define DATA_SEL  0x40
#define TR_SEL    0x68

#define RDWR_ACCS  3
#define FULL_ACCS  7

BOOLEAN  mLockLoadMonitor = FALSE;

//
// Template of STM_RSC_END structure for copying.
//
GLOBAL_REMOVE_IF_UNREFERENCED STM_RSC_END  mRscEndNode = {
  { END_OF_RESOURCES, sizeof (STM_RSC_END) },
};

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  *mStmResourcesPtr         = NULL;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN  mStmResourceTotalSize     = 0x0;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN  mStmResourceSizeUsed      = 0x0;
GLOBAL_REMOVE_IF_UNREFERENCED UINTN  mStmResourceSizeAvailable = 0x0;

GLOBAL_REMOVE_IF_UNREFERENCED UINT32  mStmState = 0;

//
// System Configuration Table pointing to STM Configuration Table
//
GLOBAL_REMOVE_IF_UNREFERENCED
EFI_SM_MONITOR_INIT_PROTOCOL  mSmMonitorInitProtocol = {
  .LoadMonitor = LoadMonitor,
  .GetMonitorState = GetMonitorState,
};

#define   CPUID1_EDX_XD_SUPPORT  0x100000

//
// Global variables and symbols pulled in from MmSupervisor
//
extern BOOLEAN mCetSupported;
extern BOOLEAN gPatchXdSupported;
extern BOOLEAN gPatchMsrIa32MiscEnableSupported;
extern BOOLEAN m5LevelPagingNeeded;

extern UINT32 mCetPl0Ssp;
extern UINT32 mCetInterruptSsp;
extern UINT32 mCetInterruptSspTable;

extern SMM_SUPV_SECURE_POLICY_DATA_V1_0   *FirmwarePolicy;

VOID
EFIAPI
CpuSmmDebugEntry (
  IN UINTN  CpuIndex
  );

VOID
EFIAPI
CpuSmmDebugExit (
  IN UINTN  CpuIndex
  );

VOID
EFIAPI
SmiRendezvous (
  IN      UINTN  CpuIndex
  );

VOID
EFIAPI
OnStmSetup (
  VOID
  );

VOID
EFIAPI
OnStmTeardown (
  VOID
  );

VOID
EFIAPI
OnException (
  VOID
  );

//
// This structure serves as a template for all processors.
//
CONST TXT_PROCESSOR_SMM_DESCRIPTOR mPsdTemplate = {
  .Signature = TXT_PROCESSOR_SMM_DESCRIPTOR_SIGNATURE,
  .Size = sizeof (TXT_PROCESSOR_SMM_DESCRIPTOR),
  .SmmDescriptorVerMajor = TXT_PROCESSOR_SMM_DESCRIPTOR_VERSION_MAJOR,
  .SmmDescriptorVerMinor = TXT_PROCESSOR_SMM_DESCRIPTOR_VERSION_MINOR,
  .LocalApicId = 0,
  .SmmEntryState = 0x0F, // Cr4Pse;Cr4Pae;Intel64Mode;ExecutionDisableOutsideSmrr
  .SmmResumeState = 0, // BIOS to STM
  .StmSmmState = 0, // STM to BIOS
  .Reserved4 = 0,
  .SmmCs = CODE_SEL,
  .SmmDs = DATA_SEL,
  .SmmSs = DATA_SEL,
  .SmmOtherSegment = DATA_SEL,
  .SmmTr = TR_SEL,
  .Reserved5 = 0,
  .SmmCr3 = 0,
  .SmmStmSetupRip = (UINT64)OnStmSetup,
  .SmmStmTeardownRip = (UINT64)OnStmTeardown,
  .SmmSmiHandlerRip = 0, // SmmSmiHandlerRip - SMM guest entrypoint
  .SmmSmiHandlerRsp = 0, // SmmSmiHandlerRsp
  .SmmGdtPtr = 0,
  .SmmGdtSize = 0,
  .RequiredStmSmmRevId = 0x80010100,
  .StmProtectionExceptionHandler = {
    .SpeRip = (UINT64)OnException,
    .SpeRsp = 0,
    .SpeSs = DATA_SEL,
    .PageViolationException = 1,
    .MsrViolationException = 1,
    .RegisterViolationException = 1,
    .IoViolationException = 1,
    .PciViolationException = 1,
  },
  .Reserved6 = 0,
  .BiosHwResourceRequirementsPtr = 0,
  .AcpiRsdp = 0,
  .PhysicalAddressBits = 0,
};

//
// This structure serves as a template for all processors.
//
SPAM_RESPONDER_DATA mSpamResponderTemplate = {
  .Signature = SPAM_RESPONDER_STRUCT_SIGNATURE,
  .VersionMinor = SPAM_REPSONDER_STRUCT_MINOR_VER,
  .VersionMajor = SPAM_REPSONDER_STRUCT_MAJOR_VER,
  .Size = 0,
  .Reserved = 0,
  .CpuIndex = 0,
  .MmEntryBase = 0,
  .MmEntrySize = 0,
  .MmSupervisorBase = 0,
  .MmSupervisorSize = 0,
  .MmSecurePolicyBase = 0,
  .MmSecurePolicySize = 0,
  .UserModuleOffset = sizeof (SPAM_RESPONDER_DATA),
  .UserModuleCount = 0
};

//
// Variables used by SMI Handler
//
IA32_DESCRIPTOR  gStmSmiHandlerIdtr;
IA32_DESCRIPTOR  *mGdtrPtr;

//
// MP Information HOB data
//
MP_INFORMATION_HOB_DATA  *mMpInformationHobData;

//
// MSEG Base and Length in SMRAM
//
UINTN  mMsegBase = 0;
UINTN  mMsegSize = 0;

//
// MMI Entry Base and Length in FV
//
EFI_PHYSICAL_ADDRESS  mMmiEntryBaseAddress  = 0;
UINTN                 mMmiEntrySize         = 0;

EFI_PHYSICAL_ADDRESS  MmSupvAuxFileBase;
EFI_PHYSICAL_ADDRESS  MmSupvAuxFileSize;

BOOLEAN  mStmConfigurationTableInitialized = FALSE;

/**
  Discovers Standalone MM drivers in FV HOBs and adds those drivers to the Standalone MM
  dispatch list.

  This function will also set the Standalone MM BFV address to the FV that contains this
  Standalone MM core driver.

  @retval   EFI_SUCCESS           An error was not encountered discovering Standalone MM drivers.
  @retval   EFI_NOT_FOUND         The HOB list could not be found.

**/
EFI_STATUS
DiscoverSmiEntryInFvHobs (
  VOID
  )
{
  UINT16                          ExtHeaderOffset;
  EFI_FIRMWARE_VOLUME_HEADER      *FwVolHeader;
  EFI_FIRMWARE_VOLUME_EXT_HEADER  *ExtHeader;
  EFI_FFS_FILE_HEADER             *FileHeader;
  EFI_PEI_HOB_POINTERS            Hob;
  EFI_STATUS                      Status;
  UINTN                           SpamBinSize;
  BOOLEAN                         MmiEntryFound = FALSE;
  BOOLEAN                         SpamResponderFound = FALSE;
  BOOLEAN                         AuxBinFound = FALSE;
  VOID                            *RawBinFileData;
  VOID                            *RawMmiEntryFileData;
  VOID                            *RawAuxFileData;

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
        __FUNCTION__,
        (UINTN)FwVolHeader,
        FwVolHeader->FvLength
        ));

      ExtHeaderOffset = ReadUnaligned16 (&FwVolHeader->ExtHeaderOffset);
      if (ExtHeaderOffset != 0) {
        ExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)((UINT8 *)FwVolHeader + ExtHeaderOffset);
        DEBUG ((DEBUG_INFO, "[%a]   FV GUID = {%g}.\n", __FUNCTION__, &ExtHeader->FvName));
      }

      //
      // If a MM_STANDALONE or MM_CORE_STANDALONE driver is in the FV. Add the drivers
      // to the dispatch list. Mark the FV with this driver as the Standalone BFV.
      //
      FileHeader = NULL;
      do {
        Status     =  FfsFindNextFile (
                        EFI_FV_FILETYPE_FREEFORM,
                        FwVolHeader,
                        &FileHeader
                        );
        if (!EFI_ERROR (Status)) {
          if (CompareGuid (&FileHeader->Name, &gMmiEntrySpamFileGuid)) {
            if (MmiEntryFound) {
              Status = EFI_ALREADY_STARTED;
              break;
            }
            Status = FfsFindSectionData (EFI_SECTION_RAW, FileHeader, &RawMmiEntryFileData, &mMmiEntrySize);
            if (!EFI_ERROR (Status)) {
              mMmiEntryBaseAddress  = (EFI_PHYSICAL_ADDRESS)(UINTN)RawMmiEntryFileData;
            } else {
              DEBUG ((DEBUG_ERROR, "[%a]   Failed to load MmiEntry [%g] in FV at 0x%p of %x bytes - %r.\n", __FUNCTION__, &gMmiEntrySpamFileGuid, FileHeader, FileHeader->Size, Status));
              break;
            }

            DEBUG ((
              DEBUG_INFO,
              "[%a]   Discovered MMI Entry for SPAM [%g] in FV at 0x%p of %x bytes.\n",
              __FUNCTION__,
              &gMmiEntrySpamFileGuid,
              mMmiEntryBaseAddress,
              mMmiEntrySize
              ));
            MmiEntryFound = TRUE;
          } else if (CompareGuid (&FileHeader->Name, &gSpamBinFileGuid)) {
            if (SpamResponderFound) {
              Status = EFI_ALREADY_STARTED;
              break;
            }
            Status = FfsFindSectionData (EFI_SECTION_RAW, FileHeader, &RawBinFileData, &SpamBinSize);
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "[%a]   Failed to find SPAM data section [%g] in FV at 0x%p of %x bytes - %r.\n", __FUNCTION__, &gSpamBinFileGuid, FileHeader, FileHeader->Size, Status));
              break;
            }
            Status = LoadMonitor ((EFI_PHYSICAL_ADDRESS)(UINTN)RawBinFileData, SpamBinSize);
            // Moving the buffer like size field to our local variable
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "[%a]   Failed to load SPAM [%g] in FV at 0x%p of %x bytes - %r.\n", __FUNCTION__, &gSpamBinFileGuid, FileHeader, FileHeader->Size, Status));
              break;
            }
            // TODO: Mark the region as supervisor read-only
            SpamResponderFound = TRUE;
          } else if (CompareGuid (&FileHeader->Name, &gMmSupervisorAuxFileGuid)) {
            if (AuxBinFound) {
              Status = EFI_ALREADY_STARTED;
              break;
            }
            Status = FfsFindSectionData (EFI_SECTION_RAW, FileHeader, &RawAuxFileData, &MmSupvAuxFileSize);
            DEBUG ((DEBUG_INFO, "Find raw data from supv aux file - %r\n", Status));
            if (EFI_ERROR (Status)) {
              break;
            }

            MmSupvAuxFileBase = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocatePages (EFI_SIZE_TO_PAGES (MmSupvAuxFileSize));
            if (MmSupvAuxFileBase == 0) {
              Status = EFI_OUT_OF_RESOURCES;
              break;
            }

            CopyMem ((VOID *)(UINTN)MmSupvAuxFileBase, (VOID *)(UINTN)RawAuxFileData, MmSupvAuxFileSize);
            // TODO: Mark the region as supervisor read-only
            AuxBinFound = TRUE;
          }

          if (MmiEntryFound && SpamResponderFound && AuxBinFound) {
            // Job done, break out of the loop
            Status = EFI_SUCCESS;
            break;
          }
        }
      } while (!EFI_ERROR (Status));
      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);

  if (!MmiEntryFound || !SpamResponderFound || !AuxBinFound) {
    DEBUG ((DEBUG_ERROR, "[%a]   Required entries for SPAM not found in any FV.\n", __FUNCTION__));
    Status = EFI_NOT_FOUND;
  } else {
    Status = EFI_SUCCESS;
  }

Done:
  return Status;
}

/**
  The constructor function for the common MM library instance with STM.

  @retval EFI_SUCCESS      The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
SmmCpuFeaturesLibStmConstructor (
  VOID
  )
{
  EFI_STATUS              Status;
  CPUID_VERSION_INFO_ECX  RegEcx;
  EFI_HOB_GUID_TYPE       *GuidHob;
  EFI_SMRAM_DESCRIPTOR    *SmramDescriptor;

  //
  // Perform library initialization common across all instances
  //
  CpuFeaturesLibInitialization ();

  //
  // Lookup the MP Information
  //
  GuidHob = GetFirstGuidHob (&gMpInformationHobGuid);
  ASSERT (GuidHob != NULL);
  mMpInformationHobData = GET_GUID_HOB_DATA (GuidHob);

  //
  // Use MP info hob to retrieve the number of processors
  //
  mGdtrPtr = AllocateZeroPool (sizeof (IA32_DESCRIPTOR) * mMpInformationHobData->NumberOfProcessors);
  if (mGdtrPtr == NULL) {
    DEBUG ((DEBUG_ERROR, "mGdtrPtr == NULL\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // If CPU supports VMX, then determine SMRAM range for MSEG.
  //
  AsmCpuid (CPUID_VERSION_INFO, NULL, NULL, &RegEcx.Uint32, NULL);
  if (RegEcx.Bits.VMX == 1) {
    GuidHob = GetFirstGuidHob (&gMsegSmramGuid);
    if (GuidHob != NULL) {
      //
      // Retrieve MSEG location from MSEG SRAM HOB
      //
      SmramDescriptor = (EFI_SMRAM_DESCRIPTOR *)GET_GUID_HOB_DATA (GuidHob);
      if (SmramDescriptor->PhysicalSize > 0) {
        mMsegBase = (UINTN)SmramDescriptor->CpuStart;
        mMsegSize = (UINTN)SmramDescriptor->PhysicalSize;
      }
    } else if (PcdGet32 (PcdCpuMsegSize) > 0) {
      //
      // Allocate MSEG from SMRAM memory
      //
      mMsegBase = (UINTN)AllocatePages (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuMsegSize)));
      if (mMsegBase > 0) {
        mMsegSize = ALIGN_VALUE (PcdGet32 (PcdCpuMsegSize), EFI_PAGE_SIZE);
      } else {
        DEBUG ((DEBUG_ERROR, "Not enough SMRAM resource to allocate MSEG size %08x\n", PcdGet32 (PcdCpuMsegSize)));
      }
    }

    if (mMsegBase > 0) {
      DEBUG ((DEBUG_INFO, "MsegBase: 0x%08x, MsegSize: 0x%08x\n", mMsegBase, mMsegSize));
    }
  }

  //
  // First locate the MMI entry blob in the FV
  Status = DiscoverSmiEntryInFvHobs ();
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Internal worker function that is called to complete CPU initialization at the
  end of SmmCpuFeaturesInitializeProcessor().

**/
VOID
FinishSmmCpuFeaturesInitializeProcessor (
  VOID
  )
{
  MSR_IA32_SMM_MONITOR_CTL_REGISTER  SmmMonitorCtl;

  //
  // Set MSEG Base Address in SMM Monitor Control MSR.
  //
  if (mMsegBase > 0) {
    SmmMonitorCtl.Uint64        = 0;
    SmmMonitorCtl.Bits.MsegBase = (UINT32)mMsegBase >> 12;
    SmmMonitorCtl.Bits.Valid    = 1;
    AsmWriteMsr64 (MSR_IA32_SMM_MONITOR_CTL, SmmMonitorCtl.Uint64);
  }
}

/**
  Return the size, in bytes, of a custom SMI Handler in bytes.  If 0 is
  returned, then a custom SMI handler is not provided by this library,
  and the default SMI handler must be used.

  @retval 0    Use the default SMI handler.
  @retval > 0  Use the SMI handler installed by SmmCpuFeaturesInstallSmiHandler()
               The caller is required to allocate enough SMRAM for each CPU to
               support the size of the custom SMI handler.
**/
UINTN
EFIAPI
SmmCpuFeaturesGetSmiHandlerSize (
  VOID
  )
{
  return mMmiEntrySize;
}

STATIC
EFI_STATUS
EFIAPI
PopulateSpamInformation (
  IN UINTN                  CpuIndex,
  IN EFI_PHYSICAL_ADDRESS   MmEntryBase,
  IN UINTN                  MmEntrySize,
  IN EFI_PHYSICAL_ADDRESS   StackBase,
  IN UINTN                  StackSize
  )
{
  mSpamResponderTemplate.Signature          = SPAM_RESPONDER_STRUCT_SIGNATURE;
  mSpamResponderTemplate.VersionMajor       = SPAM_REPSONDER_STRUCT_MAJOR_VER;
  mSpamResponderTemplate.VersionMinor       = SPAM_REPSONDER_STRUCT_MINOR_VER;
  mSpamResponderTemplate.Size               = sizeof (SPAM_RESPONDER_DATA);
  mSpamResponderTemplate.CpuIndex           = CpuIndex;
  mSpamResponderTemplate.MmEntryBase        = MmEntryBase;
  mSpamResponderTemplate.MmEntrySize        = MmEntrySize;
  mSpamResponderTemplate.MmSecurePolicyBase = (UINT64)FirmwarePolicy;
  mSpamResponderTemplate.MmSecurePolicySize = FirmwarePolicy->Size;
  mSpamResponderTemplate.UserModuleOffset   = 0;
  mSpamResponderTemplate.UserModuleCount    = 0;

  // TODO: Populate more user modules and fix up the size.

  return EFI_SUCCESS;
}

/**
  Install a custom SMI handler for the CPU specified by CpuIndex.  This function
  is only called if SmmCpuFeaturesGetSmiHandlerSize() returns a size is greater
  than zero and is called by the CPU that was elected as monarch during System
  Management Mode initialization.

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
SmmCpuFeaturesInstallSmiHandler (
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
  EFI_STATUS                    Status;
  TXT_PROCESSOR_SMM_DESCRIPTOR  *Psd;
  VOID                          *Hob;
  UINT32                        RegEax;
  EFI_PROCESSOR_INFORMATION     ProcessorInfo;
  PER_CORE_MMI_ENTRY_STRUCT_HDR *SmiEntryStructHdrPtr = NULL;
  UINT32                        SmiEntryStructHdrAddr;
  UINT32                        WholeStructSize;
  UINT16                        *FixStructPtr;
  UINT32                        *Fixup32Ptr;
  UINT64                        *Fixup64Ptr;
  UINT8                         *Fixup8Ptr;
  UINT32                        tSmiStack;

  CopyMem ((VOID *)((UINTN)SmBase + TXT_SMM_PSD_OFFSET), &mPsdTemplate, sizeof (mPsdTemplate));
  Psd             = (TXT_PROCESSOR_SMM_DESCRIPTOR *)(VOID *)((UINTN)SmBase + TXT_SMM_PSD_OFFSET);
  Psd->SmmGdtPtr  = (UINT64)(UINTN)&mGdtrPtr[CpuIndex];
  Psd->SmmGdtSize = (UINT32)GdtSize;

  //
  // Initialize values in template before copy
  //
  tSmiStack                = (UINT32)((UINTN)SmiStack + StackSize - sizeof (UINTN));
  if ((gStmSmiHandlerIdtr.Base == 0) && (gStmSmiHandlerIdtr.Limit == 0)) {
    gStmSmiHandlerIdtr.Base  = IdtBase;
    gStmSmiHandlerIdtr.Limit = (UINT16)(IdtSize - 1);
  } else {
    ASSERT (gStmSmiHandlerIdtr.Base == IdtBase);
    ASSERT (gStmSmiHandlerIdtr.Limit == (UINT16)(IdtSize - 1));
  }

  //
  // Set the value at the top of the CPU stack to the CPU Index
  //
  *(UINTN *)(UINTN)tSmiStack = CpuIndex;

  //
  // Copy template to CPU specific SMI handler location from what is located from the FV
  //
  CopyMem (
    (VOID *)((UINTN)SmBase + SMM_HANDLER_OFFSET),
    (VOID *)mMmiEntryBaseAddress,
    mMmiEntrySize
    );

  // Populate the fix up addresses
  // Get Whole structure size
  WholeStructSize = (UINT32)*(EFI_PHYSICAL_ADDRESS *)(UINTN)(SmBase + SMM_HANDLER_OFFSET + mMmiEntrySize - sizeof(UINT32));

  // Get header address
  SmiEntryStructHdrAddr = (UINT32)(SmBase + SMM_HANDLER_OFFSET + mMmiEntrySize - sizeof(UINT32) - WholeStructSize);
  SmiEntryStructHdrPtr = (PER_CORE_MMI_ENTRY_STRUCT_HDR *)(UINTN)(SmiEntryStructHdrAddr);

  // Navegiate to the fixup arrays
  FixStructPtr = (UINT16 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUpStructOffset);
  Fixup32Ptr = (UINT32 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp32Offset);
  Fixup64Ptr = (UINT64 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp64Offset);
  Fixup8Ptr = (UINT8 *)(UINTN)(SmiEntryStructHdrAddr + SmiEntryStructHdrPtr->FixUp8Offset);

  //Do the fixup
  Fixup32Ptr[FIXUP32_mPatchCetPl0Ssp] = mCetPl0Ssp;
  Fixup32Ptr[FIXUP32_GDTR] = (UINT32)(UINTN) &mGdtrPtr[CpuIndex];
  Fixup32Ptr[FIXUP32_CR3_OFFSET] = Cr3;
  Fixup32Ptr[FIXUP32_mPatchCetInterruptSsp] = mCetInterruptSsp;
  Fixup32Ptr[FIXUP32_mPatchCetInterruptSspTable] = mCetInterruptSspTable;
  Fixup32Ptr[FIXUP32_STACK_OFFSET_CPL0] = (UINT32)(UINTN)tSmiStack;
  Fixup32Ptr[FIXUP32_MSR_SMM_BASE] = SmBase;

  Fixup64Ptr[FIXUP64_SMM_DBG_ENTRY] = (UINT64)CpuSmmDebugEntry;
  Fixup64Ptr[FIXUP64_SMM_DBG_EXIT] = (UINT64)CpuSmmDebugExit;
  Fixup64Ptr[FIXUP64_SMI_RDZ_ENTRY] = (UINT64)SmiRendezvous;
  Fixup64Ptr[FIXUP64_XD_SUPPORTED] = (UINT64)&gPatchXdSupported;
  Fixup64Ptr[FIXUP64_CET_SUPPORTED] = (UINT64)&mCetSupported;
  Fixup64Ptr[FIXUP64_SMI_HANDLER_IDTR] = (UINT64)&gStmSmiHandlerIdtr;

  Fixup8Ptr[FIXUP8_gPatchXdSupported] = gPatchXdSupported;
  Fixup8Ptr[FIXUP8_gPatchMsrIa32MiscEnableSupported] = gPatchMsrIa32MiscEnableSupported;
  Fixup8Ptr[FIXUP8_gPatch5LevelPagingNeeded] = m5LevelPagingNeeded;
  Fixup8Ptr[FIXUP8_mPatchCetSupported] = mCetSupported;

  // TODO: Sort out these values, if needed
  Psd->SmmSmiHandlerRip = 0;
  Psd->SmmSmiHandlerRsp = (UINTN)SmiStack + StackSize - sizeof (UINTN);
  Psd->SmmCr3           = Cr3;

  DEBUG ((DEBUG_INFO, "CpuSmmStmExceptionStackSize - %x\n", PcdGet32 (PcdCpuSmmStmExceptionStackSize)));
  DEBUG ((DEBUG_INFO, "Pages - %x\n", EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmStmExceptionStackSize))));
  Psd->StmProtectionExceptionHandler.SpeRsp  = (UINT64)(UINTN)AllocatePages (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmStmExceptionStackSize)));
  Psd->StmProtectionExceptionHandler.SpeRsp += EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmStmExceptionStackSize)));

  Psd->BiosHwResourceRequirementsPtr = (UINT64)(UINTN)GetStmResource ();

  //
  // Get the APIC ID for the CPU specified by CpuIndex
  //
  CopyMem (&ProcessorInfo, &mMpInformationHobData->ProcessorInfoBuffer[CpuIndex], sizeof (EFI_PROCESSOR_INFORMATION));

  Psd->LocalApicId = (UINT32)ProcessorInfo.ProcessorId;
  Psd->AcpiRsdp    = 0;

  Hob = GetFirstHob (EFI_HOB_TYPE_CPU);
  if (Hob != NULL) {
    Psd->PhysicalAddressBits = ((EFI_HOB_CPU *)Hob)->SizeOfMemorySpace;
  } else {
    AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
    if (RegEax >= 0x80000008) {
      AsmCpuid (0x80000008, &RegEax, NULL, NULL, NULL);
      Psd->PhysicalAddressBits = (UINT8)RegEax;
    } else {
      Psd->PhysicalAddressBits = 36;
    }
  }

  if (!mStmConfigurationTableInitialized) {
    StmSmmConfigurationTableInit ();
    Status = PopulateSpamInformation (
      CpuIndex,
      mMmiEntryBaseAddress,
      mMmiEntrySize,
      (EFI_PHYSICAL_ADDRESS)(UINTN)SmiStack,
      StackSize
      );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "PopulateSpamInformation failed - %r\n", Status));
      ASSERT_EFI_ERROR (Status);
    }
    mStmConfigurationTableInitialized = TRUE;
  }
}

/**
  SMM End Of Dxe event notification handler.

  STM support need patch AcpiRsdp in TXT_PROCESSOR_SMM_DESCRIPTOR.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
MmEndOfDxeEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  UINTN                              Index = 0;
  TXT_PROCESSOR_SMM_DESCRIPTOR       *Psd;
  SPAM_RESPONDER_DATA                *SpamResponderData;
  UINTN                              NoHandles;
  UINTN                              HandleBufferSize;
  EFI_HANDLE                         *HandleBuffer;
  EFI_STATUS                         Status;
  EFI_LOADED_IMAGE_PROTOCOL          *LoadedImage;
  USER_MODULE_INFO                   *UserModuleBuffer = NULL;
  MSR_IA32_SMM_MONITOR_CTL_REGISTER  SmmMonitorCtl;
  UINT32                             MsegBase;
  STM_HEADER                         *StmHeader;
  VOID                               *LongRsp;

  DEBUG ((DEBUG_INFO, "MmEndOfDxeEventNotify\n"));

  //
  // Get MSEG base address from MSR_IA32_SMM_MONITOR_CTL
  //
  SmmMonitorCtl.Uint64 = AsmReadMsr64 (MSR_IA32_SMM_MONITOR_CTL);
  MsegBase             = SmmMonitorCtl.Bits.MsegBase << 12;

  //
  // STM Header is at the beginning of the STM Image, we use the value from MSR
  //
  StmHeader = (STM_HEADER *)(UINTN)MsegBase;
  LongRsp = (VOID*)(UINTN)(MsegBase + StmHeader->HwStmHdr.EspOffset);

  // Now that we have all the loaded image information, prepare the responder data
  HandleBufferSize = 0;
  HandleBuffer     = NULL;
  Status           = gMmst->MmLocateHandle (
                                   ByProtocol,
                                   &gEfiLoadedImageProtocolGuid,
                                   NULL,
                                   &HandleBufferSize,
                                   HandleBuffer
                                   );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    goto Done;
  }

  HandleBuffer = AllocateZeroPool (HandleBufferSize);
  if (HandleBuffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Status = gMmst->MmLocateHandle (
                         ByProtocol,
                         &gEfiLoadedImageProtocolGuid,
                         NULL,
                         &HandleBufferSize,
                         HandleBuffer
                         );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  NoHandles = HandleBufferSize/sizeof (EFI_HANDLE);
  Status    = gMmst->MmLocateHandle (
                          ByProtocol,
                          &gEfiLoadedImageProtocolGuid,
                          NULL,
                          &HandleBufferSize,
                          HandleBuffer
                          );

  // Let's be honest, the first one will be the core...
  Status = gMmst->MmHandleProtocol (
                        HandleBuffer[Index],
                        &gEfiLoadedImageProtocolGuid,
                        (VOID **)&LoadedImage
                        );
  mSpamResponderTemplate.MmSupervisorBase = (UINT64)(UINTN)LoadedImage->ImageBase;
  mSpamResponderTemplate.MmSupervisorSize = (UINT64)(UINTN)LoadedImage->ImageSize;

  // Now we continue to the user modules information
  mSpamResponderTemplate.UserModuleCount  = NoHandles - 1;
  UserModuleBuffer = AllocateZeroPool ((NoHandles - 1) * sizeof (USER_MODULE_INFO));
  for (Index = 1; Index < NoHandles; Index++) {
    Status = gMmst->MmHandleProtocol (
                           HandleBuffer[Index],
                           &gEfiLoadedImageProtocolGuid,
                           (VOID **)&LoadedImage
                           );
    if (EFI_ERROR (Status)) {
      continue;
    }

    UserModuleBuffer[Index - 1].UserModuleBase = (UINT64)(UINTN)LoadedImage->ImageBase;
    UserModuleBuffer[Index - 1].UserModuleSize = (UINT64)(UINTN)LoadedImage->ImageSize;
  }

  for (Index = 0; Index < gMmst->NumberOfCpus; Index++) {
    Psd = (TXT_PROCESSOR_SMM_DESCRIPTOR *)((UINTN)gMmst->CpuSaveState[Index] - SMRAM_SAVE_STATE_MAP_OFFSET + TXT_SMM_PSD_OFFSET);
    DEBUG ((DEBUG_INFO, "Index=%d  Psd=%p  Rsdp=%p\n", Index, Psd, NULL));
    Psd->AcpiRsdp = (UINT64)(UINTN)NULL;

    StmHeader->SwStmHdr.PerProcDynamicMemorySize;
    SpamResponderData = (SPAM_RESPONDER_DATA*)((UINTN)LongRsp + StmHeader->SwStmHdr.PerProcDynamicMemorySize -
                        sizeof (SPAM_RESPONDER_DATA) -
                        (NoHandles - 1) * sizeof (USER_MODULE_INFO));

    CopyMem (SpamResponderData, &mSpamResponderTemplate, sizeof (SPAM_RESPONDER_DATA));
    CopyMem (SpamResponderData + 1, UserModuleBuffer, (NoHandles - 1) * sizeof (USER_MODULE_INFO));
    // TODO: Mark the region as supervisor read-only, or even read prevention...

    LongRsp = (VOID*)((UINTN)LongRsp + StmHeader->SwStmHdr.PerProcDynamicMemorySize);
  }

  mLockLoadMonitor = TRUE;

  Status = EFI_SUCCESS;

Done:
  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  if (UserModuleBuffer != NULL) {
    FreePool (UserModuleBuffer);
  }
  return Status;
}

/**
  This function initializes the STM configuration table.
**/
VOID
StmSmmConfigurationTableInit (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *Registration;

  //
  //
  // Register SMM End of DXE Event
  //
  Status = gMmst->MmRegisterProtocolNotify (
                    &gEfiMmEndOfDxeProtocolGuid,
                    MmEndOfDxeEventNotify,
                    &Registration
                    );
  ASSERT_EFI_ERROR (Status);
}

/**

  Set valid bit for MSEG MSR.

  @param Buffer Ap function buffer. (not used)

**/
VOID
EFIAPI
EnableMsegMsr (
  IN VOID  *Buffer
  )
{
  MSR_IA32_SMM_MONITOR_CTL_REGISTER  SmmMonitorCtl;

  SmmMonitorCtl.Uint64     = AsmReadMsr64 (MSR_IA32_SMM_MONITOR_CTL);
  SmmMonitorCtl.Bits.Valid = 1;
  AsmWriteMsr64 (MSR_IA32_SMM_MONITOR_CTL, SmmMonitorCtl.Uint64);
}

/**

  Get 4K page aligned VMCS size.

  @return 4K page aligned VMCS size

**/
UINT32
GetVmcsSize (
  VOID
  )
{
  MSR_IA32_VMX_BASIC_REGISTER  VmxBasic;

  //
  // Read VMCS size and and align to 4KB
  //
  VmxBasic.Uint64 = AsmReadMsr64 (MSR_IA32_VMX_BASIC);
  return ALIGN_VALUE (VmxBasic.Bits.VmcsSize, SIZE_4KB);
}

/**

  Check STM image size.

  @param StmImage      STM image
  @param StmImageSize  STM image size

  @retval TRUE  check pass
  @retval FALSE check fail
**/
BOOLEAN
StmCheckStmImage (
  IN EFI_PHYSICAL_ADDRESS  StmImage,
  IN UINTN                 StmImageSize
  )
{
  UINTN                   MinMsegSize;
  STM_HEADER              *StmHeader;
  IA32_VMX_MISC_REGISTER  VmxMiscMsr;

  //
  // Check to see if STM image is compatible with CPU
  //
  StmHeader         = (STM_HEADER *)(UINTN)StmImage;
  VmxMiscMsr.Uint64 = AsmReadMsr64 (MSR_IA32_VMX_MISC);
  if (StmHeader->HwStmHdr.MsegHeaderRevision != VmxMiscMsr.Bits.MsegRevisionIdentifier) {
    DEBUG ((DEBUG_ERROR, "STM Image not compatible with CPU\n"));
    DEBUG ((DEBUG_ERROR, "  StmHeader->HwStmHdr.MsegHeaderRevision = %08x\n", StmHeader->HwStmHdr.MsegHeaderRevision));
    DEBUG ((DEBUG_ERROR, "  VmxMiscMsr.Bits.MsegRevisionIdentifier = %08x\n", VmxMiscMsr.Bits.MsegRevisionIdentifier));
    return FALSE;
  }

  //
  // Get Minimal required Mseg size
  //
  MinMsegSize = (EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (StmHeader->SwStmHdr.StaticImageSize)) +
                 StmHeader->SwStmHdr.AdditionalDynamicMemorySize +
                 (StmHeader->SwStmHdr.PerProcDynamicMemorySize + GetVmcsSize () * 2) * gMmst->NumberOfCpus);
  if (MinMsegSize < StmImageSize) {
    MinMsegSize = StmImageSize;
  }

  if (StmHeader->HwStmHdr.Cr3Offset >= StmHeader->SwStmHdr.StaticImageSize) {
    //
    // We will create page table, just in case that SINIT does not create it.
    //
    if (MinMsegSize < StmHeader->HwStmHdr.Cr3Offset + EFI_PAGES_TO_SIZE (6)) {
      MinMsegSize = StmHeader->HwStmHdr.Cr3Offset + EFI_PAGES_TO_SIZE (6);
    }
  }

  //
  // Check if it exceeds MSEG size
  //
  if (MinMsegSize > mMsegSize) {
    DEBUG ((DEBUG_ERROR, "MSEG too small.  Min MSEG Size = %08x  Current MSEG Size = %08x\n", MinMsegSize, mMsegSize));
    DEBUG ((DEBUG_ERROR, "  StmHeader->SwStmHdr.StaticImageSize             = %08x\n", StmHeader->SwStmHdr.StaticImageSize));
    DEBUG ((DEBUG_ERROR, "  StmHeader->SwStmHdr.AdditionalDynamicMemorySize = %08x\n", StmHeader->SwStmHdr.AdditionalDynamicMemorySize));
    DEBUG ((DEBUG_ERROR, "  StmHeader->SwStmHdr.PerProcDynamicMemorySize    = %08x\n", StmHeader->SwStmHdr.PerProcDynamicMemorySize));
    DEBUG ((DEBUG_ERROR, "  VMCS Size                                       = %08x\n", GetVmcsSize ()));
    DEBUG ((DEBUG_ERROR, "  Max CPUs                                        = %08x\n", gMmst->NumberOfCpus));
    DEBUG ((DEBUG_ERROR, "  StmHeader->HwStmHdr.Cr3Offset                   = %08x\n", StmHeader->HwStmHdr.Cr3Offset));
    return FALSE;
  }

  return TRUE;
}

/**

  Get STM state.

  @return STM state

**/
EFI_SM_MONITOR_STATE
EFIAPI
GetMonitorState (
  VOID
  )
{
  return mStmState;
}

/**

  Load STM image to MSEG.

  @param StmImage      STM image
  @param StmImageSize  STM image size

**/
VOID
StmLoadStmImage (
  IN EFI_PHYSICAL_ADDRESS  StmImage,
  IN UINTN                 StmImageSize
  )
{
  STM_HEADER                         *StmHeader;

  //
  // Zero all of MSEG base address
  //
  ZeroMem ((VOID *)(UINTN)mMsegBase, mMsegSize);

  //
  // Copy STM Image into MSEG
  //
  CopyMem ((VOID *)(UINTN)mMsegBase, (VOID *)(UINTN)StmImage, StmImageSize);

  //
  // STM Header is at the beginning of the STM Image
  //
  StmHeader = (STM_HEADER *)(UINTN)StmImage;

  StmGen4GPageTable ((UINTN)mMsegBase + StmHeader->HwStmHdr.Cr3Offset);
}

/**

  Load STM image to MSEG.

  @param StmImage      STM image
  @param StmImageSize  STM image size

  @retval EFI_SUCCESS            Load STM to MSEG successfully
  @retval EFI_ALREADY_STARTED    STM image is already loaded to MSEG
  @retval EFI_BUFFER_TOO_SMALL   MSEG is smaller than minimal requirement of STM image
  @retval EFI_UNSUPPORTED        MSEG is not enabled

**/
EFI_STATUS
EFIAPI
LoadMonitor (
  IN EFI_PHYSICAL_ADDRESS  StmImage,
  IN UINTN                 StmImageSize
  )
{
  if (mLockLoadMonitor) {
    return EFI_ACCESS_DENIED;
  }

  if (mMsegBase == 0) {
    return EFI_UNSUPPORTED;
  }

  if (!StmCheckStmImage (StmImage, StmImageSize)) {
    return EFI_BUFFER_TOO_SMALL;
  }

  // Record STM_HASH to PCR 0, just in case it is NOT TXT launch, we still need provide the evidence.
  TpmMeasureAndLogData (
    0,                        // PcrIndex
    TXT_EVTYPE_STM_HASH,      // EventType
    NULL,                     // EventLog
    0,                        // LogLen
    (VOID *)(UINTN)StmImage,  // HashData
    StmImageSize              // HashDataLen
    );

  StmLoadStmImage (StmImage, StmImageSize);

  mStmState |= EFI_SM_MONITOR_STATE_ENABLED;

  return EFI_SUCCESS;
}

/**
  This function return BIOS STM resource.
  Produced by SmmStm.
  Consumed by SmmMpService when Init.

  @return BIOS STM resource

**/
VOID *
GetStmResource (
  VOID
  )
{
  return mStmResourcesPtr;
}

/**
  This is STM setup BIOS callback.
**/
VOID
EFIAPI
SmmStmSetup (
  VOID
  )
{
  mStmState |= EFI_SM_MONITOR_STATE_ACTIVATED;
}

/**
  This is STM teardown BIOS callback.
**/
VOID
EFIAPI
SmmStmTeardown (
  VOID
  )
{
  mStmState &= ~EFI_SM_MONITOR_STATE_ACTIVATED;
}
