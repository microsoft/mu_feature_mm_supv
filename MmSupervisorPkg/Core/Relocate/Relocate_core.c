/** @file
  Core-build specialization for the SMM Entry Vector relocation logic.

  Houses the bodies of LockMmCoreBeforeExit and SetupSmiEntryExit that diverge
  between the Core (MmSupervisorCore) and Init (MmSupervisorInit) builds.  The
  shared logic lives in Relocate.c; only the per-build halves of those two
  functions live here.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Relocate.h"
#include "Mem/Mem.h"
#include "Mem/HeapGuard.h"
#include "Services/MpService/MpService.h"
#include "MmSupervisorCore.h"

//
// Forward decls referenced by the Core variants.  These are defined in shared
// Relocate.c (FindSmramInfo, GetSmBase) or other Core compilation units.
//
EFI_STATUS
EFIAPI
SmmInitializeMemoryAttributesTable (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  );

/**
  SMM Ready To Lock event notification handler.

  The CPU S3 data is copied to SMRAM for security and mSmmReadyToLock is set to
  perform additional lock actions that must be performed from SMM on the next SMI.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
 **/
VOID
EFIAPI
LockMmCoreBeforeExit (
  VOID
  )
{
  EFI_STATUS  Status;

  PERF_FUNCTION_BEGIN ();

  // This will stand for the initial locking, which will cover that:
  // a. Core data and code set to supervisor pages
  // b. DXE Core MAT is not available at this moment, thus just mark everything but SMRAM as not present
  // c. Starting from here, all memory allocated by this driver shall be CPL0 unless otherwise noticed
  // d. Once common buffer is available, the core shall be notified to accept that memory buffer
  // e. IPL lock through SMM access protocol

  // Initializes MAT for SMM region (so far there is only Core memory pages)
  SmmInitializeMemoryAttributesTable (NULL, NULL, NULL);

  // Mark supervisor pages for critical regions
  // Core code and data
  // SmiEntry code
  // Exception handler
  // GDT and its buffer
  // Save State

  // We need to do this based off MM CR3
  SetPageTableBase (mSmmCr3);

  //
  // Create a mix of 2MB and 4KB page table. Update some memory ranges absent and execute-disable.
  //
  InitPaging ();

  // Grab all hob resource decriptors, find the ones that does not overlap with SMRAM, mark them
  // as not present
  SetNonSmmMemMapAttributes ();

  // Unblock the common regions reported during PEI phase
  SetCommonBufferRegionAttribute ();

  // Unblocked other requested regions reported during PEI phase
  SetUnblockRegionAttribute ();

  // Protect the requested regions reported during PEI phase
  SetProtectedRegionAttribute ();

  //
  // Mark critical region to be read-only in page table
  //
  SetMemMapAttributes ();

  Status = LockFfsBuffer ();
  ASSERT_EFI_ERROR (Status);

  if (IsRestrictedMemoryAccess ()) {
    //
    // Set page table itself to be read-only
    //
    SetPageTableAttributes ();
  }

  PERF_START (NULL, "SmmCompleteReadyToLock", NULL, 0);
  SmmCpuFeaturesCompleteSmmReadyToLock ();
  PERF_END (NULL, "SmmCompleteReadyToLock", NULL, 0);

  SetPageTableBase (0);
  PERF_FUNCTION_END ();
}

/**
  The module Entry Point of the CPU SMM driver.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
SetupSmiEntryExit (
  VOID
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINTN       TileCodeSize;
  UINTN       TileDataSize;
  UINTN       TileSize;
  UINT8       *Stacks;
  UINT32      RegEax;
  UINT32      RegEbx;
  UINT32      RegEcx;
  UINT32      RegEdx;
  UINTN       FamilyId;
  UINTN       ModelId;
  UINT32      Cr3;
  UINT8       *Cpl3Stacks;

  PERF_FUNCTION_BEGIN ();

  //
  // Initialize address fixup
  //

  // If a feature lib has its own entry code we shouldn't fixup the addresses.
  if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
    PiSmmCpuSmiEntryFixupAddress ();
  }

  //
  // Initialize Debug Agent to support source level debug in SMM code
  //
  InitializeDebugAgent (DEBUG_AGENT_INIT_SMM, NULL, NULL);

  //
  // Report the start of CPU SMM initialization.
  //
  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    EFI_COMPUTING_UNIT_HOST_PROCESSOR | EFI_CU_HP_PC_SMM_INIT
    );

  mSmmRebootOnException = PcdGetBool (PcdSmmExceptionRebootInsteadOfHaltDefault); // MS_CHANGE

  //
  // Find out SMRR Base and SMRR Size
  //
  FindSmramInfo (&mCpuHotPlugData.SmrrBase, &mCpuHotPlugData.SmrrSize);

  //
  // Retrive NumberOfProcessors, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION for all CPU from MpInformation2 HOB.
  //
  gSmmCpuPrivate->ProcessorInfo = GetMpInformation (&mNumberOfCpus, &mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->ProcessorInfo != NULL);

  //
  // If support CPU hot plug, PcdCpuSmmEnableBspElection should be set to TRUE.
  // A constant BSP index makes no sense because it may be hot removed.
  //
  DEBUG_CODE (
    if (FeaturePcdGet (PcdCpuHotPlugSupport)) {
    ASSERT (FeaturePcdGet (PcdCpuSmmEnableBspElection));
  }

    );

  //
  // Save the PcdCpuSmmCodeAccessCheckEnable value into a global variable.
  //
  mSmmCodeAccessCheckEnable = PcdGetBool (PcdCpuSmmCodeAccessCheckEnable);
  DEBUG ((DEBUG_INFO, "PcdCpuSmmCodeAccessCheckEnable = %d\n", mSmmCodeAccessCheckEnable));

  //
  // Save the PcdPteMemoryEncryptionAddressOrMask value into a global variable.
  // Make sure AddressEncMask is contained to smallest supported address field.
  //
  mAddressEncMask = 0;// PcdGet64 (PcdPteMemoryEncryptionAddressOrMask) & PAGING_1G_ADDRESS_MASK_64;
  DEBUG ((DEBUG_INFO, "mAddressEncMask = 0x%lx\n", mAddressEncMask));

  gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus = mMaxNumberOfCpus;

  PERF_CODE (
    InitializeMpPerf (gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus);
    );

  //
  // The CPU save state and code for the SMI entry point are tiled within an SMRAM
  // allocated buffer.  See Relocate.c (Init build) for the diagram describing the
  // tiled layout; the same algorithm is used here.
  //

  //
  // Retrieve CPU Family
  //
  AsmCpuid (CPUID_VERSION_INFO, &RegEax, NULL, NULL, NULL);
  FamilyId = (RegEax >> 8) & 0xf;
  ModelId  = (RegEax >> 4) & 0xf;
  if ((FamilyId == 0x06) || (FamilyId == 0x0f)) {
    ModelId = ModelId | ((RegEax >> 12) & 0xf0);
  }

  RegEdx = 0;
  AsmCpuid (CPUID_EXTENDED_FUNCTION, &RegEax, NULL, NULL, NULL);
  if (RegEax >= CPUID_EXTENDED_CPU_SIG) {
    AsmCpuid (CPUID_EXTENDED_CPU_SIG, NULL, NULL, NULL, &RegEdx);
  }

  //
  // Determine the mode of the CPU at the time an SMI occurs
  //   Intel(R) 64 and IA-32 Architectures Software Developer's Manual
  //   Volume 3C, Section 34.4.1.1
  //
  mSmmSaveStateRegisterLma = EFI_SMM_SAVE_STATE_REGISTER_LMA_32BIT;
  if ((RegEdx & BIT29) != 0) {
    mSmmSaveStateRegisterLma = EFI_SMM_SAVE_STATE_REGISTER_LMA_64BIT;
  }

  if (FamilyId == 0x06) {
    if ((ModelId == 0x17) || (ModelId == 0x0f) || (ModelId == 0x1c)) {
      mSmmSaveStateRegisterLma = EFI_SMM_SAVE_STATE_REGISTER_LMA_64BIT;
    }
  }

  DEBUG ((DEBUG_INFO, "PcdControlFlowEnforcementPropertyMask = %d\n", PcdGet32 (PcdControlFlowEnforcementPropertyMask)));
  if (PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) {
    AsmCpuid (CPUID_SIGNATURE, &RegEax, NULL, NULL, NULL);
    if (RegEax >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS) {
      AsmCpuidEx (CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO, NULL, NULL, &RegEcx, &RegEdx);
      DEBUG ((DEBUG_INFO, "CPUID[7/0] ECX - 0x%08x\n", RegEcx));
      DEBUG ((DEBUG_INFO, "  CET_SS  - 0x%08x\n", RegEcx & CPUID_CET_SS));
      DEBUG ((DEBUG_INFO, "  CET_IBT - 0x%08x\n", RegEdx & CPUID_CET_IBT));
      if ((RegEcx & CPUID_CET_SS) == 0) {
        mCetSupported = FALSE;
        if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
          PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
        }
      }

      if (mCetSupported) {
        AsmCpuidEx (CPUID_EXTENDED_STATE, CPUID_EXTENDED_STATE_SUB_LEAF, NULL, &RegEbx, &RegEcx, NULL);
        DEBUG ((DEBUG_INFO, "CPUID[D/1] EBX - 0x%08x, ECX - 0x%08x\n", RegEbx, RegEcx));
        AsmCpuidEx (CPUID_EXTENDED_STATE, 11, &RegEax, NULL, &RegEcx, NULL);
        DEBUG ((DEBUG_INFO, "CPUID[D/11] EAX - 0x%08x, ECX - 0x%08x\n", RegEax, RegEcx));
        AsmCpuidEx (CPUID_EXTENDED_STATE, 12, &RegEax, NULL, &RegEcx, NULL);
        DEBUG ((DEBUG_INFO, "CPUID[D/12] EAX - 0x%08x, ECX - 0x%08x\n", RegEax, RegEcx));
      }
    } else {
      mCetSupported = FALSE;
      if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
        PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
      }
    }
  } else {
    mCetSupported = FALSE;
    if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
      PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
    }
  }

  //
  // Compute tile size of buffer required to hold the CPU SMRAM Save State Map, extra CPU
  // specific context start starts at SMBASE + SMM_PSD_OFFSET, and the SMI entry point.
  // This size is rounded up to nearest power of 2.
  //
  TileCodeSize = GetSmiHandlerSize ();
  TileCodeSize = ALIGN_VALUE (TileCodeSize, SIZE_4KB);
  TileDataSize = (SMRAM_SAVE_STATE_MAP_OFFSET - SMM_PSD_OFFSET) + sizeof (SMRAM_SAVE_STATE_MAP);
  TileDataSize = ALIGN_VALUE (TileDataSize, SIZE_4KB);
  TileSize     = TileDataSize + TileCodeSize - 1;
  TileSize     = 2 * GetPowerOfTwo32 ((UINT32)TileSize);
  DEBUG ((DEBUG_INFO, "SMRAM TileSize = 0x%08x (0x%08x, 0x%08x)\n", TileSize, TileCodeSize, TileDataSize));

  //
  // If the TileSize is larger than space available for the SMI Handler of
  // CPU[i], the extra CPU specific context of CPU[i+1], and the SMRAM Save
  // State Map of CPU[i+1], then ASSERT().  If this ASSERT() is triggered, then
  // the SMI Handler size must be reduced or the size of the extra CPU specific
  // context must be reduced.
  //
  ASSERT (TileSize <= (SMRAM_SAVE_STATE_MAP_OFFSET + sizeof (SMRAM_SAVE_STATE_MAP) - SMM_HANDLER_OFFSET));

  //
  //
  // Check whether the Required TileSize is enough.
  //
  if (TileSize > SIZE_8KB) {
    DEBUG ((DEBUG_ERROR, "The Range of Smbase in SMRAM is not enough -- Required TileSize = 0x%08x, Actual TileSize = 0x%08x\n", TileSize, SIZE_8KB));
    FreePool (gSmmCpuPrivate->ProcessorInfo);
    CpuDeadLoop ();
    return RETURN_BUFFER_TOO_SMALL;
  }

  //
  // Retrieve the allocated SmmBase from gSmmBaseHobGuid. If found,
  // means the SmBase relocation has been done.
  //
  mCpuHotPlugData.SmBase = NULL;
  Status                 = GetSmBase (mMaxNumberOfCpus, &mCpuHotPlugData.SmBase);
  ASSERT (!EFI_ERROR (Status));
  if (EFI_ERROR (Status)) {
    ASSERT (Status != EFI_OUT_OF_RESOURCES);
    PANIC ("Not enough space for mCpuHotPlugData.SmBase");
  }

  //
  // ASSERT SmBase has been relocated.
  //
  ASSERT (mCpuHotPlugData.SmBase != NULL);

  //
  // Allocate buffer for pointers to array in  SMM_CPU_PRIVATE_DATA.
  //
  gSmmCpuPrivate->Operation = (SMM_CPU_OPERATION *)AllocatePool (sizeof (SMM_CPU_OPERATION) * mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->Operation != NULL);

  gSmmCpuPrivate->CpuSaveStateSize = (UINTN *)AllocatePool (sizeof (UINTN) * mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->CpuSaveStateSize != NULL);

  gSmmCpuPrivate->CpuSaveState = (VOID **)AllocatePool (sizeof (VOID *) * mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->CpuSaveState != NULL);

  gSmmCpuPrivate->SmmCoreEntryContext.CpuSaveStateSize = gSmmCpuPrivate->CpuSaveStateSize;
  gSmmCpuPrivate->SmmCoreEntryContext.CpuSaveState     = gSmmCpuPrivate->CpuSaveState;

  //
  // Allocate buffer for pointers to array in CPU_HOT_PLUG_DATA.
  //
  mCpuHotPlugData.ApicId = (UINT64 *)AllocatePool (sizeof (UINT64) * mMaxNumberOfCpus);
  ASSERT (mCpuHotPlugData.ApicId != NULL);
  mCpuHotPlugData.ArrayLength = (UINT32)mMaxNumberOfCpus;

  //
  // Retrieve APIC ID of each enabled processor from the MP Services protocol.
  // Also compute the SMBASE address, CPU Save State address, and CPU Save state
  // size for each CPU in the platform
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    gSmmCpuPrivate->CpuSaveStateSize[Index] = sizeof (SMRAM_SAVE_STATE_MAP);
    gSmmCpuPrivate->CpuSaveState[Index]     = (VOID *)(mCpuHotPlugData.SmBase[Index] + SMRAM_SAVE_STATE_MAP_OFFSET);
    gSmmCpuPrivate->Operation[Index]        = SmmCpuNone;

    if (Index < mNumberOfCpus) {
      mCpuHotPlugData.ApicId[Index] = gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId;

      DEBUG ((
        DEBUG_INFO,
        "CPU[%03x]  APIC ID=%04x  SMBASE=%08x  SaveState=%08x  Size=%08x\n",
        Index,
        (UINT32)gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId,
        mCpuHotPlugData.SmBase[Index],
        gSmmCpuPrivate->CpuSaveState[Index],
        gSmmCpuPrivate->CpuSaveStateSize[Index]
        ));
    } else {
      gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId = INVALID_APIC_ID;
      mCpuHotPlugData.ApicId[Index]                    = INVALID_APIC_ID;
    }
  }

  //
  // Allocate SMI stacks for all processors.
  //
  mSmmStackSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmStackSize)));
  if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
    mSmmStackSize += (PcdGet32 (PcdMmSupervisorExceptionStackSize) + EFI_PAGES_TO_SIZE (1));
  }

  mSmmShadowStackSize = 0;
  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    mSmmShadowStackSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmShadowStackSize)));

    if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
      mSmmShadowStackSize += (PcdGet32 (PcdMmSupervisorExceptionStackSize) + EFI_PAGES_TO_SIZE (1));
    } else {
      mSmmShadowStackSize += PcdGet32 (PcdMmSupervisorExceptionStackSize);
      mSmmStackSize       += PcdGet32 (PcdMmSupervisorExceptionStackSize);
    }
  }

  Stacks = (UINT8 *)AllocatePages (gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus * (EFI_SIZE_TO_PAGES (mSmmStackSize + mSmmShadowStackSize)));
  ASSERT (Stacks != NULL);
  mSmmStackArrayBase = (UINTN)Stacks;
  mSmmStackArrayEnd  = mSmmStackArrayBase + gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus * (mSmmStackSize + mSmmShadowStackSize) - 1;

  DEBUG ((DEBUG_INFO, "Stacks                   - 0x%x\n", Stacks));
  DEBUG ((DEBUG_INFO, "mSmmStackSize            - 0x%x\n", mSmmStackSize));
  DEBUG ((DEBUG_INFO, "PcdCpuSmmStackGuard      - 0x%x\n", FeaturePcdGet (PcdCpuSmmStackGuard)));
  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    DEBUG ((DEBUG_INFO, "mSmmShadowStackSize      - 0x%x\n", mSmmShadowStackSize));
  }

  // Allocate per-cpu stack for ring3
  Status = MmAllocatePages (
             AllocateAnyPages,
             EfiRuntimeServicesData,
             gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus * (EFI_SIZE_TO_PAGES (mSmmStackSize)),
             (EFI_PHYSICAL_ADDRESS *)&Cpl3Stacks
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate user mode stacks - %r!!!\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
  }

  mSmmCpl3StackArrayBase = (UINTN)Cpl3Stacks;
 #if FeaturePcdGet (PcdMmSupervisorTestEnable)
  mSmmCpl3StackArrayEnd = mSmmCpl3StackArrayBase + gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus * mSmmStackSize - 1;
 #endif

  //
  // Initialize IDT
  //
  InitializeSmmIdt ();

  //
  // SMM Time initialization
  //
  InitializeSmmTimer ();

  //
  // Initialize MP globals
  //
  Cr3 = InitializeMpServiceData (Stacks, mSmmStackSize, mSmmShadowStackSize);

  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    for (Index = 0; Index < gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus; Index++) {
      SetShadowStack (
        Cr3,
        (EFI_PHYSICAL_ADDRESS)(UINTN)Stacks + mSmmStackSize + (mSmmStackSize + mSmmShadowStackSize) * Index,
        mSmmShadowStackSize
        );
      if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
        ConvertMemoryPageAttributes (
          Cr3,
          mPagingMode,
          (EFI_PHYSICAL_ADDRESS)(UINTN)Stacks + mSmmStackSize + PcdGet32 (PcdMmSupervisorExceptionStackSize) + (mSmmStackSize + mSmmShadowStackSize) * Index,
          EFI_PAGES_TO_SIZE (1),
          EFI_MEMORY_RP,
          TRUE,
          NULL
          );
      }
    }
  }

  DEBUG ((DEBUG_INFO, "mXdSupported - 0x%x\n", mXdSupported));

  if (mSmmInitialized == NULL) {
    mSmmInitialized = (BOOLEAN *)AllocateZeroPool (sizeof (BOOLEAN) * mMaxNumberOfCpus);
  }

  ASSERT (mSmmInitialized != NULL);
  if (mSmmInitialized == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Fill in SMM Reserved Regions
  //
  gSmmCpuPrivate->SmmReservedSmramRegion[0].SmramReservedStart = 0;
  gSmmCpuPrivate->SmmReservedSmramRegion[0].SmramReservedSize  = 0;

  //
  // Install the SMM Configuration Protocol onto a new handle on the handle database.
  // The entire SMM Configuration Protocol is allocated from SMRAM, so only a pointer
  // to an SMRAM address will be present in the handle database
  //
  Status = gMmCoreMmst.MmInstallProtocolInterface (
                         &gSmmCpuPrivate->SmmCpuHandle,
                         &gEfiSmmConfigurationProtocolGuid,
                         EFI_NATIVE_INTERFACE,
                         &gSmmCpuPrivate->SmmConfiguration
                         );
  ASSERT_EFI_ERROR (Status);

  // MSCHANGE [BEGIN] - Add flag to enable "test mode" for the SMM protections.
  //                    NOTE: "Test mode" will only be enabled in DEBUG builds.
  if (FeaturePcdGet (PcdSmmExceptionTestModeSupport)) {
    Status = gMmCoreMmst.MmInstallProtocolInterface (
                           &mSmmExceptionTestProtocolHandle,
                           &gSmmExceptionTestProtocolGuid,
                           EFI_NATIVE_INTERFACE,
                           &mSmmExceptionTestProtocol
                           );
    ASSERT_EFI_ERROR (Status);
  }

  // MSCHANGE [END]

  //
  // Initialize global buffer for MM MP.
  //
  InitializeDataForMmMp ();

  //
  // Initialize Package First Thread Index Info.
  //
  InitPackageFirstThreadIndexInfo ();

  //
  // Initialize SMM Profile feature
  //
  mSmmCr3 = Cr3;

  DEBUG ((DEBUG_INFO, "SMM CPU Module exit from SMRAM with EFI_SUCCESS\n"));

  PERF_FUNCTION_END ();
  return EFI_SUCCESS;
}
