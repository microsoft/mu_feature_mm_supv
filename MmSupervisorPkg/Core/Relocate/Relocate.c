/** @file
Agent Module to load other modules to deploy SMM Entry Vector for X86 CPU.

Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Relocate.h"
#include "Mem/Mem.h"
#include "Mem/HeapGuard.h"
#include "Services/MpService/MpService.h"
#include "MmSupervisorCore.h"

CPU_HOT_PLUG_DATA  mCpuHotPlugData = {
  CPU_HOT_PLUG_DATA_REVISION_1,                 // Revision
  0,                                            // Array Length of SmBase and APIC ID
  NULL,                                         // Pointer to APIC ID array
  NULL,                                         // Pointer to SMBASE array
  0,                                            // Reserved
  0,                                            // SmrrBase
  0                                             // SmrrSize
};

///
/// Handle for the SMM CPU Protocol
///
EFI_HANDLE  mSmmCpuHandle = NULL;

EFI_CPU_INTERRUPT_HANDLER  mExternalVectorTable[EXCEPTION_VECTOR_NUMBER];

volatile BOOLEAN  *mSmmInitialized = NULL;
UINT32            mBspApicId       = 0;

//
// SMM stack information
//
UINTN  mSmmStackArrayBase;
UINTN  mSmmStackArrayEnd;
UINTN  mSmmStackSize;

UINTN  mSmmCpl3StackArrayBase;
#if FeaturePcdGet (PcdMmSupervisorTestEnable)
UINTN  mSmmCpl3StackArrayEnd;
#endif

UINTN    mSmmShadowStackSize;
BOOLEAN  mCetSupported = TRUE;

UINTN  mMaxNumberOfCpus = 0;
UINTN  mNumberOfCpus    = 0;

//
// SMM ready to lock flag
//
BOOLEAN  mSmmReadyToLock = FALSE;

//
// Global used to cache PCD for SMM Code Access Check enable
//
BOOLEAN  mSmmCodeAccessCheckEnable = FALSE;

//
// Global copy of the PcdPteMemoryEncryptionAddressOrMask
//
UINT64  mAddressEncMask = 0;

//
// Spin lock used to serialize setting of SMM Code Access Check feature
//
SPIN_LOCK  *mConfigSmmCodeAccessCheckLock = NULL;

//
// Saved SMM ranges information
//
EFI_SMRAM_DESCRIPTOR  *mSmmCpuSmramRanges;
UINTN                 mSmmCpuSmramRangeCount;
//
// MSCHANGE [BEGIN] - Add flag to enable "test mode" for the SMM protections.
//                    NOTE: "Test mode" will only be enabled in DEBUG builds.
// Flag to indicate exception handling should be in test mode.
// This will cause exceptions to reset the system and/or log
// additional telemetry.
//

// Driver-wide global variable to hold CR3 inside SMM
UINT32  mSmmCr3;

/**
  Enable exception handling test mode.

  NOTE: This should only work on debug builds, otherwise return EFI_UNSUPPORTED.

  @retval EFI_SUCCESS            Test mode enabled.
  @retval EFI_UNSUPPORTED        Test mode could not be enabled.

**/
EFI_STATUS
EFIAPI
// MU_CHANGE
EnableSmmExceptionTestMode (
  VOID
  );

//
// Protocol for other drivers to enable test mode.
//
SMM_EXCEPTION_TEST_PROTOCOL  mSmmExceptionTestProtocol = {
  EnableSmmExceptionTestMode
};
EFI_HANDLE                   mSmmExceptionTestProtocolHandle = NULL;

BOOLEAN  mSmmRebootOnException = TRUE;
// MSCHANGE [END]

/**
  Initialize IDT to setup exception handlers for SMM.

**/
VOID
InitializeSmmIdt (
  VOID
  )
{
  EFI_STATUS       Status;
  BOOLEAN          InterruptState;
  IA32_DESCRIPTOR  DxeIdtr;

  //
  // There are 32 (not 255) entries in it since only processor
  // generated exceptions will be handled.
  //
  gcSmiIdtr.Limit = (sizeof (IA32_IDT_GATE_DESCRIPTOR) * 32) - 1;
  //
  // Allocate page aligned IDT, because it might be set as read only.
  //
  gcSmiIdtr.Base = (UINTN)AllocateCodePages (EFI_SIZE_TO_PAGES (gcSmiIdtr.Limit + 1));
  ASSERT (gcSmiIdtr.Base != 0);
  ZeroMem ((VOID *)gcSmiIdtr.Base, gcSmiIdtr.Limit + 1);

  //
  // Disable Interrupt and save DXE IDT table
  //
  InterruptState = SaveAndDisableInterrupts ();
  AsmReadIdtr (&DxeIdtr);
  //
  // Load SMM temporary IDT table
  //
  AsmWriteIdtr (&gcSmiIdtr);
  //
  // Setup SMM default exception handlers, SMM IDT table
  // will be updated and saved in gcSmiIdtr
  //
  Status = InitializeCpuExceptionHandlers (NULL);
  ASSERT_EFI_ERROR (Status);
  //
  // Restore DXE IDT table and CPU interrupt
  //
  AsmWriteIdtr ((IA32_DESCRIPTOR *)&DxeIdtr);
  SetInterruptState (InterruptState);
}

/**
  Search module name by input IP address and output it.

  @param CallerIpAddress   Caller instruction pointer.

**/
VOID
DumpModuleInfoByIp (
  IN  UINTN  CallerIpAddress
  )
{
  UINTN  Pe32Data;
  VOID   *PdbPointer;

  //
  // Find Image Base
  //
  Pe32Data = PeCoffSearchImageBase (CallerIpAddress);
  if (Pe32Data != 0) {
    DEBUG ((DEBUG_ERROR, "It is invoked from the instruction before IP(0x%p)", (VOID *)CallerIpAddress));
    PdbPointer = PeCoffLoaderGetPdbPointer ((VOID *)Pe32Data);
    if (PdbPointer != NULL) {
      DEBUG ((DEBUG_ERROR, " in module (%a)\n", PdbPointer));
    }
  }
}

/**
  Initialize SMM environment.

**/
VOID
EFIAPI
InitializeSmm (
  VOID
  )
{
  UINT32   ApicId;
  UINTN    Index;
  BOOLEAN  IsBsp;

  ApicId = GetApicId ();

  IsBsp = (BOOLEAN)(mBspApicId == ApicId);

  ASSERT (mNumberOfCpus <= mMaxNumberOfCpus);

  for (Index = 0; Index < mNumberOfCpus; Index++) {
    if (ApicId == (UINT32)gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId) {
      PERF_CODE (
        MpPerfBegin (Index, SMM_MP_PERF_PROCEDURE_ID (InitializeSmm));
        );
      //
      // Initialize SMM specific features on the currently executing CPU
      //
      SmmCpuFeaturesInitializeProcessor (
        Index,
        IsBsp,
        gSmmCpuPrivate->ProcessorInfo,
        &mCpuHotPlugData
        );

      if (IsBsp) {
        //
        // Call memory management hook function to set all cached guard pages during initialization.
        // This is only applicable to the first time in MMI, since all page allocation/free will
        // set/unset the guard pages on the fly.
        //
        MmEntryPointMemoryManagementHook ();

        // Set up the code access check before any handler was iterated
        ConfigSmmCodeAccessCheck ();
      }

      PERF_CODE (
        MpPerfEnd (Index, SMM_MP_PERF_PROCEDURE_ID (InitializeSmm));
        );

      return;
    }
  }

  ASSERT (FALSE);
}

/**
  Issue SMI IPI (All Excluding Self SMM IPI + BSP SMM IPI) to execute first SMI init.
**/
VOID
ExecuteFirstSmiInit (
  VOID
  )
{
  UINTN  Index;

  PERF_FUNCTION_BEGIN ();

  //
  // Get the BSP ApicId.
  //
  mBspApicId = GetApicId ();

  //
  // Issue SMI IPI (All Excluding Self SMM IPI + BSP SMM IPI) for SMM init
  //
  SendSmiIpi (mBspApicId);
  SendSmiIpiAllExcludingSelf ();

  //
  // Wait for all processors to finish its 1st SMI
  //
  for (Index = 0; Index < mNumberOfCpus; Index++) {
    while (!(BOOLEAN)mSmmInitialized[Index]) {
    }
  }

  PERF_FUNCTION_END ();
}

EFI_STATUS
EFIAPI
SmmInitializeMemoryAttributesTable (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  );

//
// LockMmCoreBeforeExit and SetupSmiEntryExit live in Relocate_core.c (Core
// build) and Relocate_init.c (Init build) because their bodies and (for
// LockMmCoreBeforeExit) signatures diverge between the two builds.
//

/**
  Function to compare 2 SMM_BASE_HOB_DATA pointer based on ProcessorIndex.
  @param[in] Buffer1            pointer to SMM_BASE_HOB_DATA pointer to compare
  @param[in] Buffer2            pointer to second SMM_BASE_HOB_DATA pointer to compare
  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
SmBaseHobCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if ((*(SMM_BASE_HOB_DATA **)Buffer1)->ProcessorIndex > (*(SMM_BASE_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return 1;
  } else if ((*(SMM_BASE_HOB_DATA **)Buffer1)->ProcessorIndex < (*(SMM_BASE_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return -1;
  }

  return 0;
}

/**
  Extract SmBase for all CPU from SmmBase HOB.

  @param[in]  MaxNumberOfCpus        Max NumberOfCpus.

  @param[out] AllocatedSmBaseBuffer  Pointer to SmBase Buffer allocated
                                     by this function. Only set if the
                                     function returns EFI_SUCCESS.

  @retval EFI_SUCCESS           SmBase Buffer output successfully.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval EFI_NOT_FOUND         gSmmBaseHobGuid was never created.
**/
STATIC
EFI_STATUS
GetSmBase (
  IN  UINTN  MaxNumberOfCpus,
  OUT UINTN  **AllocatedSmBaseBuffer
  )
{
  UINTN              HobCount;
  EFI_HOB_GUID_TYPE  *GuidHob;
  SMM_BASE_HOB_DATA  *SmmBaseHobData;
  UINTN              NumberOfProcessors;
  SMM_BASE_HOB_DATA  **SmBaseHobs;
  UINTN              *SmBaseBuffer;
  UINTN              HobIndex;
  UINTN              SortBuffer;
  UINTN              ProcessorIndex;
  UINT64             PrevProcessorIndex;
  EFI_HOB_GUID_TYPE  *FirstSmmBaseGuidHob;

  SmmBaseHobData     = NULL;
  HobIndex           = 0;
  ProcessorIndex     = 0;
  HobCount           = 0;
  NumberOfProcessors = 0;

  FirstSmmBaseGuidHob = GetFirstGuidHob (&gSmmBaseHobGuid);
  if (FirstSmmBaseGuidHob == NULL) {
    return EFI_NOT_FOUND;
  }

  GuidHob = FirstSmmBaseGuidHob;
  while (GuidHob != NULL) {
    HobCount++;
    SmmBaseHobData      = GET_GUID_HOB_DATA (GuidHob);
    NumberOfProcessors += SmmBaseHobData->NumberOfProcessors;

    if (NumberOfProcessors >= MaxNumberOfCpus) {
      break;
    }

    GuidHob = GetNextGuidHob (&gSmmBaseHobGuid, GET_NEXT_HOB (GuidHob));
  }

  ASSERT (NumberOfProcessors == MaxNumberOfCpus);
  if (NumberOfProcessors != MaxNumberOfCpus) {
    PANIC ("NumberOfProcessors does not match MaxNumberOfCpus");
    return EFI_DEVICE_ERROR;
  }

  SmBaseHobs = AllocatePool (sizeof (SMM_BASE_HOB_DATA *) * HobCount);
  if (SmBaseHobs == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Record each SmmBaseHob pointer in the SmBaseHobs.
  // The FirstSmmBaseGuidHob is to speed up this while-loop
  // without needing to look for SmBaseHob from beginning.
  //
  GuidHob = FirstSmmBaseGuidHob;
  while (HobIndex < HobCount) {
    SmBaseHobs[HobIndex++] = GET_GUID_HOB_DATA (GuidHob);
    GuidHob                = GetNextGuidHob (&gSmmBaseHobGuid, GET_NEXT_HOB (GuidHob));
  }

  SmBaseBuffer = (UINTN *)AllocatePool (sizeof (UINTN) * (MaxNumberOfCpus));
  ASSERT (SmBaseBuffer != NULL);
  if (SmBaseBuffer == NULL) {
    FreePool (SmBaseHobs);
    return EFI_OUT_OF_RESOURCES;
  }

  QuickSort (SmBaseHobs, HobCount, sizeof (SMM_BASE_HOB_DATA *), (BASE_SORT_COMPARE)SmBaseHobCompare, &SortBuffer);
  PrevProcessorIndex = 0;
  for (HobIndex = 0; HobIndex < HobCount; HobIndex++) {
    //
    // Make sure no overlap and no gap in the CPU range covered by each HOB
    //
    ASSERT (SmBaseHobs[HobIndex]->ProcessorIndex == PrevProcessorIndex);

    //
    // Cache each SmBase in order.
    //
    for (ProcessorIndex = 0; ProcessorIndex < SmBaseHobs[HobIndex]->NumberOfProcessors; ProcessorIndex++) {
      SmBaseBuffer[PrevProcessorIndex + ProcessorIndex] = (UINTN)SmBaseHobs[HobIndex]->SmBase[ProcessorIndex];
    }

    PrevProcessorIndex += SmBaseHobs[HobIndex]->NumberOfProcessors;
  }

  FreePool (SmBaseHobs);
  *AllocatedSmBaseBuffer = SmBaseBuffer;
  return EFI_SUCCESS;
}

/**
  Function to compare 2 MP_INFORMATION2_HOB_DATA pointer based on ProcessorIndex.
  @param[in] Buffer1            pointer to MP_INFORMATION2_HOB_DATA pointer to compare
  @param[in] Buffer2            pointer to second MP_INFORMATION2_HOB_DATA pointer to compare
  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
MpInformation2HobCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if ((*(MP_INFORMATION2_HOB_DATA **)Buffer1)->ProcessorIndex > (*(MP_INFORMATION2_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return 1;
  } else if ((*(MP_INFORMATION2_HOB_DATA **)Buffer1)->ProcessorIndex < (*(MP_INFORMATION2_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return -1;
  }

  return 0;
}

/**
  Extract NumberOfCpus, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION for all CPU from MpInformation2 HOB.
  @param[out] NumberOfCpus           Pointer to NumberOfCpus.
  @param[out] MaxNumberOfCpus        Pointer to MaxNumberOfCpus.
  @retval ProcessorInfo              Pointer to EFI_PROCESSOR_INFORMATION buffer.
**/
EFI_PROCESSOR_INFORMATION *
GetMpInformation (
  OUT UINTN  *NumberOfCpus,
  OUT UINTN  *MaxNumberOfCpus
  )
{
  EFI_HOB_GUID_TYPE          *GuidHob;
  EFI_HOB_GUID_TYPE          *FirstMpInfo2Hob;
  MP_INFORMATION2_HOB_DATA   *MpInformation2HobData;
  UINTN                      HobCount;
  UINTN                      HobIndex;
  MP_INFORMATION2_HOB_DATA   **MpInfo2Hobs;
  UINTN                      SortBuffer;
  UINTN                      ProcessorIndex;
  UINT64                     PrevProcessorIndex;
  MP_INFORMATION2_ENTRY      *MpInformation2Entry;
  EFI_PROCESSOR_INFORMATION  *ProcessorInfo;

  GuidHob               = NULL;
  MpInformation2HobData = NULL;
  FirstMpInfo2Hob       = NULL;
  MpInfo2Hobs           = NULL;
  HobIndex              = 0;
  HobCount              = 0;

  FirstMpInfo2Hob = GetFirstGuidHob (&gMpInformation2HobGuid);
  ASSERT (FirstMpInfo2Hob != NULL);
  GuidHob = FirstMpInfo2Hob;
  while (GuidHob != NULL) {
    MpInformation2HobData = GET_GUID_HOB_DATA (GuidHob);

    //
    // This is the last MpInformationHob in the HOB list.
    //
    if (MpInformation2HobData->NumberOfProcessors == 0) {
      ASSERT (HobCount != 0);
      break;
    }

    HobCount++;
    *NumberOfCpus += MpInformation2HobData->NumberOfProcessors;
    GuidHob        = GetNextGuidHob (&gMpInformation2HobGuid, GET_NEXT_HOB (GuidHob));
  }

  ASSERT (*NumberOfCpus <= PcdGet32 (PcdCpuMaxLogicalProcessorNumber));

  //
  // If support CPU hot plug, we need to allocate resources for possibly hot-added processors
  //
  if (FeaturePcdGet (PcdCpuHotPlugSupport)) {
    *MaxNumberOfCpus = PcdGet32 (PcdCpuMaxLogicalProcessorNumber);
  } else {
    *MaxNumberOfCpus = *NumberOfCpus;
  }

  MpInfo2Hobs = AllocatePool (sizeof (MP_INFORMATION2_HOB_DATA *) * HobCount);
  ASSERT (MpInfo2Hobs != NULL);
  if (MpInfo2Hobs == NULL) {
    return NULL;
  }

  //
  // Record each MpInformation2Hob pointer in the MpInfo2Hobs.
  // The FirstMpInfo2Hob is to speed up this while-loop without
  // needing to look for MpInfo2Hob from beginning.
  //
  GuidHob = FirstMpInfo2Hob;
  while (HobIndex < HobCount) {
    MpInfo2Hobs[HobIndex++] = GET_GUID_HOB_DATA (GuidHob);
    GuidHob                 = GetNextGuidHob (&gMpInformation2HobGuid, GET_NEXT_HOB (GuidHob));
  }

  ProcessorInfo = (EFI_PROCESSOR_INFORMATION *)AllocatePool (sizeof (EFI_PROCESSOR_INFORMATION) * (*MaxNumberOfCpus));
  ASSERT (ProcessorInfo != NULL);
  if (ProcessorInfo == NULL) {
    FreePool (MpInfo2Hobs);
    return NULL;
  }

  QuickSort (MpInfo2Hobs, HobCount, sizeof (MP_INFORMATION2_HOB_DATA *), (BASE_SORT_COMPARE)MpInformation2HobCompare, &SortBuffer);
  PrevProcessorIndex = 0;
  for (HobIndex = 0; HobIndex < HobCount; HobIndex++) {
    //
    // Make sure no overlap and no gap in the CPU range covered by each HOB
    //
    ASSERT (MpInfo2Hobs[HobIndex]->ProcessorIndex == PrevProcessorIndex);

    //
    // Cache each EFI_PROCESSOR_INFORMATION in order.
    //
    for (ProcessorIndex = 0; ProcessorIndex < MpInfo2Hobs[HobIndex]->NumberOfProcessors; ProcessorIndex++) {
      MpInformation2Entry = GET_MP_INFORMATION_ENTRY (MpInfo2Hobs[HobIndex], ProcessorIndex);
      CopyMem (
        &ProcessorInfo[PrevProcessorIndex + ProcessorIndex],
        &MpInformation2Entry->ProcessorInfo,
        sizeof (EFI_PROCESSOR_INFORMATION)
        );
    }

    PrevProcessorIndex += MpInfo2Hobs[HobIndex]->NumberOfProcessors;
  }

  FreePool (MpInfo2Hobs);
  return ProcessorInfo;
}

/**
  Function to perform post relocation logic before handing back to the IPL.

**/
VOID
PostRelocationRun (
  VOID
  )
{
  // MU_CHANGE: Moved first SMI and SMM CPU features to after SMM Profile init
  //
  // For relocated SMBASE, some MSRs & CSRs are still required to be configured in SMM Mode for SMM Initialization.
  // Those MSRs & CSRs must be configured before normal SMI sources happen.
  // So, here is to issue SMI IPI (All Excluding  Self SMM IPI + BSP SMM IPI) to execute first SMI init.
  //
  ExecuteFirstSmiInit ();

  //
  // Call hook for BSP to perform extra actions in normal mode after all
  // SMM base addresses have been relocated on all CPUs
  //
  SmmCpuFeaturesSmmRelocationComplete ();
}


/**
  Function to compare 2 EFI_SMRAM_DESCRIPTOR based on CpuStart.
  @param[in] Buffer1            pointer to Device Path pointer to compare
  @param[in] Buffer2            pointer to second DevicePath pointer to compare
  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
CpuSmramRangeCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if (((EFI_SMRAM_DESCRIPTOR *)Buffer1)->CpuStart > ((EFI_SMRAM_DESCRIPTOR *)Buffer2)->CpuStart) {
    return 1;
  } else if (((EFI_SMRAM_DESCRIPTOR *)Buffer1)->CpuStart < ((EFI_SMRAM_DESCRIPTOR *)Buffer2)->CpuStart) {
    return -1;
  }

  return 0;
}

/**

  Find out SMRAM information including SMRR base and SMRR size.

  @param          SmrrBase          SMRR base
  @param          SmrrSize          SMRR size

**/
VOID
FindSmramInfo (
  OUT UINT32  *SmrrBase,
  OUT UINT32  *SmrrSize
  )
{
  EFI_SMRAM_DESCRIPTOR            *CurrentSmramRange;
  EFI_HOB_GUID_TYPE               *GuidHob;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *HobData;
  UINTN                           Index;
  UINT64                          MaxSize;
  BOOLEAN                         Found;
  EFI_SMRAM_DESCRIPTOR            SmramDescriptor;

  //
  // Get SMRAM hob
  //
  GuidHob = GetFirstGuidHob (&gEfiMmPeiMmramMemoryReserveGuid);
  if (GuidHob == NULL) {
    GuidHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
    if (GuidHob == NULL) {
      DEBUG ((DEBUG_ERROR, "[%a] - Critical HOB missing that describes MMRAM regions. Cannot load MM.\n", __func__));
      ASSERT (GuidHob != NULL);
      if (mSmmRebootOnException) {
        DEBUG ((DEBUG_ERROR, "%a - Specifically invoke break point exception to log telemetry.\n", __func__));
        CpuBreakpoint ();
        ResetWarm ();
      }

      PANIC ("Critical HOB missing that describes MMRAM regions");
    }
  }

  //
  // Get SMRAM information
  //
  HobData = GET_GUID_HOB_DATA (GuidHob);

  mSmmCpuSmramRangeCount = HobData->NumberOfMmReservedRegions;
  mSmmCpuSmramRanges     = (EFI_SMRAM_DESCRIPTOR *)AllocatePool (mSmmCpuSmramRangeCount * sizeof (EFI_SMRAM_DESCRIPTOR));
  ASSERT (mSmmCpuSmramRanges != NULL);

  CopyMem (mSmmCpuSmramRanges, HobData->Descriptor, mSmmCpuSmramRangeCount * sizeof (EFI_SMRAM_DESCRIPTOR));

  //
  // Sort the mSmmCpuSmramRanges
  //
  QuickSort (mSmmCpuSmramRanges, mSmmCpuSmramRangeCount, sizeof (EFI_SMRAM_DESCRIPTOR), (BASE_SORT_COMPARE)CpuSmramRangeCompare, &SmramDescriptor);

  //
  // Find the largest SMRAM range between 1MB and 4GB that is at least 256K - 4K in size
  //
  CurrentSmramRange = NULL;
  for (Index = 0, MaxSize = SIZE_256KB - EFI_PAGE_SIZE; Index < mSmmCpuSmramRangeCount; Index++) {
    //
    // Skip any SMRAM region that is already allocated, needs testing, or needs ECC initialization
    //
    if ((mSmmCpuSmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    if (mSmmCpuSmramRanges[Index].CpuStart >= BASE_1MB) {
      if ((mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize) <= SMRR_MAX_ADDRESS) {
        if (mSmmCpuSmramRanges[Index].PhysicalSize >= MaxSize) {
          MaxSize           = mSmmCpuSmramRanges[Index].PhysicalSize;
          CurrentSmramRange = &mSmmCpuSmramRanges[Index];
        }
      }
    }
  }

  ASSERT (CurrentSmramRange != NULL);

  *SmrrBase = (UINT32)CurrentSmramRange->CpuStart;
  *SmrrSize = (UINT32)CurrentSmramRange->PhysicalSize;

  do {
    Found = FALSE;
    for (Index = 0; Index < mSmmCpuSmramRangeCount; Index++) {
      if ((mSmmCpuSmramRanges[Index].CpuStart < *SmrrBase) &&
          (*SmrrBase == (mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize)))
      {
        *SmrrBase = (UINT32)mSmmCpuSmramRanges[Index].CpuStart;
        *SmrrSize = (UINT32)(*SmrrSize + mSmmCpuSmramRanges[Index].PhysicalSize);
        Found     = TRUE;
      } else if (((*SmrrBase + *SmrrSize) == mSmmCpuSmramRanges[Index].CpuStart) && (mSmmCpuSmramRanges[Index].PhysicalSize > 0)) {
        *SmrrSize = (UINT32)(*SmrrSize + mSmmCpuSmramRanges[Index].PhysicalSize);
        Found     = TRUE;
      }
    }
  } while (Found);

  DEBUG ((DEBUG_INFO, "SMRR Base: 0x%x, SMRR Size: 0x%x\n", *SmrrBase, *SmrrSize));
}

/**
Configure SMM Code Access Check feature on an AP.
SMM Feature Control MSR will be locked after configuration.

@param[in,out] Buffer  Pointer to private data buffer.
**/
VOID
EFIAPI
ConfigSmmCodeAccessCheckOnCurrentProcessor (
  IN OUT VOID  *Buffer
  )
{
  UINTN   CpuIndex;
  UINT64  SmmFeatureControlMsr;
  UINT64  NewSmmFeatureControlMsr;

  //
  // Retrieve the CPU Index from the context passed in
  //
  CpuIndex = *(UINTN *)Buffer;

  //
  // Get the current SMM Feature Control MSR value
  //
  SmmFeatureControlMsr = SmmCpuFeaturesGetSmmRegister (CpuIndex, SmmRegFeatureControl);

  //
  // Compute the new SMM Feature Control MSR value
  //
  NewSmmFeatureControlMsr = SmmFeatureControlMsr;
  if (mSmmCodeAccessCheckEnable) {
    NewSmmFeatureControlMsr |= SMM_CODE_CHK_EN_BIT;
    if (FeaturePcdGet (PcdCpuSmmFeatureControlMsrLock)) {
      NewSmmFeatureControlMsr |= SMM_FEATURE_CONTROL_LOCK_BIT;
    }
  }

  //
  // Only set the SMM Feature Control MSR value if the new value is different than the current value
  //
  if (NewSmmFeatureControlMsr != SmmFeatureControlMsr) {
    SmmCpuFeaturesSetSmmRegister (CpuIndex, SmmRegFeatureControl, NewSmmFeatureControlMsr);
  }

  //
  // Release the spin lock user to serialize the updates to the SMM Feature Control MSR
  //
  ReleaseSpinLock (mConfigSmmCodeAccessCheckLock);
}

/**
Configure SMM Code Access Check feature for all processors.
SMM Feature Control MSR will be locked after configuration.
**/
VOID
ConfigSmmCodeAccessCheck (
  VOID
  )
{
  UINTN       Index;
  EFI_STATUS  Status;

  PERF_FUNCTION_BEGIN ();

  //
  // Check to see if the Feature Control MSR is supported on this CPU
  //
  Index = gSmmCpuPrivate->SmmCoreEntryContext.CurrentlyExecutingCpu;
  if (!SmmCpuFeaturesIsSmmRegisterSupported (Index, SmmRegFeatureControl)) {
    mSmmCodeAccessCheckEnable = FALSE;
    PERF_FUNCTION_END ();
    return;
  }

  //
  // Check to see if the CPU supports the SMM Code Access Check feature
  // Do not access this MSR unless the CPU supports the SmmRegFeatureControl
  //
  if ((AsmReadMsr64 (EFI_MSR_SMM_MCA_CAP) & SMM_CODE_ACCESS_CHK_BIT) == 0) {
    mSmmCodeAccessCheckEnable = FALSE;
    PERF_FUNCTION_END ();
    return;
  }

  //
  // Initialize the lock used to serialize the MSR programming in BSP and all APs
  //
  InitializeSpinLock (mConfigSmmCodeAccessCheckLock);

  //
  // Acquire Config SMM Code Access Check spin lock.  The BSP will release the
  // spin lock when it is done executing ConfigSmmCodeAccessCheckOnCurrentProcessor().
  //
  AcquireSpinLock (mConfigSmmCodeAccessCheckLock);

  //
  // Enable SMM Code Access Check feature on the BSP.
  //
  ConfigSmmCodeAccessCheckOnCurrentProcessor (&Index);

  //
  // Enable SMM Code Access Check feature for the APs.
  //
  for (Index = 0; Index < gMmCoreMmst.NumberOfCpus; Index++) {
    if (Index != gSmmCpuPrivate->SmmCoreEntryContext.CurrentlyExecutingCpu) {
      if (gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId == INVALID_APIC_ID) {
        //
        // If this processor does not exist
        //
        continue;
      }

      //
      // Acquire Config SMM Code Access Check spin lock.  The AP will release the
      // spin lock when it is done executing ConfigSmmCodeAccessCheckOnCurrentProcessor().
      //
      AcquireSpinLock (mConfigSmmCodeAccessCheckLock);

      //
      // Call SmmStartupThisAp() to enable SMM Code Access Check on an AP.
      //
      Status = gMmCoreMmst.MmStartupThisAp (ConfigSmmCodeAccessCheckOnCurrentProcessor, Index, &Index);
      ASSERT_EFI_ERROR (Status);

      //
      // Wait for the AP to release the Config SMM Code Access Check spin lock.
      //
      while (!AcquireSpinLockOrFail (mConfigSmmCodeAccessCheckLock)) {
        CpuPause ();
      }

      //
      // Release the Config SMM Code Access Check spin lock.
      //
      ReleaseSpinLock (mConfigSmmCodeAccessCheckLock);
    }
  }

  PERF_FUNCTION_END ();
}

// MSCHANGE [BEGIN] - Add flag to enable "test mode" for the SMM protections.
//                    NOTE: "Test mode" will only be enabled in DEBUG builds.

/**
  Enable exception handling test mode.

  NOTE: This should only work on debug builds, otherwise return EFI_UNSUPPORTED.

  @retval EFI_SUCCESS            Test mode enabled.
  @retval EFI_UNSUPPORTED        Test mode could not be enabled.

**/
EFI_STATUS
EFIAPI
// MU_CHANGE
EnableSmmExceptionTestMode (
  VOID
  )
{
  EFI_STATUS  Status = EFI_UNSUPPORTED;

  if (FeaturePcdGet (PcdSmmExceptionTestModeSupport)) {
    // MU_CHANGE START
    DEBUG ((DEBUG_INFO, "%a - Test mode enabled!\n", __func__));
    // MU_CHANGE END
    mSmmRebootOnException = TRUE;
    Status                = EFI_SUCCESS;
  }

  return Status;
}

// MSCHANGE [END]
