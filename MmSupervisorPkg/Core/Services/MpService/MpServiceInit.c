/** @file
SMM MP initialization and synchronization helpers

Copyright (c) 2009 - 2024, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include "MmSupervisorCore.h"
#include "Services/CpuService/CpuService.h"
#include "MpService.h"
#include "Relocate/Relocate.h"
#include "Mem/Mem.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"

#include <Library/MmMemoryProtectionHobLib.h> // MU_CHANGE

//
// SMM CPU Private Data structure that contains SMM Configuration Protocol
// along its supporting fields.
//
SMM_CPU_PRIVATE_DATA  mSmmCpuPrivateData = {
  SMM_CPU_PRIVATE_DATA_SIGNATURE,               // Signature
  NULL,                                         // SmmCpuHandle
  NULL,                                         // Pointer to ProcessorInfo array
  NULL,                                         // Pointer to Operation array
  NULL,                                         // Pointer to CpuSaveStateSize array
  NULL,                                         // Pointer to CpuSaveState array
  {
    { 0    }
  },                                            // SmmReservedSmramRegion
  {
    NULL,                           // SmmCoreEntryContext.SmmStartupThisAp
    0,                              // SmmCoreEntryContext.CurrentlyExecutingCpu
    0,                              // SmmCoreEntryContext.NumberOfCpus
    NULL,                           // SmmCoreEntryContext.CpuSaveStateSize
    NULL                            // SmmCoreEntryContext.CpuSaveState
  },
  NULL,                                         // SmmCoreEntry
  {
    NULL,  // SmmConfiguration.SmramReservedRegions
    NULL   // SmmConfiguration.RegisterSmmEntry
  },
  NULL,                                         // pointer to Ap Wrapper Func array
  { NULL, NULL },                               // List_Entry for Tokens.
};

//
// Global pointer used to access mSmmCpuPrivateData from outside and inside SMM
//
SMM_CPU_PRIVATE_DATA  *gSmmCpuPrivate = &mSmmCpuPrivateData;

//
// Slots for all MTRR( FIXED MTRR + VARIABLE MTRR + MTRR_LIB_IA32_MTRR_DEF_TYPE)
//
MTRR_SETTINGS                gSmiMtrrs;
UINT64                       gPhyMask;
SMM_DISPATCHER_MP_SYNC_DATA  *mSmmMpSyncData = NULL;
UINTN                        mSmmMpSyncDataSize;
SMM_CPU_SEMAPHORES           mSmmCpuSemaphores;
UINTN                        mSemaphoreSize;
SPIN_LOCK                    *mPFLock = NULL;
// SMM_CPU_SYNC_MODE            mCpuSmmSyncMode;

/**
  Used for BSP to release all APs.
  Performs an atomic compare exchange operation to release semaphore
  for each AP.

**/
VOID
ReleaseAllAPs (
  VOID
  )
{
  UINTN  Index;

  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (IsPresentAp (Index)) {
      SmmCpuSyncReleaseOneAp (mSmmMpSyncData->SyncContext, Index, gSmmCpuPrivate->SmmCoreEntryContext.CurrentlyExecutingCpu);
    }
  }
}

/**
  Check whether task has been finished by all APs.

  @param       BlockMode   Whether did it in block mode or non-block mode.

  @retval      TRUE        Task has been finished by all APs.
  @retval      FALSE       Task not has been finished by all APs.

**/
BOOLEAN
WaitForAllAPsNotBusy (
  IN BOOLEAN  BlockMode
  )
{
  UINTN  Index;

  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    //
    // Ignore BSP and APs which not call in SMM.
    //
    if (!IsPresentAp (Index)) {
      continue;
    }

    if (BlockMode) {
      AcquireSpinLock (mSmmMpSyncData->CpuData[Index].Busy);
      ReleaseSpinLock (mSmmMpSyncData->CpuData[Index].Busy);
    } else {
      if (AcquireSpinLockOrFail (mSmmMpSyncData->CpuData[Index].Busy)) {
        ReleaseSpinLock (mSmmMpSyncData->CpuData[Index].Busy);
      } else {
        return FALSE;
      }
    }
  }

  return TRUE;
}

/**
  Check whether it is an present AP.

  @param   CpuIndex      The AP index which calls this function.

  @retval  TRUE           It's a present AP.
  @retval  TRUE           This is not an AP or it is not present.

**/
BOOLEAN
IsPresentAp (
  IN UINTN  CpuIndex
  )
{
  return ((CpuIndex != gSmmCpuPrivate->SmmCoreEntryContext.CurrentlyExecutingCpu) &&
          *(mSmmMpSyncData->CpuData[CpuIndex].Present));
}

/**
  Allocate buffer for the SPIN_LOCK and PROCEDURE_TOKEN.

  @return First token of the token buffer.
**/
LIST_ENTRY *
AllocateTokenBuffer (
  VOID
  )
{
  UINTN            SpinLockSize;
  UINT32           TokenCountPerChunk;
  UINTN            Index;
  SPIN_LOCK        *SpinLock;
  UINT8            *SpinLockBuffer;
  PROCEDURE_TOKEN  *ProcTokens;

  SpinLockSize = GetSpinLockProperties ();

  TokenCountPerChunk = FixedPcdGet32 (PcdCpuSmmMpTokenCountPerChunk);
  ASSERT (TokenCountPerChunk != 0);
  if (TokenCountPerChunk == 0) {
    DEBUG ((DEBUG_ERROR, "PcdCpuSmmMpTokenCountPerChunk should not be Zero!\n"));
    if (mSmmRebootOnException) {
      DEBUG ((DEBUG_ERROR, "%a - Specifically invoke break point exception to log telemetry.\n", __func__));
      CpuBreakpoint ();
      ResetWarm ();
    }

    CpuDeadLoop ();
  }

  DEBUG ((DEBUG_INFO, "CpuSmm: SpinLock Size = 0x%x, PcdCpuSmmMpTokenCountPerChunk = 0x%x\n", SpinLockSize, TokenCountPerChunk));

  //
  // Separate the Spin_lock and Proc_token because the alignment requires by Spin_Lock.
  //
  SpinLockBuffer = AllocatePool (SpinLockSize * TokenCountPerChunk);
  if (SpinLockBuffer == NULL) {
    DEBUG ((DEBUG_ERROR, "Failed to allocate memory for spin lock buffer\n"));
    ASSERT (FALSE);
    return NULL;
  }

  ProcTokens = AllocatePool (sizeof (PROCEDURE_TOKEN) * TokenCountPerChunk);
  if (ProcTokens == NULL) {
    DEBUG ((DEBUG_ERROR, "Failed to allocate memory for procedure token buffer\n"));
    ASSERT (FALSE);
    return NULL;
  }

  for (Index = 0; Index < TokenCountPerChunk; Index++) {
    SpinLock = (SPIN_LOCK *)(SpinLockBuffer + SpinLockSize * Index);
    InitializeSpinLock (SpinLock);

    ProcTokens[Index].Signature      = PROCEDURE_TOKEN_SIGNATURE;
    ProcTokens[Index].SpinLock       = SpinLock;
    ProcTokens[Index].RunningApCount = 0;

    InsertTailList (&gSmmCpuPrivate->TokenList, &ProcTokens[Index].Link);
  }

  return &ProcTokens[0].Link;
}

/**
  Get the free token.

  If no free token, allocate new tokens then return the free one.

  @param RunningApsCount    The Running Aps count for this token.

  @retval    return the first free PROCEDURE_TOKEN.

**/
PROCEDURE_TOKEN *
GetFreeToken (
  IN UINT32  RunningApsCount
  )
{
  PROCEDURE_TOKEN  *NewToken;

  //
  // If FirstFreeToken meets the end of token list, enlarge the token list.
  // Set FirstFreeToken to the first free token.
  //
  if (gSmmCpuPrivate->FirstFreeToken == &gSmmCpuPrivate->TokenList) {
    gSmmCpuPrivate->FirstFreeToken = AllocateTokenBuffer ();
  }

  NewToken                       = PROCEDURE_TOKEN_FROM_LINK (gSmmCpuPrivate->FirstFreeToken);
  gSmmCpuPrivate->FirstFreeToken = GetNextNode (&gSmmCpuPrivate->TokenList, gSmmCpuPrivate->FirstFreeToken);

  NewToken->RunningApCount = RunningApsCount;
  AcquireSpinLock (NewToken->SpinLock);

  return NewToken;
}

/**
  Worker function to execute a caller provided function on all enabled APs.

  @param[in]     Procedure               A pointer to the function to be run on
                                         enabled APs of the system.
  @param[in]     TimeoutInMicroseconds   Indicates the time limit in microseconds for
                                         APs to return from Procedure, either for
                                         blocking or non-blocking mode.
  @param[in,out] ProcedureArguments      The parameter passed into Procedure for
                                         all APs.
  @param[in,out] Token                   This is an optional parameter that allows the caller to execute the
                                         procedure in a blocking or non-blocking fashion. If it is NULL the
                                         call is blocking, and the call will not return until the AP has
                                         completed the procedure. If the token is not NULL, the call will
                                         return immediately. The caller can check whether the procedure has
                                         completed with CheckOnProcedure or WaitForProcedure.
  @param[in,out] CPUStatus               This optional pointer may be used to get the status code returned
                                         by Procedure when it completes execution on the target AP, or with
                                         EFI_TIMEOUT if the Procedure fails to complete within the optional
                                         timeout. The implementation will update this variable with
                                         EFI_NOT_READY prior to starting Procedure on the target AP.


  @retval EFI_SUCCESS             In blocking mode, all APs have finished before
                                  the timeout expired.
  @retval EFI_SUCCESS             In non-blocking mode, function has been dispatched
                                  to all enabled APs.
  @retval others                  Failed to Startup all APs.

**/
EFI_STATUS
InternalSmmStartupAllAPs (
  IN       EFI_AP_PROCEDURE2  Procedure,
  IN       UINTN              TimeoutInMicroseconds,
  IN OUT   VOID               *ProcedureArguments OPTIONAL,
  IN OUT   MM_COMPLETION      *Token,
  IN OUT   EFI_STATUS         *CPUStatus
  )
{
  UINTN            Index;
  UINTN            CpuCount;
  PROCEDURE_TOKEN  *ProcToken;

  if ((TimeoutInMicroseconds != 0)) {
    // && ((mSmmMp.Attributes & EFI_MM_MP_TIMEOUT_SUPPORTED) == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Procedure == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CpuCount = 0;
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (IsPresentAp (Index)) {
      CpuCount++;

      // if (gSmmCpuPrivate->Operation[Index] == SmmCpuRemove) {
      //   return EFI_INVALID_PARAMETER;
      // }

      if (!AcquireSpinLockOrFail (mSmmMpSyncData->CpuData[Index].Busy)) {
        return EFI_NOT_READY;
      }

      ReleaseSpinLock (mSmmMpSyncData->CpuData[Index].Busy);
    }
  }

  if (CpuCount == 0) {
    return EFI_NOT_STARTED;
  }

  if (Token != NULL) {
    ProcToken = GetFreeToken ((UINT32)mMaxNumberOfCpus);
    *Token    = (MM_COMPLETION)ProcToken->SpinLock;
  } else {
    ProcToken = NULL;
  }

  //
  // Make sure all BUSY should be acquired.
  //
  // Because former code already check mSmmMpSyncData->CpuData[***].Busy for each AP.
  // Here code always use AcquireSpinLock instead of AcquireSpinLockOrFail for not
  // block mode.
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (IsPresentAp (Index)) {
      AcquireSpinLock (mSmmMpSyncData->CpuData[Index].Busy);
    }
  }

  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (IsPresentAp (Index)) {
      mSmmMpSyncData->CpuData[Index].Procedure = (EFI_AP_PROCEDURE2)Procedure;
      mSmmMpSyncData->CpuData[Index].Parameter = ProcedureArguments;
      if (ProcToken != NULL) {
        mSmmMpSyncData->CpuData[Index].Token = ProcToken;
      }

      if (CPUStatus != NULL) {
        mSmmMpSyncData->CpuData[Index].Status = &CPUStatus[Index];
        if (mSmmMpSyncData->CpuData[Index].Status != NULL) {
          *mSmmMpSyncData->CpuData[Index].Status = EFI_NOT_READY;
        }
      }
    } else {
      //
      // PI spec requirement:
      // For every excluded processor, the array entry must contain a value of EFI_NOT_STARTED.
      //
      if (CPUStatus != NULL) {
        CPUStatus[Index] = EFI_NOT_STARTED;
      }

      //
      // Decrease the count to mark this processor(AP or BSP) as finished.
      //
      if (ProcToken != NULL) {
        InterlockedDecrement (&ProcToken->RunningApCount);
      }
    }
  }

  ReleaseAllAPs ();

  if (Token == NULL) {
    //
    // Make sure all APs have completed their tasks.
    //
    WaitForAllAPsNotBusy (TRUE);
  }

  return EFI_SUCCESS;
}

/**
  This function sets DR6 & DR7 according to SMM save state, before running SMM C code.
  They are useful when you want to enable hardware breakpoints in SMM without entry SMM mode.

  NOTE: It might not be appreciated in runtime since it might
        conflict with OS debugging facilities. Turn them off in RELEASE.

  @param    CpuIndex              CPU Index

**/
VOID
EFIAPI
CpuSmmDebugEntry (
  IN UINTN  CpuIndex
  )
{
  SMRAM_SAVE_STATE_MAP  *CpuSaveState;

  if (FeaturePcdGet (PcdCpuSmmDebug)) {
    ASSERT (CpuIndex < mMaxNumberOfCpus);
    CpuSaveState = (SMRAM_SAVE_STATE_MAP *)gSmmCpuPrivate->CpuSaveState[CpuIndex];
    if (mSmmSaveStateRegisterLma == EFI_SMM_SAVE_STATE_REGISTER_LMA_32BIT) {
      AsmWriteDr6 (CpuSaveState->x86._DR6);
      AsmWriteDr7 (CpuSaveState->x86._DR7);
    } else {
      AsmWriteDr6 ((UINTN)CpuSaveState->x64._DR6);
      AsmWriteDr7 ((UINTN)CpuSaveState->x64._DR7);
    }
  }
}

/**
  This function restores DR6 & DR7 to SMM save state.

  NOTE: It might not be appreciated in runtime since it might
        conflict with OS debugging facilities. Turn them off in RELEASE.

  @param    CpuIndex              CPU Index

**/
VOID
EFIAPI
CpuSmmDebugExit (
  IN UINTN  CpuIndex
  )
{
  SMRAM_SAVE_STATE_MAP  *CpuSaveState;

  if (FeaturePcdGet (PcdCpuSmmDebug)) {
    ASSERT (CpuIndex < mMaxNumberOfCpus);
    CpuSaveState = (SMRAM_SAVE_STATE_MAP *)gSmmCpuPrivate->CpuSaveState[CpuIndex];
    if (mSmmSaveStateRegisterLma == EFI_SMM_SAVE_STATE_REGISTER_LMA_32BIT) {
      CpuSaveState->x86._DR7 = (UINT32)AsmReadDr7 ();
      CpuSaveState->x86._DR6 = (UINT32)AsmReadDr6 ();
    } else {
      CpuSaveState->x64._DR7 = AsmReadDr7 ();
      CpuSaveState->x64._DR6 = AsmReadDr6 ();
    }
  }
}

/**
  Allocate buffer for SpinLock and Wrapper function buffer.

**/
VOID
InitializeDataForMmMp (
  VOID
  )
{
  UINTN  Index;

  gSmmCpuPrivate->ApWrapperFunc = AllocatePool (sizeof (PROCEDURE_WRAPPER) * gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus);
  ASSERT (gSmmCpuPrivate->ApWrapperFunc != NULL);

  for (Index = 0; Index < gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus; Index++) {
    gSmmCpuPrivate->ApWrapperFunc[Index].CpuIndex = Index;
  }

  InitializeListHead (&gSmmCpuPrivate->TokenList);

  gSmmCpuPrivate->FirstFreeToken = AllocateTokenBuffer ();
}

/**
  Allocate buffer for all semaphores and spin locks.

**/
VOID
InitializeSmmCpuSemaphores (
  VOID
  )
{
  UINTN  ProcessorCount;
  UINTN  TotalSize;
  UINTN  GlobalSemaphoresSize;
  UINTN  CpuSemaphoresSize;
  UINTN  SemaphoreSize;
  UINTN  Pages;
  UINTN  *SemaphoreBlock;
  UINTN  SemaphoreAddr;

  SemaphoreSize        = GetSpinLockProperties ();
  ProcessorCount       = gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus;
  GlobalSemaphoresSize = (sizeof (SMM_CPU_SEMAPHORE_GLOBAL) / sizeof (VOID *)) * SemaphoreSize;
  CpuSemaphoresSize    = (sizeof (SMM_CPU_SEMAPHORE_CPU) / sizeof (VOID *)) * ProcessorCount * SemaphoreSize;
  TotalSize            = GlobalSemaphoresSize + CpuSemaphoresSize;
  DEBUG ((DEBUG_INFO, "One Semaphore Size    = 0x%x\n", SemaphoreSize));
  DEBUG ((DEBUG_INFO, "Total Semaphores Size = 0x%x\n", TotalSize));
  Pages          = EFI_SIZE_TO_PAGES (TotalSize);
  SemaphoreBlock = AllocatePages (Pages);
  if (SemaphoreBlock == NULL) {
    ASSERT (SemaphoreBlock != NULL);
    return;
  }

  ZeroMem (SemaphoreBlock, TotalSize);

  SemaphoreAddr                                   = (UINTN)SemaphoreBlock;
  mSmmCpuSemaphores.SemaphoreGlobal.InsideSmm     = (BOOLEAN *)SemaphoreAddr;
  SemaphoreAddr                                  += SemaphoreSize;
  mSmmCpuSemaphores.SemaphoreGlobal.AllCpusInSync = (BOOLEAN *)SemaphoreAddr;
  SemaphoreAddr                                  += SemaphoreSize;
  mSmmCpuSemaphores.SemaphoreGlobal.PFLock        = (SPIN_LOCK *)SemaphoreAddr;
  SemaphoreAddr                                  += SemaphoreSize;
  mSmmCpuSemaphores.SemaphoreGlobal.CodeAccessCheckLock
                 = (SPIN_LOCK *)SemaphoreAddr;
  SemaphoreAddr += SemaphoreSize;

  SemaphoreAddr                          = (UINTN)SemaphoreBlock + GlobalSemaphoresSize;
  mSmmCpuSemaphores.SemaphoreCpu.Busy    = (SPIN_LOCK *)SemaphoreAddr;
  SemaphoreAddr                         += ProcessorCount * SemaphoreSize;
  mSmmCpuSemaphores.SemaphoreCpu.Present = (BOOLEAN *)SemaphoreAddr;

  mPFLock = mSmmCpuSemaphores.SemaphoreGlobal.PFLock;

  mSemaphoreSize = SemaphoreSize;
}

/**
  Initialize un-cacheable data.

**/
VOID
EFIAPI
InitializeMpSyncData (
  VOID
  )
{
  RETURN_STATUS  Status;

  UINTN  CpuIndex;

  if (mSmmMpSyncData != NULL) {
    //
    // mSmmMpSyncDataSize includes one structure of SMM_DISPATCHER_MP_SYNC_DATA, one
    // CpuData array of SMM_CPU_DATA_BLOCK and one CandidateBsp array of BOOLEAN.
    //
    ZeroMem (mSmmMpSyncData, mSmmMpSyncDataSize);
    mSmmMpSyncData->CpuData      = (SMM_CPU_DATA_BLOCK *)((UINT8 *)mSmmMpSyncData + sizeof (SMM_DISPATCHER_MP_SYNC_DATA));
    mSmmMpSyncData->CandidateBsp = (BOOLEAN *)(mSmmMpSyncData->CpuData + gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus);
    if (FeaturePcdGet (PcdCpuSmmEnableBspElection)) {
      //
      // Enable BSP election by setting BspIndex to MAX_UINT32
      //
      mSmmMpSyncData->BspIndex = MAX_UINT32;
    } else {
      //
      // Use NonSMM BSP as SMM BSP
      //
      for (CpuIndex = 0; CpuIndex < gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus; CpuIndex++) {
        if (GetApicId () == gSmmCpuPrivate->ProcessorInfo[CpuIndex].ProcessorId) {
          mSmmMpSyncData->BspIndex = (UINT32)CpuIndex;
          break;
        }
      }
    }

    // mSmmMpSyncData->EffectiveSyncMode = mCpuSmmSyncMode;

    Status = SmmCpuSyncContextInit (gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus, &mSmmMpSyncData->SyncContext);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "InitializeMpSyncData: SmmCpuSyncContextInit return error %r!\n", Status));
      CpuDeadLoop ();
      return;
    }

    ASSERT (mSmmMpSyncData->SyncContext != NULL);

    mSmmMpSyncData->InsideSmm     = mSmmCpuSemaphores.SemaphoreGlobal.InsideSmm;
    mSmmMpSyncData->AllCpusInSync = mSmmCpuSemaphores.SemaphoreGlobal.AllCpusInSync;
    ASSERT (
      mSmmMpSyncData->InsideSmm != NULL &&
      mSmmMpSyncData->AllCpusInSync != NULL
      );
    *mSmmMpSyncData->InsideSmm     = FALSE;
    *mSmmMpSyncData->AllCpusInSync = FALSE;

    mSmmMpSyncData->AllApArrivedWithException = FALSE;

    for (CpuIndex = 0; CpuIndex < gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus; CpuIndex++) {
      mSmmMpSyncData->CpuData[CpuIndex].Busy =
        (SPIN_LOCK *)((UINTN)mSmmCpuSemaphores.SemaphoreCpu.Busy + mSemaphoreSize * CpuIndex);
      mSmmMpSyncData->CpuData[CpuIndex].Present =
        (BOOLEAN *)((UINTN)mSmmCpuSemaphores.SemaphoreCpu.Present + mSemaphoreSize * CpuIndex);
      *(mSmmMpSyncData->CpuData[CpuIndex].Busy)    = 0;
      *(mSmmMpSyncData->CpuData[CpuIndex].Present) = FALSE;
    }
  }
}

/**
  Initialize global data for MP synchronization.

  @param Stacks             Base address of SMI stack buffer for all processors.
  @param StackSize          Stack size for each processor in SMM.
  @param ShadowStackSize    Shadow Stack size for each processor in SMM.

**/
UINT32
InitializeMpServiceData (
  IN VOID   *Stacks,
  IN UINTN  StackSize,
  IN UINTN  ShadowStackSize
  )
{
  UINT32                          Cr3;
  UINTN                           Index;
  UINT8                           *GdtTssTables;
  UINTN                           GdtTableStepSize;
  UINT32                          MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX  VirPhyAddressSize;

  //
  // Allocate memory for all locks and semaphores
  //
  InitializeSmmCpuSemaphores ();

  //
  // Initialize mSmmMpSyncData
  //
  mSmmMpSyncDataSize = sizeof (SMM_DISPATCHER_MP_SYNC_DATA) +
                       (sizeof (SMM_CPU_DATA_BLOCK) + sizeof (BOOLEAN)) * gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus;
  mSmmMpSyncData = (SMM_DISPATCHER_MP_SYNC_DATA *)AllocatePages (EFI_SIZE_TO_PAGES (mSmmMpSyncDataSize));
  ASSERT (mSmmMpSyncData != NULL);
  // mCpuSmmSyncMode = (SMM_CPU_SYNC_MODE)PcdGet8 (PcdCpuSmmSyncMode);
  InitializeMpSyncData ();

  //
  // Initialize physical address mask
  // NOTE: Physical memory above virtual address limit is not supported !!!
  //
  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunction, NULL, NULL, NULL);
  if (MaxExtendedFunction >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  gPhyMask = LShiftU64 (1, VirPhyAddressSize.Bits.PhysicalAddressBits) - 1;
  //
  // Clear the low 12 bits
  //
  gPhyMask &= 0xfffffffffffff000ULL;

  //
  // Create page tables
  //
  Cr3 = SmmInitPageTable ();

  GdtTssTables = InitGdt (Cr3, &GdtTableStepSize);

  //
  // Check XD and BTS features on each processor on normal boot
  //
  CheckFeatureSupported ();

  //
  // Install SMI handler for each CPU
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    InstallSmiHandler (
      Index,
      (UINT32)mCpuHotPlugData.SmBase[Index],
      (VOID *)((UINTN)Stacks + (StackSize + ShadowStackSize) * Index),
      StackSize,
      (UINTN)(GdtTssTables + GdtTableStepSize * Index),
      gcSmiGdtr.Limit + 1,
      gcSmiIdtr.Base,
      gcSmiIdtr.Limit + 1,
      Cr3
      );
  }

  //
  // Record current MTRR settings
  //
  ZeroMem (&gSmiMtrrs, sizeof (gSmiMtrrs));
  MtrrGetAllMtrrs (&gSmiMtrrs);

  return Cr3;
}
