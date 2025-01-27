/** @file
Enable SMM profile.

Copyright (c) 2012 - 2023, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017 - 2020, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "SmmProfileInternal.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"

//
// The flag indicates if execute-disable is supported by processor.
//
BOOLEAN  mXdSupported = TRUE;

//
// The flag indicates if execute-disable is enabled on processor.
//
BOOLEAN  mXdEnabled = FALSE;

//
// The flag indicates if BTS is supported by processor.
//
BOOLEAN  mBtsSupported = TRUE;

/**
  Get CPU Index from APIC ID.

**/
UINTN
GetCpuIndex (
  VOID
  )
{
  UINTN   Index;
  UINT32  ApicId;

  ApicId = GetApicId ();

  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId == ApicId) {
      return Index;
    }
  }

  ASSERT (FALSE);
  return 0;
}

/**
  Update page table according to protected memory ranges and the 4KB-page mapped memory ranges.

**/
VOID
InitPaging (
  VOID
  )
{
  RETURN_STATUS  Status;
  UINTN          Index;
  UINTN          PageTable;
  UINT64         Base;
  UINT64         Limit;
  UINT64         PreviousAddress;
  UINT64         MemoryAttrMask;

  PERF_FUNCTION_BEGIN ();

  GetPageTable (&PageTable, NULL);
  if (sizeof (UINTN) == sizeof (UINT32)) {
    Limit = BASE_4GB;
  } else {
    Limit = (IsRestrictedMemoryAccess ()) ? LShiftU64 (1, mPhysicalAddressBits) : BASE_4GB;
  }

  //
  // [0, 4k] may be non-present.
  //
  // MU_CHANGE: MM_SUPV: Null pointer is enabled regardless for this module
  PreviousAddress = BASE_4KB;

  DEBUG ((DEBUG_INFO, "Patch page table start ...\n"));
  MemoryAttrMask = EFI_MEMORY_XP;
  for (Index = 0; Index < mSmmCpuSmramRangeCount; Index++) {
    Base = mSmmCpuSmramRanges[Index].CpuStart;
    if (Base > PreviousAddress) {
      //
      // Mark the ranges not in mSmmCpuSmramRanges as NX.
      //
      Status = ConvertMemoryPageAttributes (PageTable, mPagingMode, PreviousAddress, Base - PreviousAddress, MemoryAttrMask, TRUE, NULL);
      ASSERT_RETURN_ERROR (Status);
    }

    PreviousAddress = mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize;
  }

  if (PreviousAddress < Limit) {
    //
    // Set the last remaining range to EFI_MEMORY_RP/EFI_MEMORY_XP.
    // This path applies to both SmmProfile enable/disable case.
    //
    Status = ConvertMemoryPageAttributes (PageTable, mPagingMode, PreviousAddress, Limit - PreviousAddress, MemoryAttrMask, TRUE, NULL);
    ASSERT_RETURN_ERROR (Status);
  }

  //
  // Flush TLB
  //
  CpuFlushTlb ();
  DEBUG ((DEBUG_INFO, "Patch page table done!\n"));
  //
  // Set execute-disable flag
  //
  mXdEnabled = TRUE;

  PERF_FUNCTION_END ();
}

/**
  Check if feature is supported by a processor.

**/
VOID
CheckFeatureSupported (
  VOID
  )
{
  UINT32                         RegEax;
  UINT32                         RegEcx;
  UINT32                         RegEdx;
  MSR_IA32_MISC_ENABLE_REGISTER  MiscEnableMsr;

  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    AsmCpuid (CPUID_SIGNATURE, &RegEax, NULL, NULL, NULL);
    if (RegEax >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS) {
      AsmCpuidEx (CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO, NULL, NULL, &RegEcx, NULL);
      if ((RegEcx & CPUID_CET_SS) == 0) {
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
  }

  if (mXdSupported) {
    AsmCpuid (CPUID_EXTENDED_FUNCTION, &RegEax, NULL, NULL, NULL);
    if (RegEax <= CPUID_EXTENDED_FUNCTION) {
      //
      // Extended CPUID functions are not supported on this processor.
      //
      mXdSupported = FALSE;
      PatchInstructionX86 (gPatchXdSupported, mXdSupported, 1);
    }

    AsmCpuid (CPUID_EXTENDED_CPU_SIG, NULL, NULL, NULL, &RegEdx);
    if ((RegEdx & CPUID1_EDX_XD_SUPPORT) == 0) {
      //
      // Execute Disable Bit feature is not supported on this processor.
      //
      mXdSupported = FALSE;
      PatchInstructionX86 (gPatchXdSupported, mXdSupported, 1);
    }

    if (StandardSignatureIsAuthenticAMD ()) {
      //
      // AMD processors do not support MSR_IA32_MISC_ENABLE
      //
      PatchInstructionX86 (gPatchMsrIa32MiscEnableSupported, FALSE, 1);
    }
  }

  if (mBtsSupported) {
    AsmCpuid (CPUID_VERSION_INFO, NULL, NULL, NULL, &RegEdx);
    if ((RegEdx & CPUID1_EDX_BTS_AVAILABLE) != 0) {
      //
      // Per IA32 manuals:
      // When CPUID.1:EDX[21] is set, the following BTS facilities are available:
      // 1. The BTS_UNAVAILABLE flag in the IA32_MISC_ENABLE MSR indicates the
      //    availability of the BTS facilities, including the ability to set the BTS and
      //    BTINT bits in the MSR_DEBUGCTLA MSR.
      // 2. The IA32_DS_AREA MSR can be programmed to point to the DS save area.
      //
      MiscEnableMsr.Uint64 = AsmReadMsr64 (MSR_IA32_MISC_ENABLE);
      if (MiscEnableMsr.Bits.BTS == 1) {
        //
        // BTS facilities is not supported if MSR_IA32_MISC_ENABLE.BTS bit is set.
        //
        mBtsSupported = FALSE;
      }
    }
  }
}
