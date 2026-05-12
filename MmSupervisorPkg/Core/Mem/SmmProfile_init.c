/** @file
  Init (MmSupervisorInit) SMM profile feature-detection.

  Linked only into MmSupervisorInit.  The init driver does not own the SMI
  entry asm thunk, so it cannot patch the CET / XD / MSR_IA32_MISC_ENABLE
  branch labels at runtime.  Instead, CheckFeatureSupported() PANICs if the
  platform actually requests CET (PcdControlFlowEnforcementPropertyMask != 0)
  and asserts that the XD feature bit is present (we depend on it for
  guard-page protection).  See SmmProfile_core.c for the runtime equivalent.

  Copyright (c) 2012 - 2023, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017 - 2020, AMD Incorporated. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PanicLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "SmmProfileInternal.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"

//
// XD support is required by the init driver: CheckFeatureSupported() PANICs
// if it is missing.  Definition lives here (and only here) so that shared
// code paths that consult mXdSupported (e.g. ConvertMemoryPageAttributes in
// SmmCpuMemoryManagement.c) compile and link unchanged for the init build.
// The runtime equivalent in SmmProfile_core.c keeps mXdSupported as a
// patchable, mutable global.
//
BOOLEAN  mXdSupported = TRUE;

/**
  Check if feature is supported by a processor.

**/
VOID
CheckFeatureSupported (
  VOID
  )
{
  UINT32                         RegEax;
  // UINT32                         RegEcx;
  UINT32                         RegEdx;
  MSR_IA32_MISC_ENABLE_REGISTER  MiscEnableMsr;

  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    PANIC ("Shadow Stack is not supported in SMM currently!!!\n");
    // AsmCpuid (CPUID_SIGNATURE, &RegEax, NULL, NULL, NULL);
    // if (RegEax >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS) {
    //   AsmCpuidEx (CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO, NULL, NULL, &RegEcx, NULL);
    //   if ((RegEcx & CPUID_CET_SS) == 0) {
    //     mCetSupported = FALSE;
    //     if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
    //       PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
    //     }
    //   }
    // } else {
    //   mCetSupported = FALSE;
    //   if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
    //     PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
    //   }
    // }
  }

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &RegEax, NULL, NULL, NULL);
  if (RegEax <= CPUID_EXTENDED_FUNCTION) {
    //
    // Extended CPUID functions are not supported on this processor.
    //
    PANIC ("Extended CPUID functions are not supported on this processor.");
  }

  AsmCpuid (CPUID_EXTENDED_CPU_SIG, NULL, NULL, NULL, &RegEdx);
  if ((RegEdx & CPUID1_EDX_XD_SUPPORT) == 0) {
    //
    // Execute Disable Bit feature is not supported on this processor.
    //
    PANIC ("Execute Disable Bit feature is not supported on this processor.");
  }

  // if (StandardSignatureIsAuthenticAMD ()) {
  //   //
  //   // AMD processors do not support MSR_IA32_MISC_ENABLE
  //   //
  //   PatchInstructionX86 (gPatchMsrIa32MiscEnableSupported, FALSE, 1);
  // }

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
