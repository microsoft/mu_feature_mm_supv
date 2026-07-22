/** @file
  Core (MmSupervisorCore) SMM profile feature-detection.

  Linked only into the runtime MmSupervisorCore driver.  Owns:

    * mXdSupported       - Tri-state flag patched into the SMI entry asm thunk
                           (Relocate/SmiEntry.nasm) and consulted from the
                           runtime SmmCpuMemoryManagement.c.  MmSupervisorInit
                           never references this symbol, so its companion
                           (SmmProfile_init.c) does not declare it at all.

    * CheckFeatureSupported
                         - Probes CPUID for CET-SS, the XD bit, and
                           IA32_MISC_ENABLE BTS.  Patches mPatchCetSupported,
                           gPatchXdSupported, gPatchMsrIa32MiscEnableSupported
                           into the SMI entry asm thunk so the asm can branch
                           without re-reading CPUID.  MmSupervisorInit ships its
                           own asm thunk and never patches it; instead it
                           PANICs in CheckFeatureSupported (see
                           SmmProfile_init.c) if the runtime asks for features
                           that the init driver cannot honor.

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
