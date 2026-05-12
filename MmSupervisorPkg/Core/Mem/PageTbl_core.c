/** @file
  Core (MmSupervisorCore) page-table runtime helpers.

  Linked only into the runtime MmSupervisorCore driver:

    * SmiPagingPatch5LevelHook       - Patches the prebuilt SMI-entry assembly
                                       thunk so it knows whether 5-level paging
                                       is enabled on this processor.  Only
                                       meaningful when the supervisor is
                                       responsible for the SMI entry handler;
                                       MmSupervisorInit's stub never runs an
                                       SMI handler, so PageTbl_init.c provides
                                       a no-op.

    * SmiPFHandler                   - The supervisor's #PF (page fault) entry
                                       hook.  Invoked from Telemetry.c and
                                       referenced from Relocate/SmiException.nasm
                                       in the runtime driver.  The init driver
                                       links neither file and so does not need
                                       this routine.

  Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Register/Cpuid.h>
#include <Protocol/MpService.h>
#include <Protocol/SmmConfiguration.h>

#include <Library/BaseLib.h>
#include <Library/SmmCpuPlatformHookLib.h>
#include <Library/ResetSystemLib.h> // MSCHANGE - Allow system to reset instead of halt in test mode.

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "SmmProfile.h"
#include "SmmProfileInternal.h"
#include "Relocate/Relocate.h"
#include "Services/CpuService/CpuService.h"
#include "Services/MpService/MpService.h"
#include "Telemetry/Telemetry.h"

extern X86_ASSEMBLY_PATCH_LABEL  gPatch5LevelPagingNeeded;

/**
  Patch the prebuilt SMI-entry assembly thunk's 5-level-paging-needed slot.

  This is meaningful only when the supervisor itself owns the SMI entry handler
  (i.e. when SmmCpuFeaturesGetSmiHandlerSize() returns 0, asking us to provide
  the asm).  MmSupervisorInit ships its own SMI entry that does not need this
  patching, so its companion (PageTbl_init.c) is a no-op.

  @param[in]  M5LevelPagingNeeded  The result of Is5LevelPagingNeeded() for the
                                   current processor.
**/
VOID
SmiPagingPatch5LevelHook (
  IN BOOLEAN  M5LevelPagingNeeded
  )
{
  if (SmmCpuFeaturesGetSmiHandlerSize () == 0) {
    PatchInstructionX86 (gPatch5LevelPagingNeeded, M5LevelPagingNeeded, 1);
  }
}

/**
  ThePage Fault handler wrapper for SMM use.

  @param  InterruptType    Defines the type of interrupt or exception that
                           occurred on the processor.This parameter is processor architecture specific.
  @param  SystemContext    A pointer to the processor context when
                           the interrupt occurred on the processor.
**/
VOID
EFIAPI
SmiPFHandler (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  UINTN       PFAddress;
  UINTN       GuardPageAddress;
  UINTN       ShadowStackGuardPageAddress;
  UINTN       CpuIndex;
  EFI_STATUS  Status;

  ASSERT (InterruptType == EXCEPT_IA32_PAGE_FAULT);

  AcquireSpinLock (mPFLock);

  DumpCpuContext (InterruptType, SystemContext);

  PFAddress = AsmReadCr2 ();

  if (mCpuSmmRestrictedMemoryAccess && (PFAddress >= LShiftU64 (1, (mPhysicalAddressBits - 1)))) {
    DEBUG ((DEBUG_ERROR, "Do not support address 0x%lx by processor!\n", PFAddress));
    // MSCHANGE - Allow system to reset instead of halt in test mode.
    goto HaltOrReboot;
    // CpuDeadLoop ();
    // goto Exit;
  }

  //
  // If a page fault occurs in SMRAM range, it might be in a SMM stack/shadow stack guard page,
  // or SMM page protection violation.
  //
  if ((PFAddress >= mCpuHotPlugData.SmrrBase) &&
      (PFAddress < (mCpuHotPlugData.SmrrBase + mCpuHotPlugData.SmrrSize)))
  {
    CpuIndex                    = GetCpuIndex ();
    GuardPageAddress            = (mSmmStackArrayBase + EFI_PAGE_SIZE + CpuIndex * (mSmmStackSize + mSmmShadowStackSize));
    ShadowStackGuardPageAddress = (mSmmStackArrayBase + mSmmStackSize + EFI_PAGE_SIZE + CpuIndex * (mSmmStackSize + mSmmShadowStackSize));
    if ((FeaturePcdGet (PcdCpuSmmStackGuard)) &&
        (PFAddress >= GuardPageAddress) &&
        (PFAddress < (GuardPageAddress + EFI_PAGE_SIZE)))
    {
      DEBUG ((DEBUG_ERROR, "SMM stack overflow!\n"));
    } else if ((FeaturePcdGet (PcdCpuSmmStackGuard)) &&
               (mSmmShadowStackSize > 0) &&
               (PFAddress >= ShadowStackGuardPageAddress) &&
               (PFAddress < (ShadowStackGuardPageAddress + EFI_PAGE_SIZE)))
    {
      DEBUG ((DEBUG_ERROR, "SMM shadow stack overflow!\n"));
    } else {
      if ((SystemContext.SystemContextX64->ExceptionData & IA32_PF_EC_US) != 0) {
        DEBUG ((DEBUG_ERROR, "SMM exception at supervisor (0x%lx)\n", PFAddress));
        DEBUG_CODE (
          DumpModuleInfoByIp (*(UINTN *)(UINTN)SystemContext.SystemContextX64->Rsp);
          );
      } else if ((SystemContext.SystemContextX64->ExceptionData & IA32_PF_EC_ID) != 0) {
        DEBUG ((DEBUG_ERROR, "SMM exception at execution (0x%lx)\n", PFAddress));
        DEBUG_CODE (
          DumpModuleInfoByIp (*(UINTN *)(UINTN)SystemContext.SystemContextX64->Rsp);
          );
      } else {
        DEBUG ((DEBUG_ERROR, "SMM exception at access (0x%lx)\n", PFAddress));
        DEBUG_CODE (
          DumpModuleInfoByIp ((UINTN)SystemContext.SystemContextX64->Rip);
          );
      }
    }

    // MSCHANGE - Allow system to reset instead of halt in test mode.
    goto HaltOrReboot;
    // CpuDeadLoop ();
    // goto Exit;
  }

  //
  // If a page fault occurs in non-SMRAM range.
  //
  if ((PFAddress < mCpuHotPlugData.SmrrBase) ||
      (PFAddress >= mCpuHotPlugData.SmrrBase + mCpuHotPlugData.SmrrSize))
  {
    if ((SystemContext.SystemContextX64->ExceptionData & IA32_PF_EC_ID) != 0) {
      DEBUG ((DEBUG_ERROR, "Code executed on IP(0x%lx) out of SMM range after SMM is locked!\n", PFAddress));
      DEBUG_CODE (
        DumpModuleInfoByIp (*(UINTN *)(UINTN)SystemContext.SystemContextX64->Rsp);
        );
      // MSCHANGE - Allow system to reset instead of halt in test mode.
      goto HaltOrReboot;
      // CpuDeadLoop ();
      // goto Exit;
    }

    //
    // If NULL pointer was just accessed
    //
    // MU_CHANGE START Always enforce NULL pointer check
    // if ((PcdGet8 (PcdNullPointerDetectionPropertyMask) & BIT1) != 0 &&
    //     (PFAddress < EFI_PAGE_SIZE)) {
    if (PFAddress < EFI_PAGE_SIZE) {
      // MU_CHANGE END
      DEBUG ((DEBUG_ERROR, "!!! NULL pointer access !!!\n"));
      DEBUG_CODE (
        DumpModuleInfoByIp ((UINTN)SystemContext.SystemContextX64->Rip);
        );

      // MSCHANGE - Allow system to reset instead of halt in test mode.
      goto HaltOrReboot;
      // CpuDeadLoop ();
      // goto Exit;
    }

    if (mCpuSmmRestrictedMemoryAccess && IsSmmCommBufferForbiddenAddress (PFAddress)) {
      DEBUG ((DEBUG_ERROR, "Access SMM communication forbidden address (0x%lx)!\n", PFAddress));
      DEBUG_CODE (
        DumpModuleInfoByIp ((UINTN)SystemContext.SystemContextX64->Rip);
        );
      // MU_CHANGE - Allow system to reset instead of halt in test mode.
      goto HaltOrReboot;
      // CpuDeadLoop ();
      // goto Exit;
    }

    // This is an accessible area, but check and see if the supervisor bit caused the issue
    if ((SystemContext.SystemContextX64->ExceptionData & IA32_PF_EC_US) != 0) {
      DEBUG ((DEBUG_ERROR, "Access SMM communication supervisor address (0x%lx)!\n", PFAddress));
      DEBUG_CODE (
        DumpModuleInfoByIp ((UINTN)SystemContext.SystemContextX64->Rip);
        );
      // MU_CHANGE - Allow system to reset instead of halt in test mode.
      goto HaltOrReboot;
      // CpuDeadLoop ();
      // goto Exit;
    }
  }

  {
    SmiDefaultPFHandler ();
  }

  // MSCHANGE [BEGIN] - Allow system to reset instead of halt in test mode.
  goto Exit;

HaltOrReboot:
  // Dispatch to the registered exception handlers after demotion
  Status = PrepareNReportError (InterruptType, SystemContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a System encountered another error during error reporting... - %r\n", __func__, Status));
  }

  if (mSmmRebootOnException) {
    DEBUG ((DEBUG_ERROR, "%a - Reboot here in test mode.\n", __func__));
    ResetWarm ();
    CpuDeadLoop ();
  } else {
    CpuDeadLoop ();
  }

Exit:
  ReleaseSpinLock (mPFLock);
  return;
  // MSCHANGE [END]
}
