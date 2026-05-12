/** @file
  Core (MmSupervisorCore) implementation of CET shadow-stack initialization.

  Linked only into the runtime MmSupervisorCore driver.  Performs the actual
  CET shadow-stack and interrupt-SSP-table setup, including patching the
  NASM-defined entry points (mPatchCetPl0Ssp, mPatchCetInterruptSsp,
  mPatchCetInterruptSspTable) that live in Core's SmiEntry.nasm.  The Init
  build does not link those NASM labels and provides a PANIC stub instead
  (see SmmFuncsArch_init.c).

  Copyright (c) 2015 - 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

#include "Services/MpService/MpService.h"

extern BOOLEAN  mCetSupported;

X86_ASSEMBLY_PATCH_LABEL  mPatchCetPl0Ssp;
X86_ASSEMBLY_PATCH_LABEL  mPatchCetInterruptSsp;
X86_ASSEMBLY_PATCH_LABEL  mPatchCetInterruptSspTable;

//
// Storage for the three UINT32 mCet* globals lives in the shared
// SmmFuncsArch.c (so Init's SmramSaveState.c can read them at link time
// without requiring this _core.c).  We only reference them here.
//
extern UINT32  mCetPl0Ssp;
extern UINT32  mCetInterruptSsp;
extern UINT32  mCetInterruptSspTable;

UINTN  mSmmInterruptSspTables;

/**
  Initialize the shadow stack related data structure.

  @param CpuIndex     The index of CPU.
  @param ShadowStack  The bottom of the shadow stack for this CPU.
**/
VOID
InitShadowStack (
  IN UINTN  CpuIndex,
  IN VOID   *ShadowStack
  )
{
  UINTN   SmmShadowStackSize;
  UINT64  *InterruptSspTable;
  UINT32  InterruptSsp;

  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    SmmShadowStackSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmShadowStackSize)));
    //
    // Add 1 page as known good shadow stack
    //
    SmmShadowStackSize += EFI_PAGES_TO_SIZE (1);

    if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
      //
      // Add one guard page between Known Good Shadow Stack and SMM Shadow Stack.
      //
      SmmShadowStackSize += EFI_PAGES_TO_SIZE (1);
    }

    mCetPl0Ssp = (UINT32)((UINTN)ShadowStack + SmmShadowStackSize - sizeof (UINT64));
    PatchInstructionX86 (mPatchCetPl0Ssp, mCetPl0Ssp, 4);
    DEBUG ((DEBUG_INFO, "mCetPl0Ssp - 0x%x\n", mCetPl0Ssp));
    DEBUG ((DEBUG_INFO, "ShadowStack - 0x%x\n", ShadowStack));
    DEBUG ((DEBUG_INFO, "  SmmShadowStackSize - 0x%x\n", SmmShadowStackSize));

    if (mSmmInterruptSspTables == 0) {
      mSmmInterruptSspTables = (UINTN)AllocateZeroPool (sizeof (UINT64) * 8 * gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus);
      ASSERT (mSmmInterruptSspTables != 0);
      DEBUG ((DEBUG_INFO, "mSmmInterruptSspTables - 0x%x\n", mSmmInterruptSspTables));
    }

    //
    // The highest address on the stack (0xFE0) is a save-previous-ssp token pointing to a location that is 40 bytes away - 0xFB8.
    // The supervisor shadow stack token is just above it at address 0xFD8. This is where the interrupt SSP table points.
    // So when an interrupt of exception occurs, we can use SAVESSP/RESTORESSP/CLEARSSBUSY for the supervisor shadow stack,
    // due to the reason the RETF in SMM exception handler cannot clear the BUSY flag with same CPL.
    // (only IRET or RETF with different CPL can clear BUSY flag)
    // Please refer to UefiCpuPkg/Library/CpuExceptionHandlerLib/X64 for the full stack frame at runtime.
    // According to SDM (ver. 075 June 2021), shadow stack should be 32 bytes aligned.
    //
    InterruptSsp                   = (UINT32)(((UINTN)ShadowStack + EFI_PAGES_TO_SIZE (1) - (sizeof (UINT64) * 4)) & ~0x1f);
    *(UINT64 *)(UINTN)InterruptSsp = (InterruptSsp - sizeof (UINT64) * 4) | 0x2;
    mCetInterruptSsp               = InterruptSsp - sizeof (UINT64);

    mCetInterruptSspTable = (UINT32)(UINTN)(mSmmInterruptSspTables + sizeof (UINT64) * 8 * CpuIndex);
    InterruptSspTable     = (UINT64 *)(UINTN)mCetInterruptSspTable;
    InterruptSspTable[1]  = mCetInterruptSsp;
    PatchInstructionX86 (mPatchCetInterruptSsp, mCetInterruptSsp, 4);
    PatchInstructionX86 (mPatchCetInterruptSspTable, mCetInterruptSspTable, 4);
    DEBUG ((DEBUG_INFO, "mCetInterruptSsp - 0x%x\n", mCetInterruptSsp));
    DEBUG ((DEBUG_INFO, "mCetInterruptSspTable - 0x%x\n", mCetInterruptSspTable));
  }
}
