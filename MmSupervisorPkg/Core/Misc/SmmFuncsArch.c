/** @file
  SMM CPU misc functions for x64 arch specific.

Copyright (c) 2015 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

#include "Mem/Mem.h"
#include "Relocate/Relocate.h"

EFI_PHYSICAL_ADDRESS  mGdtBuffer;
UINTN                 mGdtBufferSize;
UINTN                 mGdtStepSize;

extern BOOLEAN  mCetSupported;

//
// CET shadow-stack patch addresses computed by InitShadowStack and consumed by
// SmramSaveState.c.  Defined here (zero-initialized by the loader) so that both
// the runtime supervisor (which writes them in InitShadowStack) and the init
// driver (which never writes them but reads them via Init's SmramSaveState.c)
// resolve a single storage location at link time.
//
UINT32  mCetPl0Ssp;
UINT32  mCetInterruptSsp;
UINT32  mCetInterruptSspTable;

/**
  Initialize IDT IST Field.

  @param[in]  ExceptionType       Exception type.
  @param[in]  Ist                 IST value.

**/
VOID
EFIAPI
InitializeIdtIst (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  IN UINT8               Ist
  )
{
  IA32_IDT_GATE_DESCRIPTOR  *IdtGate;

  IdtGate                  = (IA32_IDT_GATE_DESCRIPTOR *)gcSmiIdtr.Base;
  IdtGate                 += ExceptionType;
  IdtGate->Bits.Reserved_0 = Ist;
}

/**
  Initialize Gdt for all processors.

  @param[in]   Cr3          CR3 value.
  @param[out]  GdtStepSize  The step size for GDT table.

  @return GdtBase for processor 0.
          GdtBase for processor X is: GdtBase + (GdtStepSize * X)
**/
VOID *
InitGdt (
  IN  UINTN  Cr3,
  OUT UINTN  *GdtStepSize
  )
{
  UINTN                    Index;
  IA32_SEGMENT_DESCRIPTOR  *GdtDescriptor;
  UINTN                    TssBase;
  UINTN                    GdtTssTableSize;
  UINT8                    *GdtTssTables;
  UINTN                    GdtTableStepSize;
  UINTN                    IstStackSize;

  //
  // For X64 SMM, we allocate separate GDT/TSS for each CPUs to avoid TSS load contention
  // on each SMI entry.
  //
  GdtTssTableSize = (gcSmiGdtr.Limit + 1 + TSS_SIZE + EFI_PAGE_MASK) & ~EFI_PAGE_MASK; // EFI_PAGE_SIZE byte aligned
  mGdtBufferSize  = GdtTssTableSize * mNumberOfCpus;
  GdtTssTables    = (UINT8 *)AllocateCodePages (EFI_SIZE_TO_PAGES (mGdtBufferSize));
  ASSERT (GdtTssTables != NULL);
  mGdtBuffer       = (UINTN)GdtTssTables;
  GdtTableStepSize = GdtTssTableSize;
  mGdtStepSize     = GdtTssTableSize;

  for (Index = 0; Index < mNumberOfCpus; Index++) {
    CopyMem (GdtTssTables + GdtTableStepSize * Index, (VOID *)(UINTN)gcSmiGdtr.Base, gcSmiGdtr.Limit + 1 + TSS_SIZE);

    //
    // Fixup TSS descriptors
    //
    TssBase                      = (UINTN)(GdtTssTables + GdtTableStepSize * Index + gcSmiGdtr.Limit + 1);
    GdtDescriptor                = (IA32_SEGMENT_DESCRIPTOR *)(TssBase) - 2;
    GdtDescriptor->Bits.BaseLow  = (UINT16)(UINTN)TssBase;
    GdtDescriptor->Bits.BaseMid  = (UINT8)((UINTN)TssBase >> 16);
    GdtDescriptor->Bits.BaseHigh = (UINT8)((UINTN)TssBase >> 24);

    if ((FeaturePcdGet (PcdCpuSmmStackGuard)) || ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported)) {
      if (PcdGet32 (PcdMmSupervisorExceptionStackSize) > mSmmStackSize + mSmmShadowStackSize) {
        // The exception stack size cannot exceed the SMM stack size.
        IstStackSize = mSmmStackSize + mSmmShadowStackSize;
      } else {
        IstStackSize = PcdGet32 (PcdMmSupervisorExceptionStackSize);
      }

      //
      // Setup top of known good stack as IST1 for each processor.
      //
      *(UINTN *)(TssBase + TSS_X64_IST1_OFFSET) = (mSmmStackArrayBase + IstStackSize + Index * (mSmmStackSize + mSmmShadowStackSize));
    }
  }

  *GdtStepSize = GdtTableStepSize;
  return GdtTssTables;
}

