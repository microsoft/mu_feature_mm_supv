/** @file
  PI SMM MemoryAttributes support

Copyright (c) 2008 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/ResetSystemLib.h>

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"
#include "Mem/Mem.h"

// Function pointer to jump to for handler demotion
UINTN  RegisteredRing3JumpPointer = 0;
UINTN  RegApRing3JumpPointer      = 0;
UINTN  RegErrorReportJumpPointer  = 0;

// Helper function to patch the call gate
EFI_STATUS
EFIAPI
PatchCallGatePtr (
  IN  IA32_IDT_GATE_DESCRIPTOR  *CallGatePtr,
  IN  VOID                      *ReturnPointer
  )
{
  if (CallGatePtr == NULL) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  // Only touch the intended offset here
  if (CallGatePtr->Bits.OffsetLow != ((UINTN)ReturnPointer & MAX_UINT16)) {
    CallGatePtr->Bits.OffsetLow = (UINTN)ReturnPointer & MAX_UINT16;
  }

  if (CallGatePtr->Bits.OffsetHigh != (((UINTN)ReturnPointer >> 16) & MAX_UINT16)) {
    CallGatePtr->Bits.OffsetHigh = ((UINTN)ReturnPointer >> 16) & MAX_UINT16;
  }

  if (CallGatePtr->Bits.OffsetUpper != (((UINTN)ReturnPointer >> 32) & MAX_UINT32)) {
    CallGatePtr->Bits.OffsetUpper = ((UINTN)ReturnPointer >> 32) & MAX_UINT32;
  }

  return EFI_SUCCESS;
}

// Helper function to patch the Tss descriptor
EFI_STATUS
EFIAPI
PatchTssDescriptor (
  IN  IA32_TSS_DESCRIPTOR      *TssDescPtr,
  IN  IA32_TASK_STATE_SEGMENT  *TaskSegmentPtr,
  IN  VOID                     *Cpl0StackPtr
  )
{
  if ((TssDescPtr == NULL) || (TaskSegmentPtr == NULL)) {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  // Update task segment descriptor
  if (TssDescPtr->Bits.BaseLow != ((UINTN)TaskSegmentPtr & MAX_UINT16)) {
    TssDescPtr->Bits.BaseLow = (UINTN)TaskSegmentPtr & MAX_UINT16;
  }

  if (TssDescPtr->Bits.BaseMidl != (((UINTN)TaskSegmentPtr >> 16) & MAX_UINT8)) {
    TssDescPtr->Bits.BaseMidl = ((UINTN)TaskSegmentPtr >> 16) & MAX_UINT8;
  }

  if (TssDescPtr->Bits.BaseMidh != (((UINTN)TaskSegmentPtr >> 24) & MAX_UINT8)) {
    TssDescPtr->Bits.BaseMidh = ((UINTN)TaskSegmentPtr >> 24) & MAX_UINT8;
  }

  if (TssDescPtr->Bits.BaseHigh != (((UINTN)TaskSegmentPtr >> 32) & MAX_UINT32)) {
    TssDescPtr->Bits.BaseHigh = ((UINTN)TaskSegmentPtr >> 32) & MAX_UINT32;
  }

  // Update stack pointer for ring 3 usage in TSS
  if (TaskSegmentPtr->RSP0 != ((UINT64)Cpl0StackPtr)) {
    TaskSegmentPtr->RSP0 = (UINT64)Cpl0StackPtr;
  }

  return EFI_SUCCESS;
}

// Setup ring transition for AP procedure
VOID
EFIAPI
CallgateInit (
  IN UINTN  NumberOfCpus
  )
{
  UINTN                 CpuIndex;
  EFI_PHYSICAL_ADDRESS  GdtrBaseAddr;

  for (CpuIndex = 0; CpuIndex < NumberOfCpus; CpuIndex++) {
    if (CpuIndex == mSmmMpSyncData->BspIndex) {
      // BSP call gate will change, patch at runtime
      continue;
    }

    // Patch AP handlers call gate here, they can still change during later usage
    GdtrBaseAddr = mGdtBuffer + mGdtStepSize * CpuIndex;
    PatchCallGatePtr ((IA32_IDT_GATE_DESCRIPTOR *)(UINTN)(GdtrBaseAddr + CALL_GATE_OFFSET), (VOID *)NULL);
    PatchTssDescriptor (
      (IA32_TSS_DESCRIPTOR *)(UINTN)(GdtrBaseAddr + TSS_SEL_OFFSET),
      (IA32_TASK_STATE_SEGMENT *)(UINTN)(GdtrBaseAddr + TSS_DESC_OFFSET),
      (VOID *)GetThisCpl3Stack (CpuIndex)
      );
  }
}
