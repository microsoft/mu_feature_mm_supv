/** @file
  Core (MmSupervisorCore) call-gate / TSS / CPL3-demotion helpers.

  These routines are linked only into the runtime MmSupervisorCore driver.
  MmSupervisorInit never demotes into ring 3 and so omits this translation
  unit; the per-CPU Setup* helpers and the InvokeDemoted* trampolines depend
  on the AsmCallGateTransfer.nasm entry (also Core-only).

  See CallGateTransfer.c for the file-scope jump-pointer globals and the
  per-CPU patchers (PatchCallGatePtr / PatchTssDescriptor) that are shared
  with MmSupervisorInit's CallgateInit().

Copyright (c) 2008 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/ResetSystemLib.h>

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"
#include "Mem/Mem.h"

//
// Defined in CallGateTransfer.c (shared).
//
extern UINTN  RegisteredRing3JumpPointer;
extern UINTN  RegApRing3JumpPointer;
extern UINTN  RegErrorReportJumpPointer;

// Function to set up call gate for just one thread/core
VOID
EFIAPI
SetupCallGate (
  IN  VOID     *ReturnPointer,
  IN  BOOLEAN  ForcedUpdate
  )
{
  IA32_DESCRIPTOR  Gdtr;

  // We should be all set after ready to lock:
  // Return point is fixed for ring 3 handlers/AP routines in assembly code
  if (mMmReadyToLockDone && !ForcedUpdate) {
    return;
  }

  AsmReadGdtr (&Gdtr);

  SmmClearGdtReadOnlyForThisProcessor ();

  PatchCallGatePtr (
    (IA32_IDT_GATE_DESCRIPTOR *)(UINTN)(Gdtr.Base + CALL_GATE_OFFSET),
    ReturnPointer
    );

  SmmSetGdtReadOnlyForThisProcessor ();

  AsmWriteGdtr (&Gdtr);

  // Note: a same level far return to apply new GDT
}

// Function to set up TSS
VOID
EFIAPI
SetupTssDescriptor (
  IN  VOID     *Cpl0StackPtr,
  IN  BOOLEAN  ForcedUpdate
  )
{
  IA32_DESCRIPTOR  Gdtr;
  UINTN            CpuIndex;
  EFI_STATUS       Status;

  // We should be all set after ready to lock:
  // Ring 3 stack is populated in TSS for each core
  if (mMmReadyToLockDone && !ForcedUpdate) {
    return;
  }

  Status = SmmWhoAmI (NULL, &CpuIndex);
  if (EFI_ERROR (Status)) {
    // Critical error for not able to get CpuIndex, cannot proceed
    goto Exit;
  }

  AsmReadGdtr (&Gdtr);

  SmmClearGdtReadOnlyForThisProcessor ();

  PatchTssDescriptor (
    (IA32_TSS_DESCRIPTOR *)(UINTN)(Gdtr.Base + TSS_SEL_OFFSET),
    (IA32_TASK_STATE_SEGMENT *)(UINTN)(Gdtr.Base + TSS_DESC_OFFSET),
    Cpl0StackPtr
    );

  // Store CPL0 stack pointer into supv data structure, this will be used upon syscall entry
  Status = UpdateCpl0StackPtrForGs (CpuIndex, (EFI_PHYSICAL_ADDRESS)Cpl0StackPtr);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  SmmSetGdtReadOnlyForThisProcessor ();

  AsmWriteGdtr (&Gdtr);

  // Note: a same level far return to apply new GDT

  Status = EFI_SUCCESS;
Exit:
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    if (mSmmRebootOnException) {
      ResetCold ();
    }
  }
}

/**
  Invoke MM driver in CPL 3.
**/
EFI_STATUS
EFIAPI
InvokeDemotedDriverEntryPoint (
  IN MM_IMAGE_ENTRY_POINT  *EntryPoint,
  IN EFI_HANDLE            ImageHandle,
  IN EFI_MM_SYSTEM_TABLE   *MmSystemTable
  )
{
  if (EntryPoint == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return InvokeDemotedRoutine (
           mSmmMpSyncData->BspIndex,
           (EFI_PHYSICAL_ADDRESS)(UINTN)EntryPoint,
           2,
           ImageHandle,
           MmSystemTable
           );
}

/**
  Invoke MM handler in CPL 3.
**/
EFI_STATUS
EFIAPI
InvokeDemotedMmHandler (
  IN MMI_HANDLER  *DispatchHandle,
  IN CONST VOID   *Context         OPTIONAL,
  IN OUT VOID     *CommBuffer      OPTIONAL,
  IN OUT UINTN    *CommBufferSize  OPTIONAL
  )
{
  if (DispatchHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((VOID *)RegisteredRing3JumpPointer == NULL) {
    return EFI_NOT_READY;
  }

  return InvokeDemotedRoutine (
           mSmmMpSyncData->BspIndex,
           (EFI_PHYSICAL_ADDRESS)RegisteredRing3JumpPointer,
           5,
           DispatchHandle,
           Context,
           CommBuffer,
           CommBufferSize,
           DispatchHandle->Handler
           );
}

/**
  Invoke AP Procedure in CPL 3.
**/
EFI_STATUS
EFIAPI
InvokeDemotedApProcedure (
  IN UINTN              CpuIndex,
  IN EFI_AP_PROCEDURE2  Procedure,
  IN VOID               *ProcedureArgument
  )
{
  if ((Procedure == NULL) || (ProcedureArgument == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((VOID *)RegApRing3JumpPointer == NULL) {
    return EFI_NOT_READY;
  }

  return InvokeDemotedRoutine (
           CpuIndex,
           (EFI_PHYSICAL_ADDRESS)RegApRing3JumpPointer,
           2,
           Procedure,
           ProcedureArgument
           );
}

/**
  Invoke Error Report function in CPL 3, if registered.

  Note: Never call this from the syscall dispatcher.
**/
EFI_STATUS
EFIAPI
InvokeDemotedErrorReport (
  IN UINTN  CpuIndex,
  IN VOID   *ErrorInfoBuffer
  )
{
  if (ErrorInfoBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((VOID *)RegErrorReportJumpPointer == NULL) {
    return EFI_NOT_READY;
  }

  return InvokeDemotedRoutine (
           CpuIndex,
           (EFI_PHYSICAL_ADDRESS)RegErrorReportJumpPointer,
           2,
           CpuIndex,
           ErrorInfoBuffer
           );
}
