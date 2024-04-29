/** @file
Provides services to access SMRAM Save State Map

Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <SmmSecurePolicy.h>

#include <Library/SmmCpuFeaturesLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/SysCallLib.h>
#include <Library/IhvSmmSaveStateSupervisionLib.h>

#include "Relocate.h"
#include "Policy/Policy.h"
#include "Services/MpService/MpService.h"
#include "MmSupervisorCore.h"

typedef struct {
  UINT64    Signature;                                      // Offset 0x00
  UINT16    Reserved1;                                      // Offset 0x08
  UINT16    Reserved2;                                      // Offset 0x0A
  UINT16    Reserved3;                                      // Offset 0x0C
  UINT16    SmmCs;                                          // Offset 0x0E
  UINT16    SmmDs;                                          // Offset 0x10
  UINT16    SmmSs;                                          // Offset 0x12
  UINT16    SmmOtherSegment;                                // Offset 0x14
  UINT16    Reserved4;                                      // Offset 0x16
  UINT64    Reserved5;                                      // Offset 0x18
  UINT64    Reserved6;                                      // Offset 0x20
  UINT64    Reserved7;                                      // Offset 0x28
  UINT64    SmmGdtPtr;                                      // Offset 0x30
  UINT32    SmmGdtSize;                                     // Offset 0x38
  UINT32    Reserved8;                                      // Offset 0x3C
  UINT64    Reserved9;                                      // Offset 0x40
  UINT64    Reserved10;                                     // Offset 0x48
  UINT16    Reserved11;                                     // Offset 0x50
  UINT16    Reserved12;                                     // Offset 0x52
  UINT32    Reserved13;                                     // Offset 0x54
  UINT64    Reserved14;                                     // Offset 0x58
} PROCESSOR_SMM_DESCRIPTOR;

extern CONST PROCESSOR_SMM_DESCRIPTOR  gcPsd;

//
// EFER register LMA bit
//
#define LMA  BIT10

///
/// Structure used to build a lookup table for the IOMisc width information
///
typedef struct {
  UINT8                          Width;
  EFI_SMM_SAVE_STATE_IO_WIDTH    IoWidth;
} CPU_SMM_SAVE_STATE_IO_WIDTH;

typedef struct {
  EFI_MM_CPU_PROTOCOL           *UserMmCpuProtocol;
  EFI_MM_SAVE_STATE_REGISTER    Register;
  UINTN                         CpuIndex;
  UINTN                         Width;
  VOID                          *Buffer;
  UINTN                         CompletedSyscall;
} USER_SAVE_STATE_ACCESS_STRUCT;

USER_SAVE_STATE_ACCESS_STRUCT  UserSaveStateAccessHolder;

///
/// Variables from SMI Handler
///
X86_ASSEMBLY_PATCH_LABEL  gPatchSmbase;
X86_ASSEMBLY_PATCH_LABEL  gPatchSmiStack;
X86_ASSEMBLY_PATCH_LABEL  gPatchSmiCr3;
extern volatile UINT8     gcSmiHandlerTemplate[];
extern CONST UINT16       gcSmiHandlerSize;

//
// Variables used by SMI Handler
//
IA32_DESCRIPTOR  gSmiHandlerIdtr;

///
/// The mode of the CPU at the time an SMI occurs
///
UINT8  mSmmSaveStateRegisterLma;

/**
  Read information from the CPU save state.

  @param  This      EFI_SMM_CPU_PROTOCOL instance
  @param  Width     The number of bytes to read from the CPU save state.
  @param  Register  Specifies the CPU register to read form the save state.
  @param  CpuIndex  Specifies the zero-based index of the CPU save state.
  @param  Buffer    Upon return, this holds the CPU register value read from the save state.

  @retval EFI_SUCCESS   The register was read from Save State
  @retval EFI_NOT_FOUND The register is not defined for the Save State of Processor
  @retval EFI_INVALID_PARAMETER   This or Buffer is NULL.

**/
EFI_STATUS
EFIAPI
SmmReadSaveState (
  IN CONST EFI_SMM_CPU_PROTOCOL   *This,
  IN UINTN                        Width,
  IN EFI_SMM_SAVE_STATE_REGISTER  Register,
  IN UINTN                        CpuIndex,
  OUT VOID                        *Buffer
  )
{
  EFI_STATUS  Status;

  //
  // Retrieve pointer to the specified CPU's SMM Save State buffer
  //
  if ((CpuIndex >= gMmCoreMmst.NumberOfCpus) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The SpeculationBarrier() call here is to ensure the above check for the
  // CpuIndex has been completed before the execution of subsequent codes.
  //
  SpeculationBarrier ();

  //
  // Check for special EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID
  //
  if (Register == EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID) {
    //
    // The pseudo-register only supports the 64-bit size specified by Width.
    //
    if (Width != sizeof (UINT64)) {
      return EFI_INVALID_PARAMETER;
    }

    //
    // If the processor is in SMM at the time the SMI occurred,
    // the pseudo register value for EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID is returned in Buffer.
    // Otherwise, EFI_NOT_FOUND is returned.
    //
    if (*(mSmmMpSyncData->CpuData[CpuIndex].Present)) {
      *(UINT64 *)Buffer = gSmmCpuPrivate->ProcessorInfo[CpuIndex].ProcessorId;
      return EFI_SUCCESS;
    } else {
      return EFI_NOT_FOUND;
    }
  }

  if (!(*(mSmmMpSyncData->CpuData[CpuIndex].Present))) {
    return EFI_INVALID_PARAMETER;
  }

  Status = MmSaveStateReadRegister (CpuIndex, Register, Width, Buffer);

  return Status;
}

/**
  Hook the code executed immediately after an RSM instruction on the currently
  executing CPU.  The mode of code executed immediately after RSM must be
  detected, and the appropriate hook must be selected.  Always clear the auto
  HALT restart flag if it is set.

  @param[in] CpuIndex                 The processor index for the currently
                                      executing CPU.
  @param[in] CpuState                 Pointer to SMRAM Save State Map for the
                                      currently executing CPU.
  @param[in] NewInstructionPointer32  Instruction pointer to use if resuming to
                                      32-bit mode from 64-bit SMM.
  @param[in] NewInstructionPointer    Instruction pointer to use if resuming to
                                      same mode as SMM.

  @retval The value of the original instruction pointer before it was hooked.

**/
UINT64
EFIAPI
HookReturnFromSmm (
  IN UINTN              CpuIndex,
  SMRAM_SAVE_STATE_MAP  *CpuState,
  UINT64                NewInstructionPointer32,
  UINT64                NewInstructionPointer
  )
{
  UINT64  OriginalInstructionPointer;

  OriginalInstructionPointer = SmmCpuFeaturesHookReturnFromSmm (
                                 CpuIndex,
                                 CpuState,
                                 NewInstructionPointer32,
                                 NewInstructionPointer
                                 );
  if (OriginalInstructionPointer != 0) {
    return OriginalInstructionPointer;
  }

  if (mSmmSaveStateRegisterLma == EFI_SMM_SAVE_STATE_REGISTER_LMA_32BIT) {
    OriginalInstructionPointer = (UINT64)CpuState->x86._EIP;
    CpuState->x86._EIP         = (UINT32)NewInstructionPointer;
    //
    // Clear the auto HALT restart flag so the RSM instruction returns
    // program control to the instruction following the HLT instruction.
    //
    if ((CpuState->x86.AutoHALTRestart & BIT0) != 0) {
      CpuState->x86.AutoHALTRestart &= ~BIT0;
    }
  } else {
    OriginalInstructionPointer = CpuState->x64._RIP;
    if ((CpuState->x64.IA32_EFER & LMA) == 0) {
      CpuState->x64._RIP = (UINT32)NewInstructionPointer32;
    } else {
      CpuState->x64._RIP = (UINT32)NewInstructionPointer;
    }

    //
    // Clear the auto HALT restart flag so the RSM instruction returns
    // program control to the instruction following the HLT instruction.
    //
    if ((CpuState->x64.AutoHALTRestart & BIT0) != 0) {
      CpuState->x64.AutoHALTRestart &= ~BIT0;
    }
  }

  return OriginalInstructionPointer;
}

/**
  Get the size of the SMI Handler in bytes.

  @retval The size, in bytes, of the SMI Handler.

**/
UINTN
EFIAPI
GetSmiHandlerSize (
  VOID
  )
{
  UINTN  Size;

  Size = SmmCpuFeaturesGetSmiHandlerSize ();
  if (Size != 0) {
    return Size;
  }

  return gcSmiHandlerSize;
}

/**
  Install the SMI handler for the CPU specified by CpuIndex.  This function
  is called by the CPU that was elected as monarch during System Management
  Mode initialization.

  @param[in] CpuIndex   The index of the CPU to install the custom SMI handler.
                        The value must be between 0 and the NumberOfCpus field
                        in the System Management System Table (SMST).
  @param[in] SmBase     The SMBASE address for the CPU specified by CpuIndex.
  @param[in] SmiStack   The stack to use when an SMI is processed by the
                        the CPU specified by CpuIndex.
  @param[in] StackSize  The size, in bytes, if the stack used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtBase    The base address of the GDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtSize    The size, in bytes, of the GDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtBase    The base address of the IDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtSize    The size, in bytes, of the IDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] Cr3        The base address of the page tables to use when an SMI
                        is processed by the CPU specified by CpuIndex.
**/
VOID
EFIAPI
InstallSmiHandler (
  IN UINTN   CpuIndex,
  IN UINT32  SmBase,
  IN VOID    *SmiStack,
  IN UINTN   StackSize,
  IN UINTN   GdtBase,
  IN UINTN   GdtSize,
  IN UINTN   IdtBase,
  IN UINTN   IdtSize,
  IN UINT32  Cr3
  )
{
  PROCESSOR_SMM_DESCRIPTOR  *Psd;
  UINT32                    CpuSmiStack;

  //
  // Initialize PROCESSOR_SMM_DESCRIPTOR
  //
  Psd = (PROCESSOR_SMM_DESCRIPTOR *)(VOID *)((UINTN)SmBase + SMM_PSD_OFFSET);
  CopyMem (Psd, &gcPsd, sizeof (gcPsd));
  Psd->SmmGdtPtr  = (UINT64)GdtBase;
  Psd->SmmGdtSize = (UINT32)GdtSize;

  if (SmmCpuFeaturesGetSmiHandlerSize () != 0) {
    //
    // Install SMI handler provided by library
    //
    SmmCpuFeaturesInstallSmiHandler (
      CpuIndex,
      SmBase,
      SmiStack,
      StackSize,
      GdtBase,
      GdtSize,
      IdtBase,
      IdtSize,
      Cr3
      );
    return;
  }

  InitShadowStack (CpuIndex, (VOID *)((UINTN)SmiStack + StackSize));

  //
  // Initialize values in template before copy
  //
  CpuSmiStack = (UINT32)((UINTN)SmiStack + StackSize - sizeof (UINTN));
  PatchInstructionX86 (gPatchSmiStack, CpuSmiStack, 4);
  PatchInstructionX86 (gPatchSmiCr3, Cr3, 4);
  PatchInstructionX86 (gPatchSmbase, SmBase, 4);
  gSmiHandlerIdtr.Base  = IdtBase;
  gSmiHandlerIdtr.Limit = (UINT16)(IdtSize - 1);

  //
  // Set the value at the top of the CPU stack to the CPU Index
  //
  *(UINTN *)(UINTN)CpuSmiStack = CpuIndex;

  //
  // Copy template to CPU specific SMI handler location
  //
  CopyMem (
    (VOID *)((UINTN)SmBase + SMM_HANDLER_OFFSET),
    (VOID *)gcSmiHandlerTemplate,
    gcSmiHandlerSize
    );
}

/**
  This function is called by SyscallDispatcher to process user request on registering
  a child SMI handler from user space.

  @param SyscallIndex         The syscall index requested by the user. Supervisor uses it
                              to validate internal request state machine.
  @param UserMmCpuProtocol    User MM CPU protocol instance used for basic sanity check.
  @param Arg2                 When the SyscallIndex is SMM_SC_SVST_READ, this argument
                              contains Register to be read. When index is SMM_SC_SVST_READ_2,
                              this argument is width of buffer to be read in bytes.
  @param Arg3                 When the SyscallIndex is SMM_SC_SVST_READ, this is the CpuIndex
                              to be read from save state buffer. When SyscallIndex
                              is SMM_SC_SVST_READ_2, this represents the user buffer to hold
                              return data. Caller should validate the incoming buffer before
                              invoking this interface.

  @retval EFI_SUCCESS           The information is recorded.
  @retval EFI_UNSUPPORTED       This feature is not enabled.
  @retval EFI_INVALID_PARAMETER Unrecognized syscall index is passed in.
  @retval EFI_NOT_STARTED       User handler holder status does not meet expected state.
  @retval Others                Other errors returned from SmiHandlerProfileRegisterHandler.
**/
EFI_STATUS
ProcessUserSaveStateAccess (
  IN UINTN                SyscallIndex,
  IN EFI_MM_CPU_PROTOCOL  *UserMmCpuProtocol,
  IN UINT64               Arg2,
  IN UINT64               Arg3
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;

  switch (SyscallIndex) {
    case SMM_SC_SVST_READ:
      ZeroMem (&UserSaveStateAccessHolder, sizeof (UserSaveStateAccessHolder));
      UserSaveStateAccessHolder.UserMmCpuProtocol = UserMmCpuProtocol;
      UserSaveStateAccessHolder.Register          = (EFI_MM_SAVE_STATE_REGISTER)Arg2;
      UserSaveStateAccessHolder.CpuIndex          = Arg3;
      UserSaveStateAccessHolder.CompletedSyscall  = SyscallIndex;
      break;
    case SMM_SC_SVST_READ_2:
      if ((UserSaveStateAccessHolder.CompletedSyscall != SMM_SC_SVST_READ) ||
          (UserSaveStateAccessHolder.UserMmCpuProtocol != UserMmCpuProtocol))
      {
        Status = EFI_NOT_STARTED;
        goto Exit;
      }

      UserSaveStateAccessHolder.Width  = Arg2;
      UserSaveStateAccessHolder.Buffer = (VOID *)Arg3;
      // Evaluate the policy against request
      Status = IsIhvSmmSaveStateReadAllowed (
                 FirmwarePolicy,
                 UserSaveStateAccessHolder.CpuIndex,
                 UserSaveStateAccessHolder.Register,
                 UserSaveStateAccessHolder.Width,
                 NULL
                 );
      if (Status == EFI_NOT_FOUND) {
        Status = EFI_SUCCESS;
        goto Exit;
      } else if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a SavestateRead Blocked by Policy - %r\n", __FUNCTION__, Status));
        goto Exit;
      }

      Status = SmmReadSaveState (
                 NULL,
                 UserSaveStateAccessHolder.Width,
                 UserSaveStateAccessHolder.Register,
                 UserSaveStateAccessHolder.CpuIndex,
                 UserSaveStateAccessHolder.Buffer
                 );
      if (!EFI_ERROR (Status) || (Status == EFI_NOT_FOUND)) {
        // Only convert EFI_NOT_FOUND to unblocking return code on this attempt.
        Status = EFI_SUCCESS;
      }

      break;
    default:
      Status = EFI_INVALID_PARAMETER;
      break;
  }

Exit:
  return Status;
}
