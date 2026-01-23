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
#include <Library/MmSaveStateLib.h>

// #include "Relocate.h"
#include "Services/MpService/MpService.h"
#include "MmSupervisorCore.h"

//
// EFER register LMA bit
//
#define LMA  BIT10

// TODO: This should not be here
extern UINTN mNumberOfCpus;

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
  if ((CpuIndex >= mNumberOfCpus) || (Buffer == NULL)) {
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
        DEBUG ((DEBUG_ERROR, "%a SavestateRead Blocked by Policy - %r\n", __func__, Status));
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
