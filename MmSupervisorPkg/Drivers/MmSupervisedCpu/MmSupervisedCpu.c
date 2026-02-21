/** @file

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/** @file

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Pi/PiMmCis.h>
#include <Protocol/MmCpu.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SysCallLib.h>
#include <Library/MmServicesTableLib.h>

/**
  Read data from the CPU save state.

  This function is used to read the specified number of bytes of the specified register from the CPU
  save state of the specified CPU and place the value into the buffer. If the CPU does not support the
  specified register Register, then EFI_NOT_FOUND  should be returned. If the CPU does not
  support the specified register width Width, then EFI_INVALID_PARAMETER is returned.

  @param[in]  This               The EFI_MM_CPU_PROTOCOL instance.
  @param[in]  Width              The number of bytes to read from the CPU save state.
  @param[in]  Register           Specifies the CPU register to read form the save state.
  @param[in]  CpuIndex           Specifies the zero-based index of the CPU save state.
  @param[out] Buffer             Upon return, this holds the CPU register value read from the save state.

  @retval EFI_SUCCESS            The register was read from Save State.
  @retval EFI_NOT_FOUND          The register is not defined for the Save State of Processor.
  @retval EFI_INVALID_PARAMETER  Input parameters are not valid, for example, Processor No or register width
                                 is not correct.This or Buffer is NULL.
**/
EFI_STATUS
EFIAPI
SysCallMmReadSaveState (
  IN CONST EFI_MM_CPU_PROTOCOL   *This,
  IN UINTN                       Width,
  IN EFI_MM_SAVE_STATE_REGISTER  Register,
  IN UINTN                       CpuIndex,
  OUT VOID                       *Buffer
  )
{
  UINTN  Status;

  Status = SysCall (SMM_SC_SVST_READ, (UINTN)This, (UINTN)Register, CpuIndex);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a First syscall has failed - %r\n", __func__, Status));
    ASSERT (FALSE);
    goto Done;
  }

  Status = SysCall (SMM_SC_SVST_READ_2, (UINTN)This, Width, (UINTN)Buffer);

Done:
  return Status;
}

///
/// MM CPU Protocol instance
///
EFI_MM_CPU_PROTOCOL  mMmCpu = {
  SysCallMmReadSaveState,
  NULL // MmWriteSaveState
};

EFI_STATUS
EFIAPI
MmSupervisedCpuEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  MmCpuHandle = NULL;

  Status = gMmst->MmInstallProtocolInterface (
             &MmCpuHandle,
             &gEfiMmCpuProtocolGuid,
             EFI_NATIVE_INTERFACE,
             &mMmCpu
             );

  DEBUG ((DEBUG_ERROR, "%a MmInstallProtocolInterface for NumberOfCpus - %d\n", __func__, gMmst->NumberOfCpus));

  return Status;
}
