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

#include "MmSupervisorRing3Broker.h"
#include "SyscallMmCpuRing3Broker.h"

///
/// MM CPU Protocol instance
///
EFI_MM_CPU_PROTOCOL  mMmCpu = {
  SysCallMmReadSaveState,
  NULL // MmWriteSaveState
};

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
