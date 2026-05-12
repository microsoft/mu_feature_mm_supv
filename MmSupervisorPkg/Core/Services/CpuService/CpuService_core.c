/** @file
  Core (MmSupervisorCore) CPU hot-plug list-update helper.

  Linked only into the runtime MmSupervisorCore driver.  This routine reacts to
  pending SmmCpuAdd / SmmCpuRemove / SmmCpuSwitchBsp operations queued in
  gSmmCpuPrivate->Operation[] and adjusts mNumberOfCpus / mSmmMpSyncData state
  accordingly.  MmSupervisorInit uses a slimmer SMM_CPU_PRIVATE_DATA layout
  that omits the Operation array (and the SMM_CPU_OPERATION enum), so it
  cannot link this code.

Copyright (c) 2011 - 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>

#include "MmSupervisorCore.h"
#include "CpuService.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"

/**
  Update the SMM CPU list per the pending operation.

  This function is called after return from SMI handlers.
**/
VOID
SmmCpuUpdate (
  VOID
  )
{
  UINTN  Index;

  //
  // Handle pending BSP switch operations
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->Operation[Index] == SmmCpuSwitchBsp) {
      gSmmCpuPrivate->Operation[Index]    = SmmCpuNone;
      mSmmMpSyncData->SwitchBsp           = TRUE;
      mSmmMpSyncData->CandidateBsp[Index] = TRUE;
    }
  }

  //
  // Handle pending hot-add operations
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->Operation[Index] == SmmCpuAdd) {
      gSmmCpuPrivate->Operation[Index] = SmmCpuNone;
      mNumberOfCpus++;
    }
  }

  //
  // Handle pending hot-remove operations
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->Operation[Index] == SmmCpuRemove) {
      gSmmCpuPrivate->Operation[Index] = SmmCpuNone;
      mNumberOfCpus--;
    }
  }
}
