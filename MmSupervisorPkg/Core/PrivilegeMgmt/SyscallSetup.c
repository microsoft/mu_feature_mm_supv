/** @file
  PI SMM MemoryAttributes support

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Register/Msr.h>

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt.h"
#include "Relocate/Relocate.h"

// This needs to be in consistency with SmiException.nasm
UINT64                 *mMsrStarStore   = NULL;
UINT64                 *mMsrStar64Store = NULL;
UINT64                 *mMsrEferStore   = NULL;
MM_SUPV_SYSCALL_CACHE  *mMmSupvGsStore  = NULL;
SPIN_LOCK              *mCpuToken       = NULL;

/**

  Register the SMM Foundation entry point.

  @param[in]      CpuIndex             CpuIndex value of intended core, cannot be
                                       greater than mNumberOfCpus.

  @retval Address to CPL3 stack of targeted CPU if input is valid, otherwise 0

**/
EFI_PHYSICAL_ADDRESS
EFIAPI
GetThisCpl3Stack (
  IN UINTN  CpuIndex
  )
{
  if (CpuIndex >= mNumberOfCpus) {
    return 0;
  }

  return (EFI_PHYSICAL_ADDRESS)(UINTN)(mSmmCpl3StackArrayBase + mSmmStackSize * ((CpuIndex) + 1) - sizeof (UINTN));
}

/**

  Setup the pool for STAR MSR holders.

  @param[in]      NumberOfCpus         Total number of CPUs need to be supported.

  @retval EFI_OUT_OF_RESOURCES         If cannot allocate enough resource for the place holder.
  @retval EFI_SUCCESS                  MSR holders are successfully initialized.

**/
EFI_STATUS
EFIAPI
SyscallInterfaceInit (
  IN UINTN  NumberOfCpus
  )
{
  EFI_STATUS  Status;
  UINTN       SpinLockSize;

  mMsrStarStore   = AllocatePool (sizeof (UINT64) * NumberOfCpus);
  mMsrStar64Store = AllocatePool (sizeof (UINT64) * NumberOfCpus);
  mMsrEferStore   = AllocatePool (sizeof (UINT64) * NumberOfCpus);
  mMmSupvGsStore  = AllocatePool (sizeof (MM_SUPV_SYSCALL_CACHE) * NumberOfCpus);

  if ((mMsrStarStore == NULL) ||
      (mMsrStar64Store == NULL) ||
      (mMsrEferStore == NULL) ||
      (mMmSupvGsStore == NULL))
  {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  if (mCpuToken != NULL) {
    Status = EFI_ALREADY_STARTED;
    goto Exit;
  }

  SpinLockSize = GetSpinLockProperties ();
  mCpuToken    = AllocatePool (SpinLockSize);

  if (mCpuToken == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  InitializeSpinLock (mCpuToken);
  Status = EFI_SUCCESS;

Exit:
  return Status;
}
