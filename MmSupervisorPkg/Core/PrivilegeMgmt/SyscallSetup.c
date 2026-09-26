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
#include "Services/MpService/MpService.h"

// This needs to be in consistency with SmiException.nasm
UINT64                 *mMsrStarStore   = NULL;
UINT64                 *mMsrStar64Store = NULL;
UINT64                 *mMsrEferStore   = NULL;
MM_SUPV_SYSCALL_CACHE  *mMmSupvGsStore  = NULL;
SPIN_LOCK              *mCpuToken       = NULL;

// Function to set up syscall MSR for just one thread/core
EFI_STATUS
EFIAPI
SetupCpl0MsrStar (
  IN  UINTN  CpuIndex
  )
{
  UINT32                  Eax;
  UINT32                  Edx;
  MSR_IA32_EFER_REGISTER  TempEFER;
  EFI_STATUS              Status;

  if ((mMsrStarStore == NULL) ||
      (mMsrStar64Store == NULL) ||
      (mMsrEferStore == NULL) ||
      (mMmSupvGsStore == NULL))
  {
    Status = EFI_NOT_READY;
    ASSERT (FALSE);
    goto Cleanup;
  }

  if (CpuIndex >= mNumberOfCpus) {
    Status = EFI_INVALID_PARAMETER;
    ASSERT (FALSE);
    goto Cleanup;
  }

  Eax                     = 0;
  Edx                     = 0;
  mMsrStarStore[CpuIndex] = (UINT64)AsmReadMsr64 (MSR_IA32_STAR);
  Eax                     = mMsrStarStore[CpuIndex] & 0xFFFFFFFF;
  Edx                     = ((LONG_CS_R3_PH << 16) | LONG_CS_R0) & 0xFFFFFFFF;
  AsmWriteMsr64 (MSR_IA32_STAR, (((UINT64)Edx << 32) | Eax));

  mMsrStar64Store[CpuIndex] = (UINT64)AsmReadMsr64 (MSR_IA32_LSTAR);
  AsmWriteMsr64 (MSR_IA32_LSTAR, (UINT64)SyscallCenter);

  mMsrEferStore[CpuIndex] = (UINT64)AsmReadMsr64 (MSR_IA32_EFER);
  CopyMem (&TempEFER, &mMsrEferStore[CpuIndex], sizeof (TempEFER));
  TempEFER.Bits.SCE = 1;
  AsmWriteMsr64 (MSR_IA32_EFER, *(UINT64 *)&TempEFER);

  // Prevent the original OS register from being tampered somehow
  mMmSupvGsStore[CpuIndex].OsGsBasePtr = (UINT64)AsmReadMsr64 (MSR_IA32_GS_BASE);
  AsmWriteMsr64 (MSR_IA32_GS_BASE, 0);

  // Store the original content and replace it with mMmSupvGsStore for this CPU
  mMmSupvGsStore[CpuIndex].OsGsSwapBasePtr = (UINT64)AsmReadMsr64 (MSR_IA32_KERNEL_GS_BASE);
  AsmWriteMsr64 (MSR_IA32_KERNEL_GS_BASE, (UINTN)&mMmSupvGsStore[CpuIndex]);

  Status = EFI_SUCCESS;

Cleanup:
  return Status;
}

// Function to set up syscall MSR for just one thread/core
EFI_STATUS
EFIAPI
SetupBspCpl0MsrStar (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = SetupCpl0MsrStar (mSmmMpSyncData->BspIndex);
  ASSERT_EFI_ERROR (Status);
  return Status;
}

// Function to restore MSR to runtime value
EFI_STATUS
EFIAPI
RestoreCpl0MsrStar (
  IN  UINTN  CpuIndex
  )
{
  EFI_STATUS  Status;

  if ((mMsrStarStore == NULL) ||
      (mMsrStar64Store == NULL) ||
      (mMsrEferStore == NULL) ||
      (mMmSupvGsStore == NULL))
  {
    Status = EFI_OUT_OF_RESOURCES;
    ASSERT (FALSE);
    goto Cleanup;
  }

  if (CpuIndex >= mNumberOfCpus) {
    Status = EFI_INVALID_PARAMETER;
    ASSERT (FALSE);
    goto Cleanup;
  }

  AsmWriteMsr64 (MSR_IA32_LSTAR, mMsrStar64Store[CpuIndex]);
  AsmWriteMsr64 (MSR_IA32_STAR, mMsrStarStore[CpuIndex]);
  AsmWriteMsr64 (MSR_IA32_EFER, mMsrEferStore[CpuIndex]);
  AsmWriteMsr64 (MSR_IA32_GS_BASE, mMmSupvGsStore[CpuIndex].OsGsBasePtr);
  AsmWriteMsr64 (MSR_IA32_KERNEL_GS_BASE, mMmSupvGsStore[CpuIndex].OsGsSwapBasePtr);

  Status = EFI_SUCCESS;

Cleanup:
  return Status;
}

// Helper function to restore MSR to runtime value for BSP
EFI_STATUS
EFIAPI
RestoreBspCpl0MsrStar (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = RestoreCpl0MsrStar (mSmmMpSyncData->BspIndex);
  ASSERT_EFI_ERROR (Status);
  return Status;
}

// Function to fetch CPL3 stack for BSP
EFI_PHYSICAL_ADDRESS
EFIAPI
GetBspCpl3Stack (
  VOID
  )
{
  return GetThisCpl3Stack (mSmmMpSyncData->BspIndex);
}

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
  Update the address inside mMmSupvGsStore for CpuIndex.

  @param[in]      CpuIndex            CpuIndex value of intended core, cannot be
                                      greater than mNumberOfCpus.
  @param[in]      Cpl0StackPtr        Ring0 stack pointer that will be used immediately
                                      into syscall entry routine.

  @retval EFI_SUCCESS               The stack pointer is successfully update.
  @retval EFI_INVALID_PARAMETER     The CpuIndex is out of range or the incoming stack is NULL pointer.
**/
EFI_STATUS
EFIAPI
UpdateCpl0StackPtrForGs (
  IN UINTN                 CpuIndex,
  IN EFI_PHYSICAL_ADDRESS  Cpl0StackPtr
  )
{
  if ((CpuIndex >= mNumberOfCpus) ||
      ((VOID *)Cpl0StackPtr == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  mMmSupvGsStore[CpuIndex].MmSupvRsp = Cpl0StackPtr;

  return EFI_SUCCESS;
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
