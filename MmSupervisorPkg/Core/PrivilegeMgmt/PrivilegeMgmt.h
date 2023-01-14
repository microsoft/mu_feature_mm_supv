/** @file
  The internal header file includes the common header files, defines
  internal structure and functions used by MmCore module.

  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_PRIVILEGE_MGMT_H_
#define _MM_PRIVILEGE_MGMT_H_

#include <Library/SynchronizationLib.h>

// This needs to be in consistency with SmiException.nasm
#define PROTECTED_DS      0x20
#define LONG_CS_R0        0x38
#define LONG_DS_R0        0x40
#define LONG_CS_R3_PH     0x4B
#define LONG_DS_R3        0x53
#define LONG_CS_R3        0x5B
#define CALL_GATE_OFFSET  0x60
#define TSS_SEL_OFFSET    0x70
#define TSS_DESC_OFFSET   0x80

typedef struct {
  EFI_PHYSICAL_ADDRESS    MmSupvRsp;    // Offset should equal to MM_SUPV_RSP in SysCallEntry.nasm
  EFI_PHYSICAL_ADDRESS    SavedUserRsp; // Offset should equal to SAVED_USER_RSP in SysCallEntry.nasm
  EFI_PHYSICAL_ADDRESS    OsGsBasePtr;
  EFI_PHYSICAL_ADDRESS    OsGsSwapBasePtr;
} MM_SUPV_SYSCALL_CACHE;

extern UINTN      RegisteredRing3JumpPointer;
extern UINTN      RegApRing3JumpPointer;
extern UINTN      RegErrorReportJumpPointer;
extern SPIN_LOCK  *mCpuToken;

// Function to set up syscall MSR for just one thread/core
EFI_STATUS
EFIAPI
SetupCpl0MsrStar (
  IN  UINTN  CpuIndex
  );

// Function to set up syscall MSR for just one thread/core
EFI_STATUS
EFIAPI
SetupBspCpl0MsrStar (
  VOID
  );

// Function to restore MSR to runtime value
EFI_STATUS
EFIAPI
RestoreCpl0MsrStar (
  IN  UINTN  CpuIndex
  );

// Helper function to restore MSR to runtime value for BSP
EFI_STATUS
EFIAPI
RestoreBspCpl0MsrStar (
  VOID
  );

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
  );

UINT64
EFIAPI
SyscallCenter (
  UINTN  CallIndex,
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  CallerAddr
  );

VOID
EFIAPI
PrivilegeMgmtFixupAddress (
  VOID
  );

VOID
EFIAPI
ApHandlerReturnPointer (
  VOID
  );

// Setup ring transition for AP procedure
VOID
EFIAPI
CallgateInit (
  IN UINTN  NumberOfCpus
  );

VOID
EFIAPI
SyncMmEntryContextToCpl3 (
  VOID
  );

/**
  Invoke specified routine on specified core in CPL 3.
**/
EFI_STATUS
EFIAPI
InvokeDemotedRoutine (
  IN UINTN                 CpuIndex,
  IN EFI_PHYSICAL_ADDRESS  Cpl3Routine,
  IN UINTN                 ArgCount,
  ...
  );

/**
  Invoke MM driver in CPL 3.
**/
EFI_STATUS
EFIAPI
InvokeDemotedDriverEntryPoint (
  IN MM_IMAGE_ENTRY_POINT  *EntryPoint,
  IN EFI_HANDLE            ImageHandle,
  IN EFI_MM_SYSTEM_TABLE   *MmSystemTable
  );

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
  );

/**
  Invoke AP Procedure in CPL 3.
**/
EFI_STATUS
EFIAPI
InvokeDemotedApProcedure (
  IN UINTN              CpuIndex,
  IN EFI_AP_PROCEDURE2  Procedure,
  IN VOID               *ProcedureArgument
  );

/**
  Invoke Error Report function in CPL 3, if registered.

  Note: Never call this from the syscall dispatcher.
**/
EFI_STATUS
EFIAPI
InvokeDemotedErrorReport (
  IN UINTN  CpuIndex,
  IN VOID   *ErrorInfoBuffer
  );

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
  );

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
  );

#endif
