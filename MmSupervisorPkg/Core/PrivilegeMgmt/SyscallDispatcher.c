/** @file
Agent Module to load other modules to deploy SMM Entry Vector for X86 CPU.
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <PiMm.h>
#include <SmmSecurePolicy.h>

#include <Protocol/MmCpuIo.h>
#include <Protocol/MmCpu.h>

#include <Library/BaseLib.h>
#include <Library/CpuLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/SysCallLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmPolicyGateLib.h>

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt.h"
#include "Relocate/Relocate.h"
#include "Handler/Handler.h"
#include "Mem/Mem.h"

EFI_MM_SYSTEM_TABLE  *gMmUserMmst = NULL;

// Dictionary structure saving policy id and length
struct Dict {
  UINTN    id;
  UINTN    width;
};

GLOBAL_REMOVE_IF_UNREFERENCED UINT8        mMaxDictSize = (UINT8)FixedPcdGet8 (PcdMmSupervisorPrintPortsMaxSize);
GLOBAL_REMOVE_IF_UNREFERENCED UINT8        mMsrCurrSize = 0;
GLOBAL_REMOVE_IF_UNREFERENCED UINT8        mIoCurrSize  = 0;
GLOBAL_REMOVE_IF_UNREFERENCED BOOLEAN      mPrintInfo   = FALSE;
GLOBAL_REMOVE_IF_UNREFERENCED struct Dict  mMsrValues[FixedPcdGet8 (PcdMmSupervisorPrintPortsMaxSize)];
GLOBAL_REMOVE_IF_UNREFERENCED struct Dict  mIoValues[FixedPcdGet8 (PcdMmSupervisorPrintPortsMaxSize)];

VOID
AddToDict (
  UINTN    Id,
  UINTN    Width,
  BOOLEAN  IsMsr
  );

VOID
PrintDict (
  );

/**
  Adds an id/width entry to the one of the dictionary structures based on
  the inputted identifier.  This is an internal function.

  @param  Id          The address id of the used port.
  @param  Width       The length of the used port.
  @param  IsMsr       Boolean that is true if the function is given an MSR input
                      and is false otherwise.

**/
VOID
AddToDict (
  UINTN    Id,
  UINTN    Width,
  BOOLEAN  IsMsr
  )
{
  UINTN        Index;
  UINT8        MaxSize;
  UINT8        CurrSize;
  struct Dict  Entry;

  MaxSize = mMaxDictSize;

  if (IsMsr) {
    CurrSize = mMsrCurrSize;
  } else {
    CurrSize = mIoCurrSize;
  }

  for (Index = 0; Index < CurrSize; Index = Index + 1) {
    if (IsMsr) {
      if (mMsrValues[Index].id == Id) {
        return;
      }
    } else {
      if (mIoValues[Index].id == Id) {
        return;
      }
    }
  }

  if (CurrSize >= MaxSize) {
    DEBUG ((DEBUG_ERROR, "Dictionary is to large!\n"));
    return;
  }

  Entry.id    = Id;
  Entry.width = Width;
  mPrintInfo  = TRUE;

  if (IsMsr) {
    mMsrValues[CurrSize] = Entry;
    mMsrCurrSize         = mMsrCurrSize + 1;
  } else {
    mIoValues[CurrSize] = Entry;
    mIoCurrSize         = mIoCurrSize + 1;
  }

  return;
}

/**
  Prints out the two dictionaries containing the IO and MSR ports being used
  by the currently specified policy.  This is an internal function.
**/
VOID
PrintDict (
  VOID
  )
{
  UINTN  Index;

  DEBUG ((DEBUG_INFO, "Printing MSR devices that are being used by the current policy:\n"));
  for (Index = 0; Index < mMsrCurrSize; Index = Index + 1) {
    DEBUG ((
      DEBUG_INFO,
      "Important info: Arg1: %lx, Arg2: %lx\n",
      mMsrValues[Index].id,
      mMsrValues[Index].width
      ));
  }

  DEBUG ((DEBUG_INFO, "Printing IO devices that are being used by the current policy:\n"));
  for (Index = 0; Index < mIoCurrSize; Index = Index + 1) {
    DEBUG ((
      DEBUG_INFO,
      "Important info: Arg1: %lx, Arg2: %lx\n",
      mIoValues[Index].id,
      mIoValues[Index].width
      ));
  }

  return;
}

VOID
EFIAPI
SyncMmEntryContextToCpl3 (
  VOID
  )
{
  EFI_MM_STARTUP_THIS_AP  UserStartupThisAp;

  // Note: Need to make sure all the synchronized content is accessible from CPL3
  // Otherwise all contents needs to go through syscall
  if (gMmUserMmst != NULL) {
    UserStartupThisAp = gMmUserMmst->MmStartupThisAp;
    CopyMem (&(gMmUserMmst->MmStartupThisAp), &gMmCoreMmst.MmStartupThisAp, sizeof (EFI_MM_ENTRY_CONTEXT));
    gMmUserMmst->CpuSaveStateSize = NULL;
    gMmUserMmst->CpuSaveState     = NULL;
    // This is needed otherwise CPL3 code will call into supervisor code directly.
    gMmUserMmst->MmStartupThisAp = UserStartupThisAp;
  }
}

/*
  Helper function to check the running CPU is BSP or not.

  @retval TRUE    This running CPU is BSP.
  @retval FALSE   This running CPU is AP.
*/
BOOLEAN
EFIAPI
AmIBsp (
  VOID
  )
{
  UINTN       Index;
  EFI_STATUS  Status;

  Status = SmmWhoAmI (NULL, &Index);

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  return (Index == gMmCoreMmst.CurrentlyExecutingCpu);
}

VOID *
EFIAPI
QueryHobStartFromConfTable (
  VOID
  )
{
  UINTN  Index;
  VOID   *HobList = NULL;

  for (Index = 0; Index < gMmCoreMmst.NumberOfTableEntries; Index++) {
    if (CompareGuid (&gEfiHobListGuid, &gMmCoreMmst.MmConfigurationTable[Index].VendorGuid)) {
      HobList = gMmCoreMmst.MmConfigurationTable[Index].VendorTable;
      break;
    }
  }

  return HobList;
}

/**
  Conduct Syscall dispatch.
**/
UINT64
EFIAPI
SyscallDispatcher (
  UINTN  CallIndex,
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  CallerAddr,
  UINTN  Ring3StackPointer
  )
{
  UINT64      Ret = 0;
  EFI_HANDLE  MmHandle;
  BOOLEAN     IsUserRange = FALSE;
  EFI_STATUS  Status      = EFI_SUCCESS;

  if (FeaturePcdGet (PcdEnableSyscallLogs)) {
    while (!AcquireSpinLockOrFail (mCpuToken)) {
      CpuPause ();
    }

    DEBUG ((
      DEBUG_INFO,
      "%a Enter... CallIndex: %lx, Arg1: %lx, Arg2: %lx, Arg3: %lx, CallerAddr: %p, Ring3Stack %p\n",
      __FUNCTION__,
      CallIndex,
      Arg1,
      Arg2,
      Arg3,
      CallerAddr,
      Ring3StackPointer
      ));

    ReleaseSpinLock (mCpuToken);
  }

  // The real policy come from DRTM event is copied over to FirmwarePolicy
  switch (CallIndex) {
    case SMM_SC_RDMSR:
      Status = IsMsrReadWriteAllowed (
                 FirmwarePolicy,
                 (UINT32)Arg1,
                 SECURE_POLICY_RESOURCE_ATTR_READ_DIS
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Read MSR 0x%p blocked by policy - %r\n", __FUNCTION__, Arg1, Status));
        goto Exit;
      }

      Ret = AsmReadMsr64 ((UINT32)Arg1);
      DEBUG ((DEBUG_VERBOSE, "%a Read MSR %x got %x\n", __FUNCTION__, Arg1, Ret));
      if (FeaturePcdGet (PcdMmSupervisorPrintPortsEnable)) {
        AddToDict ((UINT32)Arg1, (UINT32)Arg2, TRUE);
      }

      break;
    case SMM_SC_WRMSR:
      Status = IsMsrReadWriteAllowed (
                 FirmwarePolicy,
                 (UINT32)Arg1,
                 SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Write MSR 0x%p blocked by policy - %r\n", __FUNCTION__, Arg1, Status));
        goto Exit;
      }

      AsmWriteMsr64 ((UINT32)Arg1, (UINT64)Arg2);
      DEBUG ((DEBUG_VERBOSE, "%a Write MSR %x with %x\n", __FUNCTION__, Arg1, Arg2));
      if (FeaturePcdGet (PcdMmSupervisorPrintPortsEnable)) {
        AddToDict ((UINT32)Arg1, (UINT32)Arg2, TRUE);
      }

      break;
    case SMM_SC_CLI:
      Status = IsInstructionExecutionAllowed (
                 FirmwarePolicy,
                 SECURE_POLICY_INSTRUCTION_CLI
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Instruction execution CLI blocked by policy - %r\n", __FUNCTION__, Status));
        goto Exit;
      }

      DisableInterrupts ();
      DEBUG ((DEBUG_VERBOSE, "%a Disable interrupts\n", __FUNCTION__));
      break;
    case SMM_SC_IO_READ:
      DEBUG ((DEBUG_VERBOSE, "%a Read IO type %d at %x got ", __FUNCTION__, Arg2, Arg1));
      if ((Arg2 != MM_IO_UINT8) && (Arg2 != MM_IO_UINT16) && (Arg2 != MM_IO_UINT32)) {
        DEBUG ((DEBUG_ERROR, "%a Read IO incompatible size - %d\n", __FUNCTION__, Arg2));
        Status = EFI_INVALID_PARAMETER;
        goto Exit;
      }

      Status = IsIoReadWriteAllowed (
                 FirmwarePolicy,
                 (UINT32)Arg1,
                 (EFI_MM_IO_WIDTH)Arg2,
                 SECURE_POLICY_RESOURCE_ATTR_READ_DIS
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Read IO port 0x%x with width type %d blocked by policy - %r\n", __FUNCTION__, Arg1, Arg2, Status));
        goto Exit;
      }

      if (Arg2 == MM_IO_UINT8) {
        Ret = (UINT64)IoRead8 ((UINTN)Arg1);
      } else if (Arg2 == MM_IO_UINT16) {
        Ret = (UINT64)IoRead16 ((UINTN)Arg1);
      } else if (Arg2 == MM_IO_UINT32) {
        Ret = (UINT64)IoRead32 ((UINTN)Arg1);
      } else {
        // Should not happen
        Status = EFI_INVALID_PARAMETER;
        goto Exit;
      }

      DEBUG ((DEBUG_VERBOSE, "%x\n", Ret));
      if (FeaturePcdGet (PcdMmSupervisorPrintPortsEnable)) {
        AddToDict ((UINT32)Arg1, (UINT32)Arg2, FALSE);
      }

      break;
    case SMM_SC_IO_WRITE:
      if ((Arg2 != MM_IO_UINT8) && (Arg2 != MM_IO_UINT16) && (Arg2 != MM_IO_UINT32)) {
        DEBUG ((DEBUG_ERROR, "%a Read IO incompatible size - %d\n", __FUNCTION__, Arg2));
        Status = EFI_INVALID_PARAMETER;
        goto Exit;
      }

      Status = IsIoReadWriteAllowed (
                 FirmwarePolicy,
                 (UINT32)Arg1,
                 (EFI_MM_IO_WIDTH)Arg2,
                 SECURE_POLICY_RESOURCE_ATTR_WRITE_DIS
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Write IO port 0x%x with width type %d blocked by policy - %r\n", __FUNCTION__, Arg1, Arg2, Status));
        goto Exit;
      }

      if (Arg2 == MM_IO_UINT8) {
        IoWrite8 ((UINTN)Arg1, (UINT8)Arg3);
      } else if (Arg2 == MM_IO_UINT16) {
        IoWrite16 ((UINTN)Arg1, (UINT16)Arg3);
      } else if (Arg2 == MM_IO_UINT32) {
        IoWrite32 ((UINTN)Arg1, (UINT32)Arg3);
      } else {
        // Should not happen
        Status = EFI_INVALID_PARAMETER;
        goto Exit;
      }

      DEBUG ((DEBUG_VERBOSE, "%a Write IO type %d at %x with %x\n", __FUNCTION__, Arg2, Arg1, Arg3));
      if (FeaturePcdGet (PcdMmSupervisorPrintPortsEnable)) {
        AddToDict ((UINT32)Arg1, (UINT32)Arg2, FALSE);
      }

      break;
    case SMM_SC_WBINVD:
      Status = IsInstructionExecutionAllowed (
                 FirmwarePolicy,
                 SECURE_POLICY_INSTRUCTION_WBINVD
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Instruction execution WBINVD blocked by policy - %r\n", __FUNCTION__, Status));
        goto Exit;
      }

      DEBUG ((DEBUG_VERBOSE, "%a Write back and invalidate cache\n", __FUNCTION__));
      AsmWbinvd ();
      break;
    case SMM_SC_HLT:
      Status = IsInstructionExecutionAllowed (
                 FirmwarePolicy,
                 SECURE_POLICY_INSTRUCTION_HLT
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Instruction execution HLT blocked by policy - %r\n", __FUNCTION__, Status));
        goto Exit;
      }

      DEBUG ((DEBUG_VERBOSE, "%a Cpu Halt\n", __FUNCTION__));
      CpuSleep ();
      break;
    case SMM_SC_SVST_READ:
      DEBUG ((DEBUG_VERBOSE, "%a Save state read\n", __FUNCTION__));
      Ret = 0;
      if ((Arg1 == 0) ||
          (Arg2 > EFI_MM_SAVE_STATE_REGISTER_PROCESSOR_ID) ||
          (Arg3 >= gMmCoreMmst.NumberOfCpus))
      {
        Status = EFI_INVALID_PARAMETER;
        goto Exit;
      }

      Status = ProcessUserSaveStateAccess (CallIndex, (EFI_MM_CPU_PROTOCOL *)Arg1, Arg2, Arg3);
      if (!EFI_ERROR (Status)) {
        Ret = EFI_SUCCESS;
      }

      break;
    case SMM_SC_SVST_READ_2:
      DEBUG ((DEBUG_VERBOSE, "%a Save state read\n", __FUNCTION__));
      Ret = 0;
      if (Arg1 == 0) {
        Status = EFI_INVALID_PARAMETER;
        goto Exit;
      }

      if (EFI_ERROR (InspectTargetRangeOwnership (Arg3, Arg2, &IsUserRange)) || !IsUserRange) {
        Status = EFI_SECURITY_VIOLATION;
        goto Exit;
      }

      Status = ProcessUserSaveStateAccess (CallIndex, (EFI_MM_CPU_PROTOCOL *)Arg1, Arg2, Arg3);
      if (!EFI_ERROR (Status)) {
        Ret = EFI_SUCCESS;
      }

      break;
    case SMM_REG_HDL_JMP:
      if ((RegisteredRing3JumpPointer != 0) ||
          (RegApRing3JumpPointer != 0))
      {
        Status = EFI_ALREADY_STARTED;
      } else if ((EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (Arg1), &IsUserRange)) || !IsUserRange) ||
                 (EFI_ERROR (InspectTargetRangeOwnership (Arg2, sizeof (Arg2), &IsUserRange)) || !IsUserRange))
      {
        Status = EFI_SECURITY_VIOLATION;
      } else {
        RegisteredRing3JumpPointer = Arg1;
        RegApRing3JumpPointer      = Arg2;
      }

      break;
    case SMM_INST_CONF_T:
      if ((!EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_GUID), &IsUserRange)) && IsUserRange) &&
          (!EFI_ERROR (InspectTargetRangeOwnership (Arg2, Arg3, &IsUserRange)) && IsUserRange))
      {
        Status = MmInstallConfigurationTable (
                   &gMmCoreMmst,
                   (CONST EFI_GUID *)Arg1,
                   (VOID *)Arg2,
                   (UINTN)Arg3
                   );
      } else {
        Status = EFI_SECURITY_VIOLATION;
      }

      break;
    case SMM_ALOC_POOL:
    case SMM_FREE_POOL:
      // These 2 syscall interfaces are deprecated. User memory allocation is managed in user space now.
      Status = EFI_UNSUPPORTED;
      break;
    case SMM_ALOC_PAGE:
      if (!AmIBsp ()) {
        // AP allocating pages will involve updating page tables, which is a rabbit hole we should not drill...
        Status = EFI_ACCESS_DENIED;
      } else if (Arg2 == EfiRuntimeServicesData) {
        Status = MmAllocatePages (
                   (EFI_ALLOCATE_TYPE)Arg1,
                   (EFI_MEMORY_TYPE)Arg2,
                   (UINTN)Arg3,
                   (EFI_PHYSICAL_ADDRESS *)&Ret
                   );
      } else if (Arg2 == EfiRuntimeServicesCode) {
        Status = EFI_UNSUPPORTED;
      } else {
        Status = EFI_INVALID_PARAMETER;
      }

      break;
    case SMM_FREE_PAGE:
      // Making sure Arg2 does not overflow when supplying into inspector
      // Then also making sure this entire range is owned by user
      if ((Arg2 <= EFI_SIZE_TO_PAGES ((UINTN)-1)) &&
          !EFI_ERROR (InspectTargetRangeOwnership (Arg1, EFI_PAGES_TO_SIZE (Arg2), &IsUserRange)) && IsUserRange)
      {
        Status = MmFreePages ((EFI_PHYSICAL_ADDRESS)Arg1, Arg2);
      } else {
        Status = EFI_SECURITY_VIOLATION;
      }

      break;
    case SMM_START_AP_PROC:
      if ((!EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (Arg1), &IsUserRange)) && IsUserRange) &&
          (Arg2 < gMmCoreMmst.NumberOfCpus) &&
          ((Arg3 == 0) || (!EFI_ERROR (InspectTargetRangeOwnership (Arg3, 1, &IsUserRange)) && IsUserRange)))
      {
        // We only make sure the procedure is demoted, then the arguments access protection will be natural
        Status = gMmCoreMmst.MmStartupThisAp (
                               (EFI_AP_PROCEDURE)Arg1,
                               Arg2,
                               (VOID *)Arg3
                               );
      } else {
        Status = EFI_SECURITY_VIOLATION;
      }

      break;
    case SMM_REG_HNDL:
      if ((!EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (Arg1), &IsUserRange)) && IsUserRange) &&
          ((Arg2 == 0) || (!EFI_ERROR (InspectTargetRangeOwnership (Arg2, sizeof (EFI_GUID), &IsUserRange)) && IsUserRange)))
      {
        Status = MmiUserHandlerRegister (
                   (EFI_MM_HANDLER_ENTRY_POINT)Arg1,
                   (CONST EFI_GUID *)Arg2,
                   (EFI_HANDLE)&Ret
                   );
      } else {
        Status = EFI_SECURITY_VIOLATION;
      }

      break;
    case SMM_UNREG_HNDL:
      Status = MmiHandlerUserUnRegister ((EFI_HANDLE)Arg1);
      break;
    case SMM_SET_CPL3_TBL:
      if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_MM_SYSTEM_TABLE), &IsUserRange)) || !IsUserRange) {
        Status = EFI_SECURITY_VIOLATION;
      } else if (gMmUserMmst != NULL) {
        Status = EFI_ALREADY_STARTED;
      } else {
        gMmUserMmst = (EFI_MM_SYSTEM_TABLE *)Arg1;
        SyncMmEntryContextToCpl3 ();
      }

      break;
    case SMM_INST_PROT:
      if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_GUID), &IsUserRange)) || !IsUserRange) {
        Status = EFI_SECURITY_VIOLATION;
      } else if (Arg1 == 0) {
        Status = EFI_INVALID_PARAMETER;
      } else {
        MmHandle = NULL;
        Status   = MmInstallProtocolInterface (
                     &MmHandle,
                     (EFI_GUID *)Arg1,
                     EFI_NATIVE_INTERFACE,
                     NULL
                     );
      }

      break;
    case SMM_QRY_HOB:
      Ret = (UINT64)QueryHobStartFromConfTable ();
      break;
    case SMM_ERR_RPT_JMP:
      if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (Arg1), &IsUserRange)) || !IsUserRange) {
        Status = EFI_SECURITY_VIOLATION;
      } else if (RegErrorReportJumpPointer != 0) {
        Status = EFI_ALREADY_STARTED;
      } else {
        RegErrorReportJumpPointer = Arg1;
      }

      break;
    case SMM_MM_HDL_REG_1:
    case SMM_MM_HDL_REG_2:
      if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_GUID), &IsUserRange)) || !IsUserRange) {
        Status = EFI_SECURITY_VIOLATION;
      } else {
        Status = ProcessUserHandlerReg (CallIndex, (EFI_GUID *)Arg1, Arg2, Arg3);
      }

      break;
    case SMM_MM_HDL_UNREG_1:
    case SMM_MM_HDL_UNREG_2:
      if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_GUID), &IsUserRange)) || !IsUserRange) {
        Status = EFI_SECURITY_VIOLATION;
      } else {
        Status = ProcessUserHandlerUnreg (CallIndex, (EFI_GUID *)Arg1, Arg2, Arg3);
      }

      break;
    case SMM_MM_UNBLOCKED:
      Ret = (UINT64)MmIsBufferOutsideMmValid ((EFI_PHYSICAL_ADDRESS)Arg1, Arg2);
      if (Ret != FALSE) {
        // Add another check to see if the buffer is in the user space.
        if (EFI_ERROR (InspectTargetRangeOwnership (Arg1, sizeof (EFI_GUID), &IsUserRange)) || !IsUserRange) {
          // If cannot determine the ownership, or the buffer is not in the user space, then return FALSE.
          // Note, we will not fail on the Status code here.
          Ret = FALSE;
        }
      }

      break;
    case SMM_MM_IS_COMM_BUFF:
      Ret = (UINT64)VerifyRequestUserCommBuffer ((VOID *)(UINTN)Arg1, (UINTN)Arg2);
      break;
    default:
      Status = EFI_INVALID_PARAMETER;
      break;
  }

Exit:
  if (mPrintInfo) {
    PrintDict ();
    mPrintInfo = FALSE;
  }

  if (EFI_ERROR (Status)) {
    // Prepare the content and try to engage exception handler here
    // TODO: Do buffer preparation
    ASSERT_EFI_ERROR (Status);
    if (mSmmRebootOnException) {
      DEBUG ((DEBUG_ERROR, "%a - Specifically invoke break point exception to log telemetry.\n", __FUNCTION__));
      CpuBreakpoint ();
      ResetWarm ();
    }

    CpuDeadLoop ();
  }

  if (FeaturePcdGet (PcdEnableSyscallLogs)) {
    DEBUG ((DEBUG_INFO, "%a Exit...\n", __FUNCTION__));
  }

  return Ret;
}
