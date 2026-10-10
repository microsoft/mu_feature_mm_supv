/** @file
  VMCS initialization

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "StmInit.h"
#include <Base.h>
#include <x64/Vmx.h>
#include <Library/DebugLib.h>

VOID
_ModuleEntryPoint (
  VOID
  );

/**

  Initialize the relocated VMCS for return to VMX root after a VMCALL.

  NOTE: We should not trust VMCS setting by MLE,so we need reinit them to make
  sure the data is valid.

  @param Index       CPU index.
  @param CallerVmcs  Physical address of the incoming, now-cleared VMCS.

**/
STATIC
VOID
InitializeNormalVmcs (
  IN UINT32  Index,
  IN UINT64  CallerVmcs
  )
{
  // VM_EXIT_CONTROLS                             VmExitCtrls;
  // VM_ENTRY_CONTROLS                            VmEntryCtrls;
  // GUEST_INTERRUPTIBILITY_STATE  GuestInterruptibilityState;
  VM_EXIT_MSR_ENTRY  *VmExitMsrEntry;

  // Data64 = AsmReadMsr64 (IA32_VMX_ENTRY_CTLS_MSR_INDEX);
  // VmEntryCtrls.Uint32 = (UINT32)Data64 & (UINT32)RShiftU64 (Data64, 32);
  // VmEntryCtrls.Bits.Ia32eGuest = (sizeof(UINT64) == sizeof(UINTN));
  // VmEntryCtrls.Bits.DeactivateDualMonitor = 0;
  // // Upon receiving control due to an SMI, the STM shall save the contents of the IA32_PERF_GLOBAL_CTRL MSR, disable any
  // // enabled bits in the IA32_PERF_GLOBAL_CTRL MSR
  // VmEntryCtrls.Bits.LoadIA32_PERF_GLOBAL_CTRL = 0;
  // VmEntryCtrls.Bits.LoadIA32_EFER = 1;

  // Data64 = AsmReadMsr64 (IA32_VMX_EXIT_CTLS_MSR_INDEX);
  // VmExitCtrls.Uint32 = (UINT32)Data64 & (UINT32)RShiftU64 (Data64, 32);
  // VmExitCtrls.Bits.Ia32eHost = (sizeof(UINT64) == sizeof(UINTN));
  // VmExitCtrls.Bits.SaveVmxPreemptionTimerValue = 1; // Save VmxPreemptionTimer
  // // Upon receiving control due to an SMI, the STM shall save the contents of the IA32_PERF_GLOBAL_CTRL MSR, disable any
  // // enabled bits in the IA32_PERF_GLOBAL_CTRL MSR
  // VmExitCtrls.Bits.LoadIA32_PERF_GLOBAL_CTRL = 0;
  // VmExitCtrls.Bits.SaveIA32_EFER = 1;

  // GuestInterruptibilityState.Uint32             = VmRead32 (VMCS_32_GUEST_INTERRUPTIBILITY_STATE_INDEX);
  // GuestInterruptibilityState.Bits.BlockingBySmi = 0;

  //
  // Control field
  //
  // VmWrite32 (VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX,                 VmEntryCtrls.Uint32);
  // VmWrite32 (VMCS_32_CONTROL_VMEXIT_CONTROLS_INDEX,                  VmExitCtrls.Uint32);

  //
  // Make sure the value is valid
  //
  VmWrite32 (VMCS_32_CONTROL_VMEXIT_MSR_STORE_COUNT_INDEX, mGuestContextCommonNormal.GuestContextPerCpu[Index].GuestMsrEntryCount);
  VmWrite32 (VMCS_32_CONTROL_VMEXIT_MSR_LOAD_COUNT_INDEX, mHostContextCommon.HostContextPerCpu[Index].HostMsrEntryCount);
  VmWrite32 (VMCS_32_CONTROL_VMENTRY_MSR_LOAD_COUNT_INDEX, mGuestContextCommonNormal.GuestContextPerCpu[Index].GuestMsrEntryCount);
  //
  // Upon receiving control due to an SMI, the STM shall save the contents of the IA32_PERF_GLOBAL_CTRL MSR, disable any
  // enabled bits in the IA32_PERF_GLOBAL_CTRL MSR.
  // Do we need handle IA32_PEBS_ENABLE MSR ???
  //
  VmExitMsrEntry             = (VM_EXIT_MSR_ENTRY *)(UINTN)mHostContextCommon.HostContextPerCpu[Index].HostMsrEntryAddress;
  VmExitMsrEntry[0].MsrIndex = IA32_PERF_GLOBAL_CTRL_MSR_INDEX;
  VmExitMsrEntry[0].MsrData  = 0;
  VmExitMsrEntry             = (VM_EXIT_MSR_ENTRY *)(UINTN)mGuestContextCommonNormal.GuestContextPerCpu[Index].GuestMsrEntryAddress;
  VmExitMsrEntry[0].MsrIndex = IA32_PERF_GLOBAL_CTRL_MSR_INDEX;
  VmExitMsrEntry[0].MsrData  = AsmReadMsr64 (IA32_PERF_GLOBAL_CTRL_MSR_INDEX);
  VmWrite64 (VMCS_64_CONTROL_VMEXIT_MSR_STORE_INDEX, mGuestContextCommonNormal.GuestContextPerCpu[Index].GuestMsrEntryAddress);
  VmWrite64 (VMCS_64_CONTROL_VMEXIT_MSR_LOAD_INDEX, mHostContextCommon.HostContextPerCpu[Index].HostMsrEntryAddress);
  VmWrite64 (VMCS_64_CONTROL_VMENTRY_MSR_LOAD_INDEX, mGuestContextCommonNormal.GuestContextPerCpu[Index].GuestMsrEntryAddress);

  //
  // Host field
  //
  VmWriteN (VMCS_N_HOST_CR0_INDEX, AsmReadCr0 ());
  VmWriteN (VMCS_N_HOST_CR3_INDEX, mHostContextCommon.PageTable);
  VmWriteN (VMCS_N_HOST_CR4_INDEX, AsmReadCr4 ());
  VmWrite16 (VMCS_16_HOST_ES_INDEX, AsmReadDs ());
  VmWrite16 (VMCS_16_HOST_CS_INDEX, AsmReadCs ());
  VmWrite16 (VMCS_16_HOST_SS_INDEX, AsmReadDs ());
  VmWrite16 (VMCS_16_HOST_DS_INDEX, AsmReadDs ());
  VmWrite16 (VMCS_16_HOST_FS_INDEX, AsmReadDs ());
  VmWrite16 (VMCS_16_HOST_GS_INDEX, AsmReadDs ());
  VmWrite16 (VMCS_16_HOST_TR_INDEX, AsmReadDs ());
  VmWriteN (VMCS_N_HOST_TR_BASE_INDEX, 0);
  VmWriteN (VMCS_N_HOST_GDTR_BASE_INDEX, mHostContextCommon.Gdtr.Base);
  VmWriteN (VMCS_N_HOST_IDTR_BASE_INDEX, mHostContextCommon.Idtr.Base);

  SAFE_DEBUG ((DEBUG_INFO, "[%a] - Current VMCS_N_HOST_RSP_INDEX is 0x%lx.\n", __func__, VmReadN (VMCS_N_HOST_RSP_INDEX)));
  SAFE_DEBUG ((DEBUG_INFO, "[%a] - mHostContextCommon.HostContextPerCpu[Index].Stack being written is 0x%lx.\n", __func__, mHostContextCommon.HostContextPerCpu[Index].Stack));
  VmWriteN (VMCS_N_HOST_RSP_INDEX, mHostContextCommon.HostContextPerCpu[Index].Stack);
  SAFE_DEBUG ((DEBUG_INFO, "[%a] - VMCS_N_HOST_RSP_INDEX value read back after write is 0x%lx.\n", __func__, VmReadN (VMCS_N_HOST_RSP_INDEX)));
  // Making sure we can still thunk back to the same place...
  VmWriteN (VMCS_N_HOST_RIP_INDEX, (UINTN)_ModuleEntryPoint);

  VmWrite64 (VMCS_64_HOST_IA32_PERF_GLOBAL_CTRL_INDEX, 0);

  //
  // Guest field
  //
  // Intel SDM Sept 2026: 34.15.4.1: If the "deactivate dual-monitor treatment" VM-entry control is 1, the executive-VMCS
  //                                 pointer field must contain the VMXON pointer.
  // Intel SDM Sept 2026: 34.15.4.7: If the executive-VMCS pointer field contains the VMXON pointer (the VM entry remains
  //                                 in VMX root operation), the current-VMCS pointer is loaded from the VMCS-link pointer
  //                                 field.
  VmWrite64 (VMCS_64_GUEST_VMCS_LINK_PTR_INDEX, CallerVmcs);

  VmWriteN (VMCS_N_GUEST_RIP_INDEX, VmReadN (VMCS_N_GUEST_RIP_INDEX) + VmRead32 (VMCS_32_RO_VMEXIT_INSTRUCTION_LENGTH_INDEX));

  VmWriteN (VMCS_N_GUEST_RFLAGS_INDEX, 0x00000002);                   // VMCALL success
  // VmWrite32 (VMCS_32_GUEST_INTERRUPTIBILITY_STATE_INDEX, GuestInterruptibilityState.Uint32);

  // VmWrite64 (VMCS_64_GUEST_IA32_PERF_GLOBAL_CTRL_INDEX,  AsmReadMsr64(IA32_PERF_GLOBAL_CTRL_MSR_INDEX));

  return;
}

/**
  Relocate the incoming VMCS into MSEG and prepare a VMCALL return.

  @param Index  CPU index.
**/
VOID
VmcsInit (
  IN UINT32  Index
  )
{
  UINT64      CurrentVmcs;
  UINTN       VmcsBase;
  UINT32      VmcsSize;
  STM_HEADER  *StmHeader;
  UINTN       Rflags;

  StmHeader = mHostContextCommon.StmHeader;
  VmcsBase  = (UINTN)StmHeader +
              STM_PAGES_TO_SIZE (STM_SIZE_TO_PAGES (StmHeader->SwStmHdr.StaticImageSize)) +
              StmHeader->SwStmHdr.AdditionalDynamicMemorySize +
              StmHeader->SwStmHdr.PerProcDynamicMemorySize * mHostContextCommon.CpuNum;
  VmcsSize = GetVmcsSize ();

  mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs = (UINT64)(VmcsBase + VmcsSize * (Index * 2));

  SAFE_DEBUG ((EFI_D_INFO, "SmiVmcsPtr(%d) - %016lx\n", (UINTN)Index, mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_RIP_INDEX (before store): %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RIP_INDEX)));

  AsmVmPtrStore (&CurrentVmcs);
  SAFE_DEBUG ((EFI_D_INFO, "CurrentVmcs(%d) - %016lx\n", (UINTN)Index, CurrentVmcs));

  Rflags = AsmVmClear (&CurrentVmcs);
  if ((Rflags & (RFLAGS_CF | RFLAGS_ZF)) != 0) {
    SAFE_DEBUG ((DEBUG_ERROR, "ERROR: AsmVmClear(%d) - %016lx : %08x\n", (UINTN)Index, CurrentVmcs, Rflags));
    CpuDeadLoop ();
  }

  // Intel SDM Sept 2026: 27.11.1: neither VMCS may be active during the ordinary memory copy.
  Rflags = AsmVmClear (&mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs);
  if ((Rflags & (RFLAGS_CF | RFLAGS_ZF)) != 0) {
    SAFE_DEBUG ((DEBUG_ERROR, "ERROR: AsmVmClear(%d) - %016lx : %08x\n", (UINTN)Index, mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs, Rflags));
    CpuDeadLoop ();
  }

  CopyMem (
    (VOID *)(UINTN)mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs,
    (VOID *)(UINTN)CurrentVmcs,
    (UINTN)VmcsSize
    );

  AsmWbinvd ();

  Rflags = AsmVmPtrLoad (&mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs);
  if ((Rflags & (RFLAGS_CF | RFLAGS_ZF)) != 0) {
    SAFE_DEBUG ((DEBUG_ERROR, "ERROR: AsmVmPtrLoad(%d) - %016lx : %08x\n", (UINTN)Index, mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs, Rflags));
    CpuDeadLoop ();
  }

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_RIP_INDEX (after load): %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RIP_INDEX)));
  InitializeNormalVmcs (Index, CurrentVmcs);
}
