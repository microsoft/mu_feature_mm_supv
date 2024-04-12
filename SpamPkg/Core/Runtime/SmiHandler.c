/** @file
  SMI handler

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "StmRuntime.h"
#include <SpamResponder.h>

STM_HANDLER  mStmHandlerSmi[VmExitReasonMax];

/**

  This function initialize STM handle for SMI.

**/
VOID
InitStmHandlerSmi (
  VOID
  )
{
  UINT32  Index;

  for (Index = 0; Index < VmExitReasonMax; Index++) {
    mStmHandlerSmi[Index] = UnknownHandlerSmi;
  }

  mStmHandlerSmi[VmExitReasonIoSmi]    = SmiEventHandler;
  mStmHandlerSmi[VmExitReasonOtherSmi] = SmiEventHandler;
  mStmHandlerSmi[VmExitReasonVmCall]   = SmiVmcallHandler;
}

/**

  This function is unknown handler for SMI.

  @param Index CPU index

**/
VOID
UnknownHandlerSmi (
  IN UINT32  Index
  )
{
  AcquireSpinLock (&mHostContextCommon.DebugLock);

  DEBUG ((EFI_D_ERROR, "!!!UnknownHandlerSmi - %d\n", (UINTN)Index));
  DumpVmcsAllField ();

  ReleaseSpinLock (&mHostContextCommon.DebugLock);

  CpuDeadLoop ();
}

/**

  This function checks Pending Mtf before resume.

  @param Index CPU index

**/
VOID
CheckPendingMtf (
  IN UINT32  Index
  )
{
  VM_EXIT_INFO_INTERRUPTION  VmEntryControlInterrupt;

  //
  // Check pending MTF
  //
  if (mGuestContextCommonSmi.GuestContextPerCpu[Index].InfoBasic.Bits.PendingMtf == 0) {
    return;
  }

  //
  // In this case, prior to resuming the interrupted guest, the STM must set the VMENTRY
  // interrupt-information field in the interrupted contexts VMCS to 80000070H (inject
  // "other event" number 0). This will cause an MTF VMEXIT to be pended and delivered
  // immediately after completion of the VMRESUME from the STM.
  //
  // If the STM doesn't do this re-injection, the guest will execute two instructions, rather
  // than one, before the MTF VMEXIT occurs. This may have undesirable effects on the
  // MLE and must be avoided.
  //
  VmEntryControlInterrupt.Uint32             = 0;
  VmEntryControlInterrupt.Bits.InterruptType = INTERRUPT_TYPE_OTHER_EVENT;
  VmEntryControlInterrupt.Bits.Valid         = 1;
  VmWrite32 (VMCS_32_CONTROL_VMENTRY_INTERRUPTION_INFO_INDEX, VmEntryControlInterrupt.Uint32);
}

/**
  The main validation routine for the SPAM Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then measure
  the content into TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and measure into TPM.

  @param[in]  SpamResponderData  The pointer to the SPAM_RESPONDER_DATA structure.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SpamResponderReport (
  IN SPAM_RESPONDER_DATA  *SpamResponderData
  );

/**

  This function is STM handler for SMI.

  @param Register X86 register context

**/
VOID
StmHandlerSmi (
  IN X86_REGISTER  *Register
  )
{
  UINT32              Index;
  UINTN               Rflags;
  VM_EXIT_INFO_BASIC  InfoBasic;
  X86_REGISTER        *Reg;
  EFI_STATUS          Status;

  Index            = ApicToIndex (ReadLocalApicId ());
  InfoBasic.Uint32 = VmRead32 (VMCS_32_RO_EXIT_REASON_INDEX);

  STM_PERF_START (Index, InfoBasic.Bits.Reason, "OsSmiHandler", "StmHandlerSmi");

  Reg           = &mGuestContextCommonSmi.GuestContextPerCpu[Index].Register;
  Register->Rsp = VmReadN (VMCS_N_GUEST_RSP_INDEX);
  CopyMem (Reg, Register, sizeof (X86_REGISTER));
 #if 0
  DEBUG ((EFI_D_INFO, "!!!StmHandlerSmi - %d\n", (UINTN)Index));
 #endif
  //
  // Dispatch
  //
  if (InfoBasic.Bits.Reason >= VmExitReasonMax) {
    DEBUG ((EFI_D_ERROR, "!!!UnknownReason!!! (0x%x)\n", InfoBasic.Bits.Reason));
    DumpVmcsAllField ();

    CpuDeadLoop ();
  }

  mGuestContextCommonSmi.GuestContextPerCpu[Index].InfoBasic.Uint32 = InfoBasic.Uint32;

  //
  // Call dispatch handler
  //
  mStmHandlerSmi[InfoBasic.Bits.Reason](Index);

  //
  // Get information about the image being loaded
  //
  SPAM_RESPONDER_DATA  *SpamData = (SPAM_RESPONDER_DATA *)(UINTN)Reg->Rsp;

  Status = SpamResponderReport (SpamData);
  ASSERT_EFI_ERROR (Status);

  VmWriteN (VMCS_N_GUEST_RSP_INDEX, Reg->Rsp); // sync RSP

  STM_PERF_END (Index, "OsSmiHandler", "StmHandlerSmi");

  CheckPendingMtf (Index);

  //
  // Resume
  //
  Rflags = AsmVmResume (&mGuestContextCommonSmi.GuestContextPerCpu[Index].Register);
  // BUGBUG: - AsmVmLaunch if AsmVmResume fail
  if (VmRead32 (VMCS_32_RO_VM_INSTRUCTION_ERROR_INDEX) == VmxFailErrorVmResumeWithNonLaunchedVmcs) {
    Rflags = AsmVmLaunch (&mGuestContextCommonSmi.GuestContextPerCpu[Index].Register);
  }

  AcquireSpinLock (&mHostContextCommon.DebugLock);

  DEBUG ((EFI_D_ERROR, "!!!ResumeGuestSmi FAIL!!! - %d\n", (UINTN)Index));
  DEBUG ((EFI_D_ERROR, "Rflags: %08x\n", Rflags));
  DEBUG ((EFI_D_ERROR, "VMCS_32_RO_VM_INSTRUCTION_ERROR: %08x\n", (UINTN)VmRead32 (VMCS_32_RO_VM_INSTRUCTION_ERROR_INDEX)));
  DumpVmcsAllField ();
  DumpRegContext (&mGuestContextCommonSmi.GuestContextPerCpu[Index].Register);

  ReleaseSpinLock (&mHostContextCommon.DebugLock);

  CpuDeadLoop ();

  return;
}
