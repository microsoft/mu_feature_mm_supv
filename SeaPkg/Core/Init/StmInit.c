/** @file
  STM initialization

  Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <SeaResponder.h>
#include <Library/LocalApicLib.h>
#include <SmmSecurePolicy.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/PcdLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MtrrLib.h>
#include <Library/SecurePolicyLib.h>
#include <x64/CpuArchSpecific.h>

#include "StmInit.h"
#include "Runtime/StmRuntimeUtil.h"

SEA_HOST_CONTEXT_COMMON   mHostContextCommon;
SEA_GUEST_CONTEXT_COMMON  mGuestContextCommonNormal;

volatile BOOLEAN        mIsBspInitialized;
extern volatile UINT64  mSerializationLock;

/*++
  STM runtime:

                           +------------+
                           | SMM handler|
  +-------+                +------------+
  | Guest | --                  ^ |
  +-------+  |       (2)VMResume| |(3)RSM
             |(1) SMI           | v
  +-------+  |-----------> +------------+
  |       |  |(4) VMResume |SMI-H  SMM-H|
  | MVMM  |  -<----------- |   STM      |
  |       | (0) Init       |STM-Init    |
  +-------+ -------------> +------------+

  Memory layout:
                        +--------------------+ --
                        | SMM VMCS           |  |
                        +--------------------+  |-> Per-Processor VMCS
                        | SMI VMCS           |  |
                        +--------------------+ --
                        | SMM VMCS           |  |
                        +--------------------+  |-> Per-Processor VMCS
                        | SMI VMCS           |  |
                        +--------------------+ --
                        | Stack              |  |-> Per-Processor Dynamic
                        +--------------------+ --
                        | Stack              |  |-> Per-Processor Dynamic
                  RSP-> +--------------------+ --
                        | Heap               |  |
                        +--------------------+  |-> Additional Dynamic
                        | Page Table (24K)   |  |
                  CR3-> +--------------------+ --
                  RIP-> | STM Code           |  |
                        +--------------------+  |
                        | GDT (4K)           |  |-> Static Image
                  GDT-> +--------------------+  |
                        | STM Header (4K)    |  |
                 MSEG-> +--------------------+ --
--*/

/**

  This function return 4K page aligned VMCS size.

  @return 4K page aligned VMCS size

**/
UINT32
GetVmcsSize (
  VOID
  )
{
  UINT64  Data64;
  UINT32  VmcsSize;

  Data64   = AsmReadMsr64 (IA32_VMX_BASIC_MSR_INDEX);
  VmcsSize = (UINT32)(RShiftU64 (Data64, 32) & 0xFFFF);
  VmcsSize = STM_PAGES_TO_SIZE (STM_SIZE_TO_PAGES (VmcsSize));

  return VmcsSize;
}

/**

  This function return if Senter executed.

  @retval TRUE  Senter executed
  @retval FALSE Sexit not executed

**/
BOOLEAN
IsSentryEnabled (
  VOID
  )
{
  UINT32  TxtStatus;

  TxtStatus = TxtPubRead32 (TXT_STS);
  if (((TxtStatus & TXT_STS_SENTER_DONE) != 0) &&
      ((TxtStatus & TXT_STS_SEXIT_DONE) == 0))
  {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**

  This function get CPU number in TXT heap region.

  @return CPU number in TXT heap region

**/
UINT32
GetCpuNumFromTxt (
  VOID
  )
{
  TXT_BIOS_TO_OS_DATA  *BiosToOsData;

  BiosToOsData = GetTxtBiosToOsData ();

  return BiosToOsData->NumLogProcs;
}

/**
  This function returns the CPU index based on its stack location.

  @param[in] Register       Stack value of this CPU
  @param[in] PrintDbgMsgs   Whether to print debug messages or not.
                            This allows the function to be called before debug printing is available.

  @return CPU index
**/
UINT32
GetIndexFromStack (
  IN X86_REGISTER  *Register,
  IN BOOLEAN       PrintDbgMsgs
  )
{
  STM_HEADER  *StmHeader;
  UINTN       ThisStackTop;
  UINTN       StackBottom;
  UINTN       Index;

  StmHeader = (STM_HEADER *)(UINTN)((UINT32)AsmReadMsr64 (IA32_SMM_MONITOR_CTL_MSR_INDEX) & 0xFFFFF000);

  if (PrintDbgMsgs) {
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - StmHeader at 0x%p.\n", __func__, __LINE__, StmHeader));
  }

  //
  // Stack top of this CPU
  //
  ThisStackTop = ((UINTN)Register + SIZE_4KB - 1) & ~(SIZE_4KB - 1);
  if (PrintDbgMsgs) {
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - ThisStackTop = 0x%lx.\n", __func__, __LINE__, ThisStackTop));
  }

  //
  // EspOffset pointer to bottom of 1st CPU
  //
  StackBottom = (UINTN)StmHeader + StmHeader->HwStmHdr.EspOffset;
  if (PrintDbgMsgs) {
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - StackBottom = 0x%lx.\n", __func__, __LINE__, StackBottom));
  }

  Index = (ThisStackTop - StackBottom) / StmHeader->SwStmHdr.PerProcDynamicMemorySize;
  if (PrintDbgMsgs) {
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Index = 0x%lx.\n", __func__, __LINE__, Index));
  }

  //
  // Need minus one for 0-based CPU index
  //
  return (UINT32)(Index - 1);
}

/**

  This function return minimal MSEG size required by STM.

  @param StmHeader  Stm header

  @return minimal MSEG size

**/
UINTN
GetMinMsegSize (
  IN STM_HEADER  *StmHeader
  )
{
  UINTN  MinMsegSize;

  MinMsegSize = (STM_PAGES_TO_SIZE (STM_SIZE_TO_PAGES (StmHeader->SwStmHdr.StaticImageSize)) +
                 StmHeader->SwStmHdr.AdditionalDynamicMemorySize +
                 (StmHeader->SwStmHdr.PerProcDynamicMemorySize + GetVmcsSize () * 2) * mHostContextCommon.CpuNum);

  return MinMsegSize;
}

/**

  This function initialize STM heap.

  @param StmHeader MSEG STM header

**/
VOID
InitHeap (
  IN STM_HEADER  *StmHeader
  )
{
  mHostContextCommon.HeapBottom = (UINT64)((UINTN)StmHeader +
                                           StmHeader->HwStmHdr.Cr3Offset +
                                           STM_PAGES_TO_SIZE (6)); // reserve 6 page for page table
  mHostContextCommon.HeapTop = (UINT64)((UINTN)StmHeader +
                                        STM_PAGES_TO_SIZE (STM_SIZE_TO_PAGES (StmHeader->SwStmHdr.StaticImageSize)) +
                                        StmHeader->SwStmHdr.AdditionalDynamicMemorySize);
}

/**

  This function initialize basic context for STM.

**/
VOID
InitBasicContext (
  VOID
  )
{
  mHostContextCommon.HostContextPerCpu         = AllocatePages (STM_SIZE_TO_PAGES (sizeof (SEA_HOST_CONTEXT_PER_CPU)) * mHostContextCommon.CpuNum);
  mGuestContextCommonNormal.GuestContextPerCpu = AllocatePages (STM_SIZE_TO_PAGES (sizeof (SEA_GUEST_CONTEXT_PER_CPU)) * mHostContextCommon.CpuNum);
}

EFI_STATUS
CrossCheckSmBase (
  UINTN CpuIndex,
  EFI_PHYSICAL_ADDRESS  SmBase,
  UINTN Offset,
  UINTN Size
) {
  UINTN Index;
  UINT64 Target = 0;
  UINT64 Other = 0;
  EFI_STATUS Status;

  if (Size > sizeof (UINT64)) {
    return EFI_UNSUPPORTED;
  }

  if (mHostContextCommon.HostContextPerCpu == NULL) {
    return EFI_NOT_STARTED;
  }

  if (mHostContextCommon.HostContextPerCpu[CpuIndex].Stack == 0) {
    return EFI_NOT_READY;
  }

  if (mHostContextCommon.HostContextPerCpu[CpuIndex].Smbase != SmBase) {
    return EFI_SECURITY_VIOLATION;
  }

  CopyMem (&Target, (VOID *)(UINTN)(SmBase + Offset), Size);

  Status = EFI_SUCCESS;
  for (Index = 0; Index < mHostContextCommon.CpuNum; Index ++) {
    if (mHostContextCommon.HostContextPerCpu[CpuIndex].Stack == 0) {
      // If this one has not run yet, we can ignore it
      continue;
    }

    Other = 0;
    CopyMem (&Other, (VOID *)(UINTN)(mHostContextCommon.HostContextPerCpu[Index].Smbase + Offset), Size);
    if (Other != Target) {
      SAFE_DEBUG ((DEBUG_ERROR, "%a Offset (0x%x) from SMBASE (0x%x) on CPU %d has value 0x%x and does not match that (0x%x) of this CPU (%d)\n",
        __func__,
        Offset,
        SmBase,
        Index,
        Other,
        Target,
        CpuIndex));
      Status = EFI_SECURITY_VIOLATION;
      break;
    }
  }

  return Status;
}

/**

  This function initialize BSP.

  @param Register X86 register context

**/
VOID
BspInit (
  IN X86_REGISTER  *Register
  )
{
  STM_HEADER                    *StmHeader;
  TXT_PROCESSOR_SMM_DESCRIPTOR  *TxtProcessorSmmDescriptor;
  X86_REGISTER                  *Reg;
  IA32_IDT_GATE_DESCRIPTOR      *IdtGate;
  UINT32                        SubIndex;
  UINT32                        RegEax;
  IA32_VMX_MISC_MSR             VmxMisc;

  StmHeader = (STM_HEADER *)(UINTN)((UINT32)AsmReadMsr64 (IA32_SMM_MONITOR_CTL_MSR_INDEX) & 0xFFFFF000);

  SAFE_DEBUG ((EFI_D_INFO, "!!!STM build time - %a %a!!!\n", (CHAR8 *)__DATE__, (CHAR8 *)__TIME__));
  SAFE_DEBUG ((EFI_D_INFO, "!!!STM Relocation DONE!!!\n"));
  SAFE_DEBUG ((EFI_D_INFO, "!!!Enter StmInit (BSP)!!! - %d (%x)\n", (UINTN)0, (UINTN)ReadUnaligned32 ((UINT32 *)&Register->Rax)));

  // Check Signature and size
  VmxMisc.Uint64 = AsmReadMsr64 (IA32_VMX_MISC_MSR_INDEX);
  if ((VmxMisc.Uint64 & BIT15) != 0) {
    TxtProcessorSmmDescriptor = (TXT_PROCESSOR_SMM_DESCRIPTOR *)(UINTN)(AsmReadMsr64 (IA32_SMBASE_INDEX) + SMM_TXTPSD_OFFSET);
  } else {
    TxtProcessorSmmDescriptor = (TXT_PROCESSOR_SMM_DESCRIPTOR *)(UINTN)(VmRead32 (VMCS_32_GUEST_SMBASE_INDEX) + SMM_TXTPSD_OFFSET);
  }

  SAFE_DEBUG ((EFI_D_INFO, "HeapBottom - %08x\n", mHostContextCommon.HeapBottom));
  SAFE_DEBUG ((EFI_D_INFO, "HeapTop    - %08x\n", mHostContextCommon.HeapTop));

  SAFE_DEBUG ((EFI_D_INFO, "TxtProcessorSmmDescriptor     - %08x\n", (UINTN)TxtProcessorSmmDescriptor));
  SAFE_DEBUG ((EFI_D_INFO, "  Signature                   - %016lx\n", TxtProcessorSmmDescriptor->Signature));
  SAFE_DEBUG ((EFI_D_INFO, "  Size                        - %04x\n", (UINTN)TxtProcessorSmmDescriptor->Size));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmDescriptorVerMajor       - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmDescriptorVerMajor));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmDescriptorVerMinor       - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmDescriptorVerMinor));
  SAFE_DEBUG ((EFI_D_INFO, "  LocalApicId                 - %08x\n", (UINTN)TxtProcessorSmmDescriptor->LocalApicId));
  SAFE_DEBUG ((EFI_D_INFO, "  ExecutionDisableOutsideSmrr - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmEntryState.ExecutionDisableOutsideSmrr));
  SAFE_DEBUG ((EFI_D_INFO, "  Intel64Mode                 - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmEntryState.Intel64Mode));
  SAFE_DEBUG ((EFI_D_INFO, "  Cr4Pae                      - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmEntryState.Cr4Pae));
  SAFE_DEBUG ((EFI_D_INFO, "  Cr4Pse                      - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmEntryState.Cr4Pse));
  SAFE_DEBUG ((EFI_D_INFO, "  SmramToVmcsRestoreRequired  - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmResumeState.SmramToVmcsRestoreRequired));
  SAFE_DEBUG ((EFI_D_INFO, "  ReinitializeVmcsRequired    - %02x\n", (UINTN)TxtProcessorSmmDescriptor->SmmResumeState.ReinitializeVmcsRequired));
  SAFE_DEBUG ((EFI_D_INFO, "  DomainType                  - %02x\n", (UINTN)TxtProcessorSmmDescriptor->StmSmmState.DomainType));
  SAFE_DEBUG ((EFI_D_INFO, "  XStatePolicy                - %02x\n", (UINTN)TxtProcessorSmmDescriptor->StmSmmState.XStatePolicy));
  SAFE_DEBUG ((EFI_D_INFO, "  EptEnabled                  - %02x\n", (UINTN)TxtProcessorSmmDescriptor->StmSmmState.EptEnabled));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmCs                       - %04x\n", (UINTN)TxtProcessorSmmDescriptor->SmmCs));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmDs                       - %04x\n", (UINTN)TxtProcessorSmmDescriptor->SmmDs));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmSs                       - %04x\n", (UINTN)TxtProcessorSmmDescriptor->SmmSs));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmOtherSegment             - %04x\n", (UINTN)TxtProcessorSmmDescriptor->SmmOtherSegment));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmTr                       - %04x\n", (UINTN)TxtProcessorSmmDescriptor->SmmTr));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmCr3                      - %016lx\n", TxtProcessorSmmDescriptor->SmmCr3));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmStmSetupRip              - %016lx\n", TxtProcessorSmmDescriptor->SmmStmSetupRip));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmStmTeardownRip           - %016lx\n", TxtProcessorSmmDescriptor->SmmStmTeardownRip));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmSmiHandlerRip            - %016lx\n", TxtProcessorSmmDescriptor->SmmSmiHandlerRip));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmSmiHandlerRsp            - %016lx\n", TxtProcessorSmmDescriptor->SmmSmiHandlerRsp));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmGdtPtr                   - %016lx\n", TxtProcessorSmmDescriptor->SmmGdtPtr));
  SAFE_DEBUG ((EFI_D_INFO, "  SmmGdtSize                  - %08x\n", (UINTN)TxtProcessorSmmDescriptor->SmmGdtSize));
  SAFE_DEBUG ((EFI_D_INFO, "  RequiredStmSmmRevId         - %08x\n", (UINTN)TxtProcessorSmmDescriptor->RequiredStmSmmRevId));
  SAFE_DEBUG ((EFI_D_INFO, "  StmProtectionExceptionHandler:\n"));
  SAFE_DEBUG ((EFI_D_INFO, "    SpeRip                    - %016lx\n", TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.SpeRip));
  SAFE_DEBUG ((EFI_D_INFO, "    SpeRsp                    - %016lx\n", TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.SpeRsp));
  SAFE_DEBUG ((EFI_D_INFO, "    SpeSs                     - %04x\n", (UINTN)TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.SpeSs));
  SAFE_DEBUG ((EFI_D_INFO, "    PageViolationException    - %04x\n", (UINTN)TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.PageViolationException));
  SAFE_DEBUG ((EFI_D_INFO, "    MsrViolationException     - %04x\n", (UINTN)TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.MsrViolationException));
  SAFE_DEBUG ((EFI_D_INFO, "    RegisterViolationException- %04x\n", (UINTN)TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.RegisterViolationException));
  SAFE_DEBUG ((EFI_D_INFO, "    IoViolationException      - %04x\n", (UINTN)TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.IoViolationException));
  SAFE_DEBUG ((EFI_D_INFO, "    PciViolationException     - %04x\n", (UINTN)TxtProcessorSmmDescriptor->StmProtectionExceptionHandler.PciViolationException));
  SAFE_DEBUG ((EFI_D_INFO, "  PhysicalAddressBits         - %02x\n", (UINTN)TxtProcessorSmmDescriptor->PhysicalAddressBits));

  if (TxtProcessorSmmDescriptor->Signature != TXT_PROCESSOR_SMM_DESCRIPTOR_SIGNATURE) {
    SAFE_DEBUG ((EFI_D_INFO, "TXT Descriptor Signature ERROR - %016lx!\n", TxtProcessorSmmDescriptor->Signature));
    CpuDeadLoop ();
  }

  if (TxtProcessorSmmDescriptor->Size != sizeof (TXT_PROCESSOR_SMM_DESCRIPTOR)) {
    SAFE_DEBUG ((EFI_D_INFO, "TXT Descriptor Size ERROR - %08x!\n", TxtProcessorSmmDescriptor->Size));
    CpuDeadLoop ();
  }

  SAFE_DEBUG ((EFI_D_INFO, "Register(%d) - %08x\n", (UINTN)0, Register));
  Reg           = &mGuestContextCommonNormal.GuestContextPerCpu[0].Register;
  Register->Rsp = VmReadN (VMCS_N_GUEST_RSP_INDEX);
  CopyMem (Reg, Register, sizeof (X86_REGISTER));

  mHostContextCommon.StmHeader = StmHeader;
  SAFE_DEBUG ((EFI_D_INFO, "StmHeader                     - %08x\n", (UINTN)mHostContextCommon.StmHeader));
  SAFE_DEBUG ((EFI_D_INFO, "Hardware field:\n"));
  SAFE_DEBUG ((EFI_D_INFO, "  MsegHeaderRevision          - %08x\n", (UINTN)StmHeader->HwStmHdr.MsegHeaderRevision));
  SAFE_DEBUG ((EFI_D_INFO, "  MonitorFeatures             - %08x\n", (UINTN)StmHeader->HwStmHdr.MonitorFeatures));
  SAFE_DEBUG ((EFI_D_INFO, "  GdtrLimit                   - %08x\n", (UINTN)StmHeader->HwStmHdr.GdtrLimit));
  SAFE_DEBUG ((EFI_D_INFO, "  GdtrBaseOffset              - %08x\n", (UINTN)StmHeader->HwStmHdr.GdtrBaseOffset));
  SAFE_DEBUG ((EFI_D_INFO, "  CsSelector                  - %08x\n", (UINTN)StmHeader->HwStmHdr.CsSelector));
  SAFE_DEBUG ((EFI_D_INFO, "  EipOffset                   - %08x\n", (UINTN)StmHeader->HwStmHdr.EipOffset));
  SAFE_DEBUG ((EFI_D_INFO, "  EspOffset                   - %08x\n", (UINTN)StmHeader->HwStmHdr.EspOffset));
  SAFE_DEBUG ((EFI_D_INFO, "  Cr3Offset                   - %08x\n", (UINTN)StmHeader->HwStmHdr.Cr3Offset));
  SAFE_DEBUG ((EFI_D_INFO, "Software field:\n"));
  SAFE_DEBUG ((EFI_D_INFO, "  StmSpecVerMajor             - %02x\n", (UINTN)StmHeader->SwStmHdr.StmSpecVerMajor));
  SAFE_DEBUG ((EFI_D_INFO, "  StmSpecVerMinor             - %02x\n", (UINTN)StmHeader->SwStmHdr.StmSpecVerMinor));
  SAFE_DEBUG ((EFI_D_INFO, "  StaticImageSize             - %08x\n", (UINTN)StmHeader->SwStmHdr.StaticImageSize));
  SAFE_DEBUG ((EFI_D_INFO, "  PerProcDynamicMemorySize    - %08x\n", (UINTN)StmHeader->SwStmHdr.PerProcDynamicMemorySize));
  SAFE_DEBUG ((EFI_D_INFO, "  AdditionalDynamicMemorySize - %08x\n", (UINTN)StmHeader->SwStmHdr.AdditionalDynamicMemorySize));
  SAFE_DEBUG ((EFI_D_INFO, "  Intel64ModeSupported        - %08x\n", (UINTN)StmHeader->SwStmHdr.StmFeatures.Intel64ModeSupported));
  SAFE_DEBUG ((EFI_D_INFO, "  EptSupported                - %08x\n", (UINTN)StmHeader->SwStmHdr.StmFeatures.EptSupported));
  SAFE_DEBUG ((EFI_D_INFO, "  NumberOfRevIDs              - %08x\n", (UINTN)StmHeader->SwStmHdr.NumberOfRevIDs));
  for (SubIndex = 0; SubIndex < StmHeader->SwStmHdr.NumberOfRevIDs; SubIndex++) {
    SAFE_DEBUG ((EFI_D_INFO, "  StmSmmRevID(%02d)             - %08x\n", (UINTN)SubIndex, (UINTN)StmHeader->SwStmHdr.StmSmmRevID[SubIndex]));
  }

  //
  // Check MSEG BASE/SIZE in TXT region
  //
  SAFE_DEBUG ((EFI_D_INFO, "MinMsegSize - %08x!\n", GetMinMsegSize (StmHeader)));

  mHostContextCommon.PhysicalAddressBits = TxtProcessorSmmDescriptor->PhysicalAddressBits;
  AsmCpuid (CPUID_EXTENDED_INFORMATION, &RegEax, NULL, NULL, NULL);
  if (RegEax >= CPUID_EXTENDED_ADDRESS_SIZE) {
    AsmCpuid (CPUID_EXTENDED_ADDRESS_SIZE, &RegEax, NULL, NULL, NULL);
    RegEax = (UINT8)RegEax;
    SAFE_DEBUG ((EFI_D_INFO, "CPUID - PhysicalAddressBits - 0x%02x\n", (UINT8)RegEax));
  } else {
    RegEax = 36;
  }

  if ((mHostContextCommon.PhysicalAddressBits == 0) || (mHostContextCommon.PhysicalAddressBits > (UINT8)RegEax)) {
    mHostContextCommon.PhysicalAddressBits = (UINT8)RegEax;
  }

  if (sizeof (UINTN) == sizeof (UINT32)) {
    if (mHostContextCommon.PhysicalAddressBits > 32) {
      mHostContextCommon.PhysicalAddressBits = 32;
    }
  }

  SAFE_DEBUG ((DEBUG_INFO, "mHostContextCommon.PhysicalAddressBits - 0x%08x!\n", (UINT8)mHostContextCommon.PhysicalAddressBits));

  mHostContextCommon.PageTable = AsmReadCr3 ();
  AsmReadGdtr (&mHostContextCommon.Gdtr);

  //
  // Set up STM host IDT to catch exception
  //
  mHostContextCommon.Idtr.Limit = (UINT16)(STM_MAX_IDT_NUM * sizeof (IA32_IDT_GATE_DESCRIPTOR) - 1);
  mHostContextCommon.Idtr.Base  = (UINTN)AllocatePages (STM_SIZE_TO_PAGES (mHostContextCommon.Idtr.Limit + 1));
  IdtGate                       = (IA32_IDT_GATE_DESCRIPTOR *)mHostContextCommon.Idtr.Base;
  InitializeExternalVectorTablePtr (IdtGate);

  for (SubIndex = 0; SubIndex < mHostContextCommon.CpuNum; SubIndex++) {
    mHostContextCommon.HostContextPerCpu[SubIndex].HostMsrEntryCount          = 1;
    mGuestContextCommonNormal.GuestContextPerCpu[SubIndex].GuestMsrEntryCount = 1;
  }

  mHostContextCommon.HostContextPerCpu[0].HostMsrEntryAddress          = (UINT64)(UINTN)AllocatePages (STM_SIZE_TO_PAGES (sizeof (VM_EXIT_MSR_ENTRY) * mHostContextCommon.HostContextPerCpu[0].HostMsrEntryCount * mHostContextCommon.CpuNum));
  mGuestContextCommonNormal.GuestContextPerCpu[0].GuestMsrEntryAddress = (UINT64)(UINTN)AllocatePages (STM_SIZE_TO_PAGES (sizeof (VM_EXIT_MSR_ENTRY) * mGuestContextCommonNormal.GuestContextPerCpu[0].GuestMsrEntryCount * mHostContextCommon.CpuNum));
  for (SubIndex = 0; SubIndex < mHostContextCommon.CpuNum; SubIndex++) {
    mHostContextCommon.HostContextPerCpu[SubIndex].HostMsrEntryAddress          = mHostContextCommon.HostContextPerCpu[0].HostMsrEntryAddress + sizeof (VM_EXIT_MSR_ENTRY) * mHostContextCommon.HostContextPerCpu[0].HostMsrEntryCount * SubIndex;
    mGuestContextCommonNormal.GuestContextPerCpu[SubIndex].GuestMsrEntryAddress = mGuestContextCommonNormal.GuestContextPerCpu[0].GuestMsrEntryAddress + sizeof (VM_EXIT_MSR_ENTRY) * mGuestContextCommonNormal.GuestContextPerCpu[0].GuestMsrEntryCount * SubIndex;
  }

  //
  // Add more paging for Host CR3.
  //
  CreateHostPaging ();

  // Disable perf init for now to reduce heap allocations
  // STM_PERF_INIT;

  //
  // Initialization done
  //
  mIsBspInitialized = TRUE;

  return;
}

/**
  This function initializes an AP.

  @param[in]  Index        CPU index
  @param[in]  Register     X86 register context
**/
VOID
ApInit (
  IN UINT32        Index,
  IN X86_REGISTER  *Register
  )
{
  X86_REGISTER  *Reg;

  SAFE_DEBUG ((DEBUG_INFO, "!!!Enter StmInit (AP done)!!! - %d (%x)\n", (UINTN)Index, (UINTN)ReadUnaligned32 ((UINT32 *)&Register->Rax)));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - Index Given = %d.\n", __func__, Index));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - Register at 0x%lx.\n", __func__, Register));

  if (Index >= mHostContextCommon.CpuNum) {
    SAFE_DEBUG ((DEBUG_INFO, "!!!Index(0x%x) >= mHostContextCommon.CpuNum(0x%x)\n", (UINTN)Index, (UINTN)mHostContextCommon.CpuNum));
    CpuDeadLoop ();
    Index = GetIndexFromStack (Register, TRUE);
  }

  // Todo: Currently not using JoinedCpuNum. It might be used in teardown in the future.
  // InterlockedIncrement (&mHostContextCommon.JoinedCpuNum);

  SAFE_DEBUG ((DEBUG_INFO, "Register(%d) - %08x\n", (UINTN)Index, Register));
  Reg           = &mGuestContextCommonNormal.GuestContextPerCpu[Index].Register;
  Register->Rsp = VmReadN (VMCS_N_GUEST_RSP_INDEX);
  CopyMem (Reg, Register, sizeof (X86_REGISTER));

  // Todo: Currently not using JoinedCpuNum. It might be used in teardown in the future.
  // if (mHostContextCommon.JoinedCpuNum > mHostContextCommon.CpuNum) {
  //   SAFE_DEBUG ((DEBUG_ERROR, "JoinedCpuNum(%d) > CpuNum(%d)\n", (UINTN)mHostContextCommon.JoinedCpuNum, (UINTN)mHostContextCommon.CpuNum));
  //   // Reset system
  //   CpuDeadLoop ();
  // }

  return;
}

/**

  This function initialize common part for BSP and AP.

  @param Index    CPU index

**/
VOID
CommonInit (
  IN UINT32  Index
  )
{
  UINTN              StackBase;
  UINTN              StackSize;
  STM_HEADER         *StmHeader;
  UINT32             RegEdx;
  IA32_VMX_MISC_MSR  VmxMisc;

  AsmWriteCr4 (AsmReadCr4 () | CR4_OSFXSR | CR4_OSXMMEXCPT);
  if (IsXStateSupported ()) {
    AsmWriteCr4 (AsmReadCr4 () | CR4_OSXSAVE);
  }

  VmxMisc.Uint64 = AsmReadMsr64 (IA32_VMX_MISC_MSR_INDEX);
  RegEdx         = ReadUnaligned32 ((UINT32 *)&mGuestContextCommonNormal.GuestContextPerCpu[Index].Register.Rdx);
  if ((RegEdx & STM_CONFIG_SMI_UNBLOCKING_BY_VMX_OFF) != 0) {
    if (VmxMisc.Bits.VmxOffUnblockSmiSupport != 0) {
      AsmWriteMsr64 (IA32_SMM_MONITOR_CTL_MSR_INDEX, AsmReadMsr64 (IA32_SMM_MONITOR_CTL_MSR_INDEX) | IA32_SMM_MONITOR_SMI_UNBLOCKING_BY_VMX_OFF);
    }
  }

  mHostContextCommon.HostContextPerCpu[Index].Index  = Index;
  mHostContextCommon.HostContextPerCpu[Index].ApicId = ReadLocalApicId ();

  StmHeader = mHostContextCommon.StmHeader;
  StackBase = (UINTN)StmHeader +
              STM_PAGES_TO_SIZE (STM_SIZE_TO_PAGES (StmHeader->SwStmHdr.StaticImageSize)) +
              StmHeader->SwStmHdr.AdditionalDynamicMemorySize;
  StackSize = StmHeader->SwStmHdr.PerProcDynamicMemorySize;
  SAFE_DEBUG ((DEBUG_INFO, "%a - Stack(%d) - StackSize = 0x%lx\n", __func__, (UINTN)Index, StackSize));
  mHostContextCommon.HostContextPerCpu[Index].Stack = (UINTN)(StackBase + StackSize * (Index + 1)); // Stack Top

  if ((VmxMisc.Uint64 & BIT15) != 0) {
    mHostContextCommon.HostContextPerCpu[Index].Smbase = (UINT32)AsmReadMsr64 (IA32_SMBASE_INDEX);
  } else {
    mHostContextCommon.HostContextPerCpu[Index].Smbase = VmRead32 (VMCS_32_GUEST_SMBASE_INDEX);
  }

  mHostContextCommon.HostContextPerCpu[Index].TxtProcessorSmmDescriptor = (TXT_PROCESSOR_SMM_DESCRIPTOR *)(UINTN)(mHostContextCommon.HostContextPerCpu[Index].Smbase + SMM_TXTPSD_OFFSET);

  SAFE_DEBUG ((EFI_D_INFO, "SMBASE(%d) - %08x\n", (UINTN)Index, (UINTN)mHostContextCommon.HostContextPerCpu[Index].Smbase));
  SAFE_DEBUG ((EFI_D_INFO, "TxtProcessorSmmDescriptor(%d) - %08x\n", (UINTN)Index, mHostContextCommon.HostContextPerCpu[Index].TxtProcessorSmmDescriptor));
  SAFE_DEBUG ((EFI_D_INFO, "Stack(%d) - %08x\n", (UINTN)Index, (UINTN)mHostContextCommon.HostContextPerCpu[Index].Stack));
}

/**

  This function launch back to MLE.

  @param Index    CPU index
  @param Register X86 register context
**/
VOID
LaunchBack (
  IN UINT32        Index,
  IN X86_REGISTER  *Register
  )
{
  UINTN              Rflags;
  VM_ENTRY_CONTROLS  VmEntryCtrls;

  //
  // Indicate operation status from caller.
  //
  VmWriteN (VMCS_N_GUEST_RFLAGS_INDEX, VmReadN (VMCS_N_GUEST_RFLAGS_INDEX) & ~RFLAGS_CF);

  SAFE_DEBUG ((DEBUG_ERROR, "Register @ LaunchBack: 0x%lx\n", (UINTN)Register));

  SAFE_DEBUG ((EFI_D_INFO, "!!!LaunchBack (%d)!!!\n", (UINTN)Index));
  SAFE_DEBUG ((DEBUG_ERROR, "VMCS_32_CONTROL_VMEXIT_CONTROLS_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_CONTROL_VMEXIT_CONTROLS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "CR0: %08x\n", (UINTN)AsmReadCr0 ()));
  SAFE_DEBUG ((DEBUG_ERROR, "CR3: %08x\n", (UINTN)AsmReadCr3 ()));
  SAFE_DEBUG ((DEBUG_ERROR, "CR4: %08x\n", (UINTN)AsmReadCr4 ()));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_EFER_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_EFER_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_SYSENTER_ESP_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_SYSENTER_ESP_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_SYSENTER_EIP_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_SYSENTER_EIP_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_PERF_GLOBAL_CTRL_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_PERF_GLOBAL_CTRL_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_CR_PAT_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_CR_PAT_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_S_CET: %08x\n", (UINTN)AsmReadMsr64 (0x6A2)));
  SAFE_DEBUG ((DEBUG_ERROR, "IA32_PKRS: %08x\n", (UINTN)AsmReadMsr64 (0x6E1)));

  SAFE_DEBUG ((DEBUG_ERROR, "Host-state CR0: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_CR0_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state CR3: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_CR3_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state CR4: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_CR4_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_64_HOST_IA32_EFER_INDEX: %08x\n", (UINTN)VmReadN (VMCS_64_HOST_IA32_EFER_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_IA32_SYSENTER_ESP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_IA32_SYSENTER_ESP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_IA32_SYSENTER_EIP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_IA32_SYSENTER_EIP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_64_HOST_IA32_PERF_GLOBAL_CTRL_INDEX: %08x\n", (UINTN)VmRead64 (VMCS_64_HOST_IA32_PERF_GLOBAL_CTRL_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_64_HOST_IA32_PAT_INDEX: %08x\n", (UINTN)VmRead64 (VMCS_64_HOST_IA32_PAT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_RIP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_RIP_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_ES_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_ES_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_CS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_CS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_SS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_SS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_DS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_DS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_FS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_FS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_GS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_GS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_16_HOST_TR_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_HOST_TR_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_FS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_FS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_GS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_GS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_TR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_TR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_GDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_GDTR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Host-state VMCS_N_HOST_IDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_HOST_IDTR_BASE_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rax = 0x%lx.\n", __func__, __LINE__, Register->Rax));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rcx = 0x%lx.\n", __func__, __LINE__, Register->Rcx));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rdx = 0x%lx.\n", __func__, __LINE__, Register->Rdx));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rbx = 0x%lx.\n", __func__, __LINE__, Register->Rbx));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rsp = 0x%lx.\n", __func__, __LINE__, Register->Rsp));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rbp = 0x%lx.\n", __func__, __LINE__, Register->Rbp));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rsi = 0x%lx.\n", __func__, __LINE__, Register->Rsi));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rdi = 0x%lx.\n", __func__, __LINE__, Register->Rdi));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R8  = 0x%lx.\n", __func__, __LINE__, Register->R8));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R9  = 0x%lx.\n", __func__, __LINE__, Register->R9));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R10 = 0x%lx.\n", __func__, __LINE__, Register->R10));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R11 = 0x%lx.\n", __func__, __LINE__, Register->R11));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R12 = 0x%lx.\n", __func__, __LINE__, Register->R12));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R13 = 0x%lx.\n", __func__, __LINE__, Register->R13));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R14 = 0x%lx.\n", __func__, __LINE__, Register->R14));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R15 = 0x%lx.\n", __func__, __LINE__, Register->R15));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_CR0_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CR0_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_CR3_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CR3_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_CR4_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CR4_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_DR7_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_DR7_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_RSP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RSP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_RIP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RIP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_RFLAGS_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RFLAGS_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_64_GUEST_IA32_DEBUGCTL_INDEX: %08x\n", (UINTN)VmRead64 (VMCS_64_GUEST_IA32_DEBUGCTL_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_IA32_SYSENTER_ESP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_IA32_SYSENTER_ESP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_IA32_SYSENTER_EIP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_IA32_SYSENTER_EIP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_64_GUEST_IA32_EFER_INDEX: %08x\n", (UINTN)VmRead64 (VMCS_64_GUEST_IA32_EFER_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_ES_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_ES_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_CS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_CS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_SS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_SS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_DS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_DS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_FS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_FS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_GS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_GS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_LDTR_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_LDTR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_16_GUEST_TR_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_TR_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_ES_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_ES_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_CS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_CS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_SS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_SS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_DS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_DS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_FS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_FS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_GS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_GS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_LDTR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_LDTR_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_TR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_TR_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_GDTR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_GDTR_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_IDTR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_IDTR_LIMIT_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_ES_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_ES_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_CS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_SS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_SS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_DS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_DS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_FS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_FS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_GS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_GS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_LDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_LDTR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_TR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_TR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_GDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_GDTR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_IDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_IDTR_BASE_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_ES_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_ES_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_CS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_CS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_SS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_SS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_DS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_DS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_FS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_FS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_GS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_GS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_LDTR_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_LDTR_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_TR_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_TR_ACCESS_RIGHT_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_CONTROL_PROCESSOR_BASED_VM_EXECUTION_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_CONTROL_PROCESSOR_BASED_VM_EXECUTION_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_CONTROL_2ND_PROCESSOR_BASED_VM_EXECUTION_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_CONTROL_2ND_PROCESSOR_BASED_VM_EXECUTION_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_INTERRUPTIBILITY_STATE_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_INTERRUPTIBILITY_STATE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_32_GUEST_ACTIVITY_STATE_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_ACTIVITY_STATE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_N_GUEST_PENDING_DEBUG_EXCEPTIONS_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_PENDING_DEBUG_EXCEPTIONS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On exit Guest-state VMCS_64_GUEST_VMCS_LINK_PTR_INDEX: %08x\n", (UINTN)VmRead64 (VMCS_64_GUEST_VMCS_LINK_PTR_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "On Exit MSR IA32_VMX_CR0_FIXED0_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR0_FIXED0_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On Exit MSR IA32_VMX_CR0_FIXED1_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR0_FIXED1_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On Exit MSR IA32_VMX_CR4_FIXED0_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR4_FIXED0_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "On Exit MSR IA32_VMX_CR4_FIXED1_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR4_FIXED1_MSR_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Register @ LaunchBack Before AsmVmLaunch: 0x%lx\n", (UINTN)Register));

  VmEntryCtrls.Uint32 = VmRead32 (VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX);
  SAFE_DEBUG ((DEBUG_ERROR, "VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX = 0x%x.\n", VmEntryCtrls.Uint32));
  VmEntryCtrls.Bits.DeactivateDualMonitor = 1;
  VmWrite32 (VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX, VmEntryCtrls.Uint32);
  SAFE_DEBUG ((DEBUG_ERROR, "VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX (after deactivate dual monitor) = 0x%x.\n", VmRead32 (VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - mHostContextCommon at Exit (0x%lx [0x%lx]):\n", __func__, (UINTN)&mHostContextCommon, sizeof (mHostContextCommon)));
  DUMP_HEX (DEBUG_INFO, 0, (VOID *)&mHostContextCommon, sizeof (mHostContextCommon), "");

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - mGuestContextCommonNormal at Exit (0x%lx [0x%lx]):\n", __func__, (UINTN)&mGuestContextCommonNormal, sizeof (mGuestContextCommonNormal)));
  DUMP_HEX (DEBUG_INFO, 0, (VOID *)&mGuestContextCommonNormal, sizeof (mGuestContextCommonNormal), "");

  // RelocateStmImage (TRUE);

  // SAFE_DEBUG ((DEBUG_ERROR, "Message after RelocateStmImage (TRUE)\n"));

  mSerializationLock = 0;

  Rflags = AsmVmResume (Register);
  if (VmRead32 (VMCS_32_RO_VM_INSTRUCTION_ERROR_INDEX) == VmxFailErrorVmResumeWithNonLaunchedVmcs) {
    SAFE_DEBUG ((DEBUG_ERROR, "Calling AsmVmLaunch()\n"));
    Rflags = AsmVmLaunch (Register);
  }

  SAFE_DEBUG ((DEBUG_ERROR, "!!!LaunchBack FAIL!!!\n"));
  SAFE_DEBUG ((DEBUG_ERROR, "Rflags: %08x\n", Rflags));
  SAFE_DEBUG ((DEBUG_ERROR, "VMCS_32_RO_VM_INSTRUCTION_ERROR: %08x\n", (UINTN)VmRead32 (VMCS_32_RO_VM_INSTRUCTION_ERROR_INDEX)));

  CpuDeadLoop ();
}

/**

  This function return if 2 resource overlap.

  @param Address1   Address of 1st resource
  @param Length1    Length of 1st resource
  @param Address2   Address of 2nd resource
  @param Length2    Length of 2nd resource

  @retval TRUE  overlap
  @retval FALSE no overlap

**/
BOOLEAN
IsOverlap (
  IN UINT64  Address1,
  IN UINT64  Length1,
  IN UINT64  Address2,
  IN UINT64  Length2
  )
{
  if ((Address1 + Length1 > Address2) && (Address1 < Address2 + Length2)) {
    // Overlap
    return TRUE;
  } else {
    return FALSE;
  }
}

/**

  This function initialize VMCS.

  @param Index    CPU index

**/
VOID
VmcsInit (
  IN UINT32   Index,
  IN BOOLEAN  IncrementGuestRip
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
  SAFE_DEBUG ((EFI_D_INFO, "Increment Guest RIP = %a.\n", IncrementGuestRip ? "True" : "False"));

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_RIP_INDEX (before store): %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RIP_INDEX)));

  AsmVmPtrStore (&CurrentVmcs);
  SAFE_DEBUG ((EFI_D_INFO, "CurrentVmcs(%d) - %016lx\n", (UINTN)Index, CurrentVmcs));
  // Todo: Need to set TsegBase and TsegLength somewhere?
  // if (IsOverlap (CurrentVmcs, VmcsSize, mHostContextCommon.TsegBase, mHostContextCommon.TsegLength)) {
  //   // Overlap TSEG
  //   SAFE_DEBUG ((DEBUG_ERROR, "CurrentVmcs violation - %016lx\n", CurrentVmcs));
  //   CpuDeadLoop ();
  // }

  Rflags = AsmVmClear (&CurrentVmcs);
  if ((Rflags & (RFLAGS_CF | RFLAGS_ZF)) != 0) {
    SAFE_DEBUG ((DEBUG_ERROR, "ERROR: AsmVmClear(%d) - %016lx : %08x\n", (UINTN)Index, CurrentVmcs, Rflags));
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

  InitializeNormalVmcs (Index, &mGuestContextCommonNormal.GuestContextPerCpu[Index].Vmcs, IncrementGuestRip);
}

/**
  Function for caller to query the capabilities of SEA core.

  @param[in, out]  Register  The registers of the context of current VMCALL request.

  @retval EFI_SUCCESS               The function completed successfully.
  @retval EFI_INVALID_PARAMETER     The supplied buffer has NULL physical address.
  @retval EFI_SECURITY_VIOLATION    The system status tripped on security violation.
**/
EFI_STATUS
EFIAPI
GetCapabilities (
  IN OUT X86_REGISTER  *Register
  )
{
  STM_STATUS               StmStatus;
  EFI_STATUS               Status;
  UINT64                   BufferBase;
  UINT64                   BufferSize;
  SEA_CAPABILITIES_STRUCT  RetStruct;

  if (Register == NULL) {
    Status = EFI_INVALID_PARAMETER;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming register being NULL!\n", __func__));
    goto Done;
  }

  // Check the buffer not null requirement
  BufferBase = Register->Rbx;
  BufferSize = EFI_PAGES_TO_SIZE (Register->Rdx);
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - BufferBase = 0x%LX. BufferSize = 0x%LX.\n", __func__, __LINE__, BufferBase, BufferSize));
  if (BufferBase == 0) {
    StmStatus = ERROR_INVALID_PARAMETER;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer being NULL!\n", __func__));
    goto Done;
  }

  // Check the minimal size requirement
  if (BufferSize < sizeof (SEA_CAPABILITIES_STRUCT)) {
    StmStatus = ERROR_STM_BUFFER_TOO_SMALL;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    // Populate rdx with the number of pages required
    WriteUnaligned32 ((UINT32 *)&Register->Rdx, EFI_SIZE_TO_PAGES (sizeof (SEA_CAPABILITIES_STRUCT)));
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer too small: 0x%x bytes!\n", __func__, BufferSize));
    goto Done;
  }

  // Check the buffer alignment requirement
  if (!IS_ALIGNED (BufferBase, EFI_PAGE_SIZE)) {
    StmStatus = ERROR_SMM_BAD_BUFFER;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer not page size aligned: 0x%x bytes!\n", __func__, BufferBase));
    goto Done;
  }

  // Check the buffer supplied is not in the MSEG or TSEG.
  if (IsBufferInsideMmram (BufferBase, BufferSize)) {
    StmStatus = ERROR_STM_PAGE_NOT_FOUND;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer is inside MMRAM: Base: 0x%x, Size: 0x%x !\n", __func__, BufferBase, BufferSize));
    goto Done;
  }

  // Enough complaints, get to work now.
  RetStruct.SeaSpecVerMajor = SEA_SPEC_VERSION_MAJOR;
  RetStruct.SeaSpecVerMinor = SEA_SPEC_VERSION_MINOR;
  RetStruct.Reserved        = 0;
  RetStruct.SeaHeaderSize   = OFFSET_OF (SEA_CAPABILITIES_STRUCT, SeaFeatures);
  RetStruct.SeaTotalSize    = sizeof (SEA_CAPABILITIES_STRUCT);

  RetStruct.SeaFeatures.VerifyMmiEntry = TRUE;
  RetStruct.SeaFeatures.VerifyMmPolicy = TRUE;
  RetStruct.SeaFeatures.VerifyMmSupv   = TRUE;
  RetStruct.SeaFeatures.HashAlg        = HASH_ALG_SHA256;
  RetStruct.SeaFeatures.Reserved       = 0;

  CopyMem ((VOID *)(UINTN)BufferBase, &RetStruct, RetStruct.SeaTotalSize);
  Status    = EFI_SUCCESS;
  StmStatus = STM_SUCCESS;
  WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);

Done:
  return Status;
}

/**
  Function for caller to query the resources of SMM environment.

  @param[in]  Register  The registers of the context of current VMCALL request.

  @retval EFI_SUCCESS               The function completed successfully.
  @retval EFI_INVALID_PARAMETER     The supplied buffer has NULL physical address.
  @retval EFI_SECURITY_VIOLATION    The system status tripped on security violation.
**/
EFI_STATUS
EFIAPI
GetResources (
  IN OUT X86_REGISTER  *Register
  )
{
  STM_STATUS                        StmStatus;
  EFI_STATUS                        Status;
  UINT64                            BufferBase;
  UINT64                            BufferSize;
  UINTN                             CpuIndex;
  TPML_DIGEST_VALUES                DigestList[SUPPORTED_DIGEST_COUNT];

  if (Register == NULL) {
    Status = EFI_INVALID_PARAMETER;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming register being NULL!\n", __func__));
    goto Done;
  }

  // Check the buffer not null requirement
  BufferBase = Register->Rbx;
  BufferSize = EFI_PAGES_TO_SIZE (Register->Rdx);
  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - BufferBase 0x%lx.\n", __func__, BufferBase));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - BufferSize 0x%lx.\n", __func__, BufferSize));

  if ((BufferBase == 0) && (BufferSize != 0)) {
    StmStatus = ERROR_INVALID_PARAMETER;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer being NULL!\n", __func__));
    goto Done;
  }

  // Check the buffer alignment requirement
  if (!IS_ALIGNED (BufferBase, EFI_PAGE_SIZE)) {
    StmStatus = ERROR_SMM_BAD_BUFFER;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer not page size aligned: 0x%x bytes!\n", __func__, BufferBase));
    goto Done;
  }

  // Check the buffer supplied is not in the MSEG or TSEG.
  if ((BufferBase != 0) && IsBufferInsideMmram (BufferBase, BufferSize)) {
    StmStatus = ERROR_STM_PAGE_NOT_FOUND;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
    SAFE_DEBUG ((DEBUG_ERROR, "%a Incoming buffer is inside MMRAM: Base: 0x%x, Size: 0x%x !\n", __func__, BufferBase, BufferSize));
    goto Done;
  }

  //
  // Get information about the image being loaded
  //
  ZeroMem (DigestList, sizeof (DigestList));
  DigestList[MMI_ENTRY_DIGEST_INDEX].digests[0].hashAlg = TPM_ALG_SHA256;
  DigestList[MMI_ENTRY_DIGEST_INDEX].count              = 1;
  CopyMem (DigestList[MMI_ENTRY_DIGEST_INDEX].digests[0].digest.sha256, PcdGetPtr (PcdMmiEntryBinHash), SHA256_DIGEST_SIZE);

  DigestList[MM_SUPV_DIGEST_INDEX].digests[0].hashAlg = TPM_ALG_SHA256;
  DigestList[MM_SUPV_DIGEST_INDEX].count              = 1;
  CopyMem (DigestList[MM_SUPV_DIGEST_INDEX].digests[0].digest.sha256, PcdGetPtr (PcdMmSupervisorCoreHash), SHA256_DIGEST_SIZE);

  CpuIndex = GetIndexFromStack (Register, TRUE);
  AcquireSpinLock (&mHostContextCommon.ResponderLock);
  Status = SeaResponderReport (
             CpuIndex,
             (EFI_PHYSICAL_ADDRESS)(UINTN)PcdGetPtr (PcdAuxBinFile),
             PcdGetSize (PcdAuxBinFile),
             PcdGet64 (PcdMmiEntryBinSize),
             DigestList,
             SUPPORTED_DIGEST_COUNT,
             (VOID *)(UINTN)BufferBase,
             BufferSize
             );
  if (!EFI_ERROR (Status)) {
    SAFE_DEBUG ((DEBUG_ERROR, "%a Validation routine succeeded!\n", __func__));
    StmStatus = STM_SUCCESS;
    Status = EFI_SUCCESS;
  } else if (Status == EFI_BUFFER_TOO_SMALL) {
    SAFE_DEBUG ((DEBUG_ERROR, "%a Policy cannot fit into provided buffer (0x%x)!\n", __func__, BufferSize));
    StmStatus = ERROR_STM_BUFFER_TOO_SMALL;
    // Populate rdx with the number of pages required
    WriteUnaligned32 ((UINT32 *)&Register->Rdx, EFI_SIZE_TO_PAGES (BufferSize));
    Status = EFI_SECURITY_VIOLATION;
  } else {
    // Some other errors
    SAFE_DEBUG ((DEBUG_ERROR, "%a Validation routine failed with %r!!!\n", __func__, Status));
    StmStatus = ERROR_STM_SECURITY_VIOLATION;
    WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
    Status = EFI_SECURITY_VIOLATION;
  }

  WriteUnaligned32 ((UINT32 *)&Register->Rax, StmStatus);
  ReleaseSpinLock (&mHostContextCommon.ResponderLock);

Done:
  return Status;
}

VOID
EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

VOID
DumpMtrrsInStm (
  VOID
  )
{
  MTRR_SETTINGS  LocalMtrrs;
  MTRR_SETTINGS  *Mtrrs;
  UINTN          Index;
  UINTN          VariableMtrrCount;

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - Enter\n", __func__));

  MtrrGetAllMtrrs (&LocalMtrrs);
  Mtrrs = &LocalMtrrs;
  SAFE_DEBUG ((DEBUG_ERROR, "MTRR Default Type: %016lx\n", Mtrrs->MtrrDefType));
  for (Index = 0; Index < MTRR_NUMBER_OF_FIXED_MTRR; Index++) {
    SAFE_DEBUG ((DEBUG_ERROR, "Fixed MTRR[%02d]   : %016lx\n", Index, Mtrrs->Fixed.Mtrr[Index]));
  }

  VariableMtrrCount = GetVariableMtrrCount ();
  for (Index = 0; Index < VariableMtrrCount; Index++) {
    SAFE_DEBUG (
      (
       DEBUG_ERROR,
       "Variable MTRR[%02d]: Base=%016lx Mask=%016lx\n",
       Index,
       Mtrrs->Variables.Mtrr[Index].Base,
       Mtrrs->Variables.Mtrr[Index].Mask
      )
      );
  }

  SAFE_DEBUG ((DEBUG_ERROR, "\n"));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - Exit\n", __func__));
}

/**

  This function handles VMCalls into SEA module in C code.

  @param Register X86 register context

**/
VOID
SeaVmcallDispatcher (
  IN X86_REGISTER  *Register
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsFirstEntryOnBsp;
  BOOLEAN     IsFirstEntryOnThisCore;
  UINT32      CpuIndex;
  UINT32      ServiceId;
  STM_HEADER  *StmHeader;

  if (Register == NULL) {
    ASSERT (Register != NULL);
    return;
  }

  IsFirstEntryOnBsp = (IsBsp () && mHostContextCommon.StmHeader == NULL);
  if (IsFirstEntryOnBsp) {
    // The build process should make sure "virtual address" is same as "file pointer to raw data",
    // in final PE/COFF image, so that we can let StmLoad load binary to memory directly.
    // If no, GenStm tool will "load image". So here, we just need "relocate image".
    RelocateStmImage (FALSE);

    // Initialize debug lock on first entry (assume GetCapabilities() is called once and first entry)
    InitializeSpinLock (&mHostContextCommon.DebugLock);
    InitializeSpinLock (&mHostContextCommon.MemoryLock);
    InitializeSpinLock (&mHostContextCommon.ResponderLock);

    StmHeader = (STM_HEADER *)(UINTN)((UINT32)AsmReadMsr64 (IA32_SMM_MONITOR_CTL_MSR_INDEX) & 0xFFFFF000);
    // We have to know CpuNum, or we do not know where VMCS will be.
    if (IsSentryEnabled ()) {
      mHostContextCommon.CpuNum = GetCpuNumFromTxt ();
      SAFE_DEBUG ((EFI_D_INFO, "CpuNumber from TXT Region - %d\n", (UINTN)mHostContextCommon.CpuNum));
    } else {
      SAFE_DEBUG ((DEBUG_ERROR, "SENTER must be enabled for before SEA execution.\n"));
      CpuDeadLoop ();
    }

    // Note: After this mHostContextCommon can be used.
    InitHeap (StmHeader);
    InitBasicContext ();

    ProcessLibraryConstructorList ();

    SAFE_DEBUG ((DEBUG_INFO, "[%a] - (CpuNum = %d) mHostContextCommon.HostContextPerCpu = 0x%p.\n", __func__, mHostContextCommon.CpuNum, mHostContextCommon.HostContextPerCpu));
    SAFE_DEBUG ((DEBUG_INFO, "[%a] - (CpuNum = %d) mGuestContextCommonNormal.GuestContextPerCpu = 0x%p.\n", __func__, mHostContextCommon.CpuNum, mGuestContextCommonNormal.GuestContextPerCpu));

    SAFE_DEBUG ((DEBUG_INFO, "[%a][L%d] - Performing BSP init.\n", __func__, __LINE__));
    BspInit (Register);
    SAFE_DEBUG ((DEBUG_INFO, "[%a][L%d] - Done with first entry on BSP init.\n", __func__, __LINE__));

    // The heap area below the context allocations will be "reused" across entries.
    // This assumes all entries are serialized.
    mHostContextCommon.HeapReusableBase = mHostContextCommon.HeapTop;
  } else {
    mHostContextCommon.HeapTop = mHostContextCommon.HeapReusableBase;
    ZeroMem (
      (VOID *)(UINTN)mHostContextCommon.HeapBottom,
      (UINTN)(mHostContextCommon.HeapReusableBase - mHostContextCommon.HeapBottom)
      );
    SAFE_DEBUG ((DEBUG_INFO, "[%a] - Heap area set to 0x%p.\n", __func__, mHostContextCommon.HeapReusableBase));
  }

  CpuIndex               = GetIndexFromStack (Register, TRUE);
  IsFirstEntryOnThisCore = mHostContextCommon.HostContextPerCpu[CpuIndex].Stack == 0;

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - Enter\n", __func__));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - mHostContextCommon at Entry (0x%lx [0x%lx]):\n", __func__, (UINTN)&mHostContextCommon, sizeof (mHostContextCommon)));
  DUMP_HEX (DEBUG_INFO, 0, (VOID *)&mHostContextCommon, sizeof (mHostContextCommon), "");

  SAFE_DEBUG ((DEBUG_ERROR, "[%a] - mGuestContextCommonNormal at Entry (0x%lx [0x%lx]):\n", __func__, (UINTN)&mGuestContextCommonNormal, sizeof (mGuestContextCommonNormal)));
  DUMP_HEX (DEBUG_INFO, 0, (VOID *)&mGuestContextCommonNormal, sizeof (mGuestContextCommonNormal), "");

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Register at 0x%p.\n", __func__, __LINE__, Register));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - ServiceId (local stack var) at 0x%p.\n", __func__, __LINE__, &ServiceId));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - CpuIndex = 0x%x.\n", __func__, __LINE__, CpuIndex));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - First entry on this core = %a.\n", __func__, __LINE__, IsFirstEntryOnThisCore ? "True" : "False"));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - First entry on BSP = %a.\n", __func__, __LINE__, IsFirstEntryOnBsp ? "True" : "False"));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rax = 0x%lx.\n", __func__, __LINE__, Register->Rax));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rcx = 0x%lx.\n", __func__, __LINE__, Register->Rcx));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rdx = 0x%lx.\n", __func__, __LINE__, Register->Rdx));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rbx = 0x%lx.\n", __func__, __LINE__, Register->Rbx));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rsp = 0x%lx.\n", __func__, __LINE__, Register->Rsp));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rbp = 0x%lx.\n", __func__, __LINE__, Register->Rbp));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rsi = 0x%lx.\n", __func__, __LINE__, Register->Rsi));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Rdi = 0x%lx.\n", __func__, __LINE__, Register->Rdi));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R8  = 0x%lx.\n", __func__, __LINE__, Register->R8));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R9  = 0x%lx.\n", __func__, __LINE__, Register->R9));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R10 = 0x%lx.\n", __func__, __LINE__, Register->R10));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R11 = 0x%lx.\n", __func__, __LINE__, Register->R11));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R12 = 0x%lx.\n", __func__, __LINE__, Register->R12));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R13 = 0x%lx.\n", __func__, __LINE__, Register->R13));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R14 = 0x%lx.\n", __func__, __LINE__, Register->R14));
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - R15 = 0x%lx.\n", __func__, __LINE__, Register->R15));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - VMCS_32_RO_EXIT_REASON_INDEX = 0x%lx.\n", __func__, __LINE__, VmRead32 (VMCS_32_RO_EXIT_REASON_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_CR0_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CR0_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_CR3_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CR3_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_CR4_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CR4_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_DR7_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_DR7_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_RSP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RSP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_RIP_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RIP_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_RFLAGS_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_RFLAGS_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_ES_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_ES_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_CS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_CS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_SS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_SS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_DS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_DS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_FS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_FS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_GS_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_GS_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_LDTR_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_LDTR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_16_GUEST_TR_INDEX: %04x\n", (UINTN)VmRead16 (VMCS_16_GUEST_TR_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_ES_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_ES_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_CS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_CS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_SS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_SS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_DS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_DS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_FS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_FS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_GS_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_GS_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_LDTR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_LDTR_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_TR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_TR_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_GDTR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_GDTR_LIMIT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_IDTR_LIMIT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_IDTR_LIMIT_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_ES_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_ES_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_CS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_CS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_SS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_SS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_DS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_DS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_FS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_FS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_GS_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_GS_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_LDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_LDTR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_TR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_TR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_GDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_GDTR_BASE_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_N_GUEST_IDTR_BASE_INDEX: %08x\n", (UINTN)VmReadN (VMCS_N_GUEST_IDTR_BASE_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_ES_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_ES_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_CS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_CS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_SS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_SS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_DS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_DS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_FS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_FS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_GS_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_GS_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_LDTR_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_LDTR_ACCESS_RIGHT_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "Guest-state VMCS_32_GUEST_TR_ACCESS_RIGHT_INDEX: %08x\n", (UINTN)VmRead32 (VMCS_32_GUEST_TR_ACCESS_RIGHT_INDEX)));

  SAFE_DEBUG ((DEBUG_ERROR, "MSR IA32_VMX_CR0_FIXED0_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR0_FIXED0_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "MSR IA32_VMX_CR0_FIXED1_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR0_FIXED1_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "MSR IA32_VMX_CR4_FIXED0_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR4_FIXED0_MSR_INDEX)));
  SAFE_DEBUG ((DEBUG_ERROR, "MSR IA32_VMX_CR4_FIXED1_MSR_INDEX: %08x\n", (UINTN)AsmReadMsr64 (IA32_VMX_CR4_FIXED1_MSR_INDEX)));

  DumpMtrrsInStm ();

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - LocalApicId (From ReadLocalApicId) = 0x%x\n", __func__, __LINE__, ReadLocalApicId ()));

  ServiceId = ReadUnaligned32 ((UINT32 *)&Register->Rax);
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - ServiceId = 0x%x\n", __func__, __LINE__, ServiceId));

  if (ReadLocalApicId () != mHostContextCommon.HostContextPerCpu[0].ApicId) {
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Performing AP stack init for CPU index %d.\n", __func__, __LINE__, CpuIndex));
    ApInit (CpuIndex, Register);
  }

  if (IsFirstEntryOnThisCore) {
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Calling CommonInit()...\n", __func__, __LINE__));
    CommonInit (CpuIndex);
    SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Returned from CommonInit().\n", __func__, __LINE__));
  }

  switch (ServiceId) {
    case SEA_API_GET_CAPABILITIES:
      SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - SEA_API_GET_CAPABILITIES entered.\n", __func__, __LINE__));
      Status = GetCapabilities (Register);
      SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Returned from GetCapabilities(). Status = %r.\n", __func__, __LINE__, Status));
      break;

    case SEA_API_GET_RESOURCES:
      if (!mIsBspInitialized) {
        SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - !mIsBspInitialized.\n", __func__, __LINE__));
        Status = EFI_NOT_STARTED;
        break;
      }

      SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - SEA_API_GET_RESOURCES entered.\n", __func__, __LINE__));
      Status = GetResources (Register);
      SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Returned from GetResources(). Status = %r.\n", __func__, __LINE__, Status));
      break;
  }

  if (EFI_ERROR (Status)) {
    SAFE_DEBUG ((DEBUG_ERROR, "ServiceId(0x%x) error - %r\n", (UINTN)ServiceId, Status));
  }

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Calling VmcsInit()...\n", __func__, __LINE__));
  VmcsInit (CpuIndex, IsFirstEntryOnThisCore);
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Calling VmcsInit()...\n", __func__, __LINE__));

  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Calling LaunchBack()...\n", __func__, __LINE__));
  LaunchBack (CpuIndex, Register);
  SAFE_DEBUG ((DEBUG_ERROR, "[%a][L%d] - Returned from LaunchBack().\n", __func__, __LINE__));

  return;
}
