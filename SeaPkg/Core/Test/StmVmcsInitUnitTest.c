/** @file
  Host regressions for the production STM VMCS relocation and return path.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "../Init/StmInit.h"
#include <Library/UnitTestLib.h>
#include <Library/UnitTestHostBaseLib.h>

typedef struct {
  UINT32    Index;
  UINT64    Value;
} MOCK_VMCS_FIELD;

typedef struct {
  UINT32             Revision;
  UINT32             FieldCount;
  MOCK_VMCS_FIELD    Fields[64];
} MOCK_VMCS;

typedef struct {
  UINT32    CpuIndex;
  UINT64    InitialLink;
} RETURN_TEST_CASE;

STATIC_ASSERT (sizeof (MOCK_VMCS) <= EFI_PAGE_SIZE, "Mock VMCS must fit in its region");

SEA_HOST_CONTEXT_COMMON   mHostContextCommon;
SEA_GUEST_CONTEXT_COMMON  mGuestContextCommonNormal;

STATIC SEA_HOST_CONTEXT_PER_CPU   mHostCpus[2];
STATIC SEA_GUEST_CONTEXT_PER_CPU  mGuestCpus[2];
STATIC VM_EXIT_MSR_ENTRY          mHostMsrs[2];
STATIC VM_EXIT_MSR_ENTRY          mGuestMsrs[2];
STATIC MOCK_VMCS                  *mCaller;
STATIC MOCK_VMCS                  *mDestination;
STATIC MOCK_VMCS                  *mCurrent;
STATIC VOID                       *mMseg;
STATIC BOOLEAN                    mCallerActive;
STATIC BOOLEAN                    mDestinationActive;
STATIC UINTN                      mPhase;

STATIC RETURN_TEST_CASE  mReturnCases[] = {
  { 0, 0          },
  { 0, MAX_UINT64 },
  { 1, 0x12345000 }
};

STATIC
UINT64
ReadField (
  IN MOCK_VMCS  *Vmcs,
  IN UINT32     Index
  )
{
  UINTN  Field;

  ASSERT (Vmcs != NULL);
  for (Field = 0; Field < Vmcs->FieldCount; Field++) {
    if (Vmcs->Fields[Field].Index == Index) {
      return Vmcs->Fields[Field].Value;
    }
  }

  return 0;
}

STATIC
VOID
WriteField (
  IN MOCK_VMCS  *Vmcs,
  IN UINT32     Index,
  IN UINT64     Value
  )
{
  UINTN  Field;

  ASSERT (Vmcs != NULL);
  for (Field = 0; Field < Vmcs->FieldCount; Field++) {
    if (Vmcs->Fields[Field].Index == Index) {
      Vmcs->Fields[Field].Value = Value;
      return;
    }
  }

  ASSERT (Vmcs->FieldCount < ARRAY_SIZE (Vmcs->Fields));
  Vmcs->Fields[Vmcs->FieldCount].Index = Index;
  Vmcs->Fields[Vmcs->FieldCount].Value = Value;
  Vmcs->FieldCount++;
}

UINT32
VmRead32 (
  IN UINT32  Index
  )
{
  return (UINT32)ReadField (mCurrent, Index);
}

UINTN
VmReadN (
  IN UINT32  Index
  )
{
  return (UINTN)ReadField (mCurrent, Index);
}

VOID
VmWrite16 (
  IN UINT32  Index,
  IN UINT16  Data
  )
{
  WriteField (mCurrent, Index, Data);
}

VOID
VmWrite32 (
  IN UINT32  Index,
  IN UINT32  Data
  )
{
  WriteField (mCurrent, Index, Data);
}

VOID
VmWrite64 (
  IN UINT32  Index,
  IN UINT64  Data
  )
{
  WriteField (mCurrent, Index, Data);
}

VOID
VmWriteN (
  IN UINT32  Index,
  IN UINTN   Data
  )
{
  WriteField (mCurrent, Index, Data);
}

UINTN
AsmVmPtrStore (
  IN UINT64  *Vmcs
  )
{
  ASSERT (mPhase == 0);
  ASSERT (mCurrent == mCaller);
  *Vmcs  = (UINTN)mCurrent;
  mPhase = 1;
  return 0;
}

UINTN
AsmVmClear (
  IN UINT64  *Vmcs
  )
{
  if (*Vmcs == (UINTN)mCaller) {
    ASSERT (mPhase == 1);
    mCallerActive = FALSE;
    mCurrent      = NULL;
    mPhase        = 2;
  } else {
    ASSERT (*Vmcs == (UINTN)mDestination);
    ASSERT (mPhase == 2);
    if (mDestinationActive) {
      // Model cached VMCS data overwriting backing memory when it is flushed.
      SetMem (mDestination, EFI_PAGE_SIZE, 0xCC);
    }

    mDestinationActive = FALSE;
    mPhase             = 3;
  }

  return 0;
}

STATIC
VOID
EFIAPI
MockWbinvd (
  VOID
  )
{
  ASSERT (mPhase == 3);
  ASSERT (!mCallerActive);
  ASSERT (!mDestinationActive);
  ASSERT (CompareMem (mCaller, mDestination, EFI_PAGE_SIZE) == 0);
  mPhase = 4;
}

UINTN
AsmVmPtrLoad (
  IN UINT64  *Vmcs
  )
{
  ASSERT (mPhase == 4);
  ASSERT (*Vmcs == (UINTN)mDestination);
  mCurrent           = mDestination;
  mDestinationActive = TRUE;
  mPhase             = 5;
  return 0;
}

UINT32
GetVmcsSize (
  VOID
  )
{
  return EFI_PAGE_SIZE;
}

VOID
_ModuleEntryPoint (
  VOID
  )
{
}

STATIC
UINTN
EFIAPI
MockReadCr (
  VOID
  )
{
  return 0;
}

STATIC
UINT16
EFIAPI
MockReadSegment (
  VOID
  )
{
  return 8;
}

STATIC
UINT64
EFIAPI
MockReadMsr (
  IN UINT32  Index
  )
{
  ASSERT (Index == IA32_PERF_GLOBAL_CTRL_MSR_INDEX);
  return 0;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PrepareReturn (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  RETURN_TEST_CASE  *TestCase;
  STM_HEADER        *Header;
  UINTN             Index;

  TestCase = Context;
  mCaller  = AllocateAlignedPages (1, EFI_PAGE_SIZE);
  mMseg    = AllocateAlignedPages (5, EFI_PAGE_SIZE);
  UT_ASSERT_NOT_NULL (mCaller);
  UT_ASSERT_NOT_NULL (mMseg);
  ZeroMem (mCaller, EFI_PAGE_SIZE);
  ZeroMem (mMseg, EFI_PAGES_TO_SIZE (5));
  ZeroMem (&mHostContextCommon, sizeof (mHostContextCommon));
  ZeroMem (&mGuestContextCommonNormal, sizeof (mGuestContextCommonNormal));
  ZeroMem (mHostCpus, sizeof (mHostCpus));
  ZeroMem (mGuestCpus, sizeof (mGuestCpus));

  Header                                       = mMseg;
  Header->SwStmHdr.StaticImageSize             = EFI_PAGE_SIZE;
  mHostContextCommon.StmHeader                 = Header;
  mHostContextCommon.CpuNum                    = ARRAY_SIZE (mHostCpus);
  mHostContextCommon.HostContextPerCpu         = mHostCpus;
  mGuestContextCommonNormal.GuestContextPerCpu = mGuestCpus;
  InitializeSpinLock (&mHostContextCommon.DebugLock);
  for (Index = 0; Index < ARRAY_SIZE (mHostCpus); Index++) {
    mHostCpus[Index].HostMsrEntryAddress   = (UINTN)&mHostMsrs[Index];
    mGuestCpus[Index].GuestMsrEntryAddress = (UINTN)&mGuestMsrs[Index];
    mHostCpus[Index].HostMsrEntryCount     = 1;
    mGuestCpus[Index].GuestMsrEntryCount   = 1;
  }

  mDestination                          = (MOCK_VMCS *)((UINTN)mMseg + EFI_PAGES_TO_SIZE (1 + TestCase->CpuIndex * 2));
  mCurrent                              = mCaller;
  mCallerActive                         = TRUE;
  mDestinationActive                    = FALSE;
  mPhase                                = 0;
  mCaller->Revision                     = 1;
  ((UINT8 *)mCaller)[EFI_PAGE_SIZE - 1] = 0xA5;
  WriteField (mCaller, VMCS_N_GUEST_RIP_INDEX, 0x123456789000);
  WriteField (mCaller, VMCS_N_GUEST_RFLAGS_INDEX, 0x202);
  WriteField (mCaller, VMCS_32_RO_VMEXIT_INSTRUCTION_LENGTH_INDEX, 3);
  WriteField (mCaller, VMCS_64_GUEST_VMCS_LINK_PTR_INDEX, TestCase->InitialLink);
  WriteField (mCaller, VMCS_64_CONTROL_EXECUTIVE_VMCS_PTR_INDEX, 0x8000);
  return UNIT_TEST_PASSED;
}

STATIC
VOID
EFIAPI
CleanupReturn (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  if (mCaller != NULL) {
    FreeAlignedPages (mCaller, 1);
  }

  if (mMseg != NULL) {
    FreeAlignedPages (mMseg, 5);
  }
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RestoresCallerVmcs (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  RETURN_TEST_CASE  *TestCase;

  TestCase = Context;
  VmcsInit (TestCase->CpuIndex);
  UT_ASSERT_EQUAL (mPhase, 5);
  UT_ASSERT_FALSE (mCallerActive);
  UT_ASSERT_TRUE (mDestinationActive);
  UT_ASSERT_EQUAL ((UINTN)mCurrent, (UINTN)mDestination);
  UT_ASSERT_EQUAL (ReadField (mDestination, VMCS_64_GUEST_VMCS_LINK_PTR_INDEX), (UINTN)mCaller);
  UT_ASSERT_EQUAL (ReadField (mDestination, VMCS_N_GUEST_RIP_INDEX), 0x123456789003);
  UT_ASSERT_EQUAL (ReadField (mCaller, VMCS_N_GUEST_RIP_INDEX), 0x123456789000);
  UT_ASSERT_EQUAL (ReadField (mCaller, VMCS_64_GUEST_VMCS_LINK_PTR_INDEX), TestCase->InitialLink);
  UT_ASSERT_EQUAL (ReadField (mDestination, VMCS_64_CONTROL_EXECUTIVE_VMCS_PTR_INDEX), 0x8000);
  UT_ASSERT_EQUAL (((UINT8 *)mDestination)[EFI_PAGE_SIZE - 1], 0xA5);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
AdvancesEveryVmcall (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINTN  Call;
  UINTN  Rip;

  for (Call = 0; Call < 3; Call++) {
    Rip = 0x123456789000 + Call * 0x100;
    // A root return restores the caller but does not make the MSEG VMCS inactive.
    mCurrent      = mCaller;
    mCallerActive = TRUE;
    mPhase        = 0;
    WriteField (mCaller, VMCS_N_GUEST_RIP_INDEX, Rip);
    WriteField (mCaller, VMCS_32_RO_VMEXIT_INSTRUCTION_LENGTH_INDEX, 3 + Call);
    VmcsInit (0);
    UT_ASSERT_EQUAL (ReadField (mDestination, VMCS_N_GUEST_RIP_INDEX), Rip + 3 + Call);
    UT_ASSERT_EQUAL (ReadField (mDestination, VMCS_64_GUEST_VMCS_LINK_PTR_INDEX), (UINTN)mCaller);
    UT_ASSERT_EQUAL (mPhase, 5);
  }

  return UNIT_TEST_PASSED;
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  EFI_STATUS                   Status;
  UNIT_TEST_FRAMEWORK_HANDLE   Framework;
  UNIT_TEST_SUITE_HANDLE       Suite;
  UNIT_TEST_HOST_BASE_LIB_X86  Hooks;
  UNIT_TEST_HOST_BASE_LIB_X86  *OriginalHooks;

  Framework                = NULL;
  OriginalHooks            = gUnitTestHostBaseLib.X86;
  Hooks                    = *OriginalHooks;
  Hooks.AsmReadCr0         = MockReadCr;
  Hooks.AsmReadCr4         = MockReadCr;
  Hooks.AsmReadCs          = MockReadSegment;
  Hooks.AsmReadDs          = MockReadSegment;
  Hooks.AsmReadMsr64       = MockReadMsr;
  Hooks.AsmWbinvd          = MockWbinvd;
  gUnitTestHostBaseLib.X86 = &Hooks;

  Status = InitUnitTestFramework (&Framework, "STM VMCS return", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "VMCS relocation and return", "Stm.VmcsReturn", NULL, NULL);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = AddTestCase (Suite, "Restore caller when incoming link is zero", "ZeroLink", RestoresCallerVmcs, PrepareReturn, CleanupReturn, &mReturnCases[0]);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = AddTestCase (Suite, "Restore caller instead of the no-current-VMCS sentinel", "NoCurrentVmcs", RestoresCallerVmcs, PrepareReturn, CleanupReturn, &mReturnCases[1]);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = AddTestCase (Suite, "Restore AP caller instead of an inherited link", "ApLink", RestoresCallerVmcs, PrepareReturn, CleanupReturn, &mReturnCases[2]);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = AddTestCase (Suite, "Clear reused destination and advance every VMCALL", "RepeatedCalls", AdvancesEveryVmcall, PrepareReturn, CleanupReturn, &mReturnCases[0]);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  Status = RunAllTestSuites (Framework);

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "STM VMCS host tests failed: %r\n", Status));
  }

  if (Framework != NULL) {
    FreeUnitTestFramework (Framework);
  }

  gUnitTestHostBaseLib.X86 = OriginalHooks;
  return EFI_ERROR (Status) ? 1 : 0;
}
