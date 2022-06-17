/** @file
  Unit tests of the instance in MmSupervisorPkg of the SmmPolicyGateLib class

  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <Uefi.h>
#include <SmmSecurePolicy.h>
#include <Protocol/MmCpuIo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Library/UnitTestLib.h>
#include <Library/SmmPolicyGateLib.h>

#define UNIT_TEST_APP_NAME     "SmmPolicyGateLib Unit Tests"
#define UNIT_TEST_APP_VERSION  "1.0"

typedef struct {
  SMM_SUPV_SECURE_POLICY_DATA_V1_0    *Policy;
} TEST_CONTEXT_POLICY;

SMM_SUPV_SECURE_POLICY_DATA_V1_0  mTestPolicyTemplate = {
  .VersionMinor     = 0x0000,
  .VersionMajor     = 0x0001,
  .PolicyRootOffset = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0),
};

SMM_SUPV_POLICY_ROOT_V1  mTestPolicyRootTemplate = {
  .Version        = 1,
  .PolicyRootSize = sizeof (SMM_SUPV_POLICY_ROOT_V1),
};

/*
  Helper function to create a test policy with single 8bit read-allow IO entry of port 0x72
*/
UNIT_TEST_STATUS
EFIAPI
CreateSingleIoPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  SMM_SUPV_SECURE_POLICY_DATA_V1_0           *TestPolicy;
  SMM_SUPV_POLICY_ROOT_V1                    *TestPolicyRoot;
  SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0  *IoPolicy;
  UINT32                                     PolicySize;

  PolicySize = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0) +
               sizeof (SMM_SUPV_POLICY_ROOT_V1) +
               sizeof (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0);

  TestPolicy = AllocatePool (PolicySize);
  CopyMem (TestPolicy, &mTestPolicyTemplate, sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0));
  TestPolicy->PolicyRootCount = 1;
  TestPolicy->Size            = PolicySize;

  TestPolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)(TestPolicy + 1);
  CopyMem (TestPolicyRoot, &mTestPolicyRootTemplate, sizeof (SMM_SUPV_POLICY_ROOT_V1));
  TestPolicyRoot->AccessAttr = SMM_SUPV_ACCESS_ATTR_ALLOW;
  TestPolicyRoot->Count      = 1;
  TestPolicyRoot->Type       = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO;
  TestPolicyRoot->Offset     = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0) + sizeof (SMM_SUPV_POLICY_ROOT_V1);

  IoPolicy                = (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0 *)(TestPolicyRoot + 1);
  IoPolicy->Attributes    = SECURE_POLICY_RESOURCE_ATTR_READ;
  IoPolicy->IoAddress     = 0x72;
  IoPolicy->LengthOrWidth = 1;

  ((TEST_CONTEXT_POLICY *)Context)->Policy = TestPolicy;

  return UNIT_TEST_PASSED;
}

/*
  Helper function to create a test policy with one read-allow MSR entry of 2 contiguous registers starting at 0xC0000080
*/
UNIT_TEST_STATUS
EFIAPI
CreateSingleMsrPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  SMM_SUPV_SECURE_POLICY_DATA_V1_0            *TestPolicy;
  SMM_SUPV_POLICY_ROOT_V1                     *TestPolicyRoot;
  SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0  *MsrPolicy;
  UINT32                                      PolicySize;

  PolicySize = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0) +
               sizeof (SMM_SUPV_POLICY_ROOT_V1) +
               sizeof (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0);

  TestPolicy = AllocatePool (PolicySize);
  CopyMem (TestPolicy, &mTestPolicyTemplate, sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0));
  TestPolicy->PolicyRootCount = 1;
  TestPolicy->Size            = PolicySize;

  TestPolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)(TestPolicy + 1);
  CopyMem (TestPolicyRoot, &mTestPolicyRootTemplate, sizeof (SMM_SUPV_POLICY_ROOT_V1));
  TestPolicyRoot->AccessAttr = SMM_SUPV_ACCESS_ATTR_ALLOW;
  TestPolicyRoot->Count      = 1;
  TestPolicyRoot->Type       = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR;
  TestPolicyRoot->Offset     = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0) + sizeof (SMM_SUPV_POLICY_ROOT_V1);

  MsrPolicy             = (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0 *)(TestPolicyRoot + 1);
  MsrPolicy->Attributes = SECURE_POLICY_RESOURCE_ATTR_READ;
  MsrPolicy->MsrAddress = 0xC0000080;
  MsrPolicy->Length     = 2;

  ((TEST_CONTEXT_POLICY *)Context)->Policy = TestPolicy;

  return UNIT_TEST_PASSED;
}

/*
  Helper function to create a test policy with one execution-allow instruction entry of CLI
*/
UNIT_TEST_STATUS
EFIAPI
CreateSingleInsPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  SMM_SUPV_SECURE_POLICY_DATA_V1_0                    *TestPolicy;
  SMM_SUPV_POLICY_ROOT_V1                             *TestPolicyRoot;
  SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0  *InstructionPolicy;
  UINT32                                              PolicySize;

  PolicySize = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0) +
               sizeof (SMM_SUPV_POLICY_ROOT_V1) +
               sizeof (SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0);

  TestPolicy = AllocatePool (PolicySize);
  CopyMem (TestPolicy, &mTestPolicyTemplate, sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0));
  TestPolicy->PolicyRootCount = 1;
  TestPolicy->Size            = PolicySize;

  TestPolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)(TestPolicy + 1);
  CopyMem (TestPolicyRoot, &mTestPolicyRootTemplate, sizeof (SMM_SUPV_POLICY_ROOT_V1));
  TestPolicyRoot->AccessAttr = SMM_SUPV_ACCESS_ATTR_ALLOW;
  TestPolicyRoot->Count      = 1;
  TestPolicyRoot->Type       = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION;
  TestPolicyRoot->Offset     = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0) + sizeof (SMM_SUPV_POLICY_ROOT_V1);

  InstructionPolicy                   = (SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0 *)(TestPolicyRoot + 1);
  InstructionPolicy->Attributes       = SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
  InstructionPolicy->InstructionIndex = SECURE_POLICY_INSTRUCTION_CLI;

  ((TEST_CONTEXT_POLICY *)Context)->Policy = TestPolicy;

  return UNIT_TEST_PASSED;
}

/*
  Helper function to clean up prepared policy, if needed.
*/
VOID
EFIAPI
ClearTestPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;
  if ((PolicyCntx != NULL) && (PolicyCntx->Policy != NULL)) {
    FreePool (PolicyCntx->Policy);
  }
}

/**
  Unit test for IsIoReadWriteAllowed () API of the SmmPolicyGateLib against allow list.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateMatchEntryOnAllowIoList (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Test IO read on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x72, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test IO write on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x72, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test IO read not on test policy, should fail
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x71, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test IO read not on test policy, should fail
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x71, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for IsIoReadWriteAllowed () API of the SmmPolicyGateLib against deny list.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateMatchEntryOnDenyIoList (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Change the root access attribute to deny list
  ((SMM_SUPV_POLICY_ROOT_V1 *)(PolicyCntx->Policy + 1))->AccessAttr = SMM_SUPV_ACCESS_ATTR_DENY;

  // Test IO read on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x72, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test IO write on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x72, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test IO read not on test policy, should pass
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x71, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test IO read not on test policy, should pass
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0x71, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for IsIoReadWriteAllowed () API of the SmmPolicyGateLib against overflow requests.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateOnOverflowIoRequests (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Test uint32 IO overflow read on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0xFFFD, MM_IO_UINT32, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_INVALID_PARAMETER);

  // Test uint16 IO overflow read on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0xFFFF, MM_IO_UINT16, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_INVALID_PARAMETER);

  // Test uint8 on edge IO write on test policy
  Status = IsIoReadWriteAllowed (PolicyCntx->Policy, 0xFFFF, MM_IO_UINT8, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for IsMsrReadWriteAllowed () API of the SmmPolicyGateLib against allow list.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateMatchEntryOnAllowMsrList (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Test MSR read on test policy
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000080, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test MSR read on test policy in entry range
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000081, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test MSR write on test policy
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000080, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test MSR read on test policy in entry range
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000081, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test MSR read not on test policy, should fail
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0x00000071, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test IO read not on test policy, should fail
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0x00000071, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for IsMsrReadWriteAllowed () API of the SmmPolicyGateLib against deny list.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateMatchEntryOnDenyMsrList (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Change the root access attribute to deny list
  ((SMM_SUPV_POLICY_ROOT_V1 *)(PolicyCntx->Policy + 1))->AccessAttr = SMM_SUPV_ACCESS_ATTR_DENY;

  // Test MSR read on test policy
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000080, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test MSR read on test policy in entry range
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000081, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test MSR write on test policy
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000080, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test MSR read on test policy in entry range
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0xC0000081, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test MSR read not on test policy, should fail
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0x00000071, SECURE_POLICY_RESOURCE_ATTR_READ);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test IO read not on test policy, should fail
  Status = IsMsrReadWriteAllowed (PolicyCntx->Policy, 0x00000071, SECURE_POLICY_RESOURCE_ATTR_WRITE);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for IsInstructionExecutionAllowed () API of the SmmPolicyGateLib against allow list.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateMatchEntryOnAllowInsList (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Test instruction execution on test policy
  Status = IsInstructionExecutionAllowed (PolicyCntx->Policy, SECURE_POLICY_INSTRUCTION_CLI);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  // Test instruction execution not on test policy
  Status = IsInstructionExecutionAllowed (PolicyCntx->Policy, SECURE_POLICY_INSTRUCTION_HLT);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for IsInstructionExecutionAllowed () API of the SmmPolicyGateLib against deny list.

  @param[in]  Context    [Optional] An optional parameter that enables:
                         1) test-case reuse with varied parameters and
                         2) test-case re-entry for Target tests that need a
                         reboot.  This parameter is a VOID* and it is the
                         responsibility of the test author to ensure that the
                         contents are well understood by all test cases that may
                         consume it.

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
**/
UNIT_TEST_STATUS
EFIAPI
PolicyGateMatchEntryOnDenyInsList (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_CONTEXT_POLICY  *PolicyCntx;
  EFI_STATUS           Status;

  PolicyCntx = (TEST_CONTEXT_POLICY *)Context;

  // Change the root access attribute to deny list
  ((SMM_SUPV_POLICY_ROOT_V1 *)(PolicyCntx->Policy + 1))->AccessAttr = SMM_SUPV_ACCESS_ATTR_DENY;

  // Test instruction execution on test policy
  Status = IsInstructionExecutionAllowed (PolicyCntx->Policy, SECURE_POLICY_INSTRUCTION_CLI);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_ACCESS_DENIED);

  // Test instruction execution not on test policy
  Status = IsInstructionExecutionAllowed (PolicyCntx->Policy, SECURE_POLICY_INSTRUCTION_HLT);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  return UNIT_TEST_PASSED;
}

/**
  Initialize the unit test framework, suite, and unit tests for the
  SmmPolicyGateLib and run the SmmPolicyGateLib unit test.

  @retval  EFI_SUCCESS           All test cases were dispatched.
  @retval  EFI_OUT_OF_RESOURCES  There are not enough resources available to
                                 initialize the unit tests.
**/
STATIC
EFI_STATUS
EFIAPI
UnitTestingEntry (
  VOID
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      PolicyGateTests;
  TEST_CONTEXT_POLICY         PolicyContext;

  Framework            = NULL;
  PolicyContext.Policy = NULL;

  DEBUG ((DEBUG_INFO, "%a v%a\n", UNIT_TEST_APP_NAME, UNIT_TEST_APP_VERSION));

  //
  // Start setting up the test framework for running the tests.
  //
  Status = InitUnitTestFramework (&Framework, UNIT_TEST_APP_NAME, gEfiCallerBaseName, UNIT_TEST_APP_VERSION);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }

  //
  // Populate the SmmPolicyGateLib Unit Test Suite.
  //
  Status = CreateUnitTestSuite (&PolicyGateTests, Framework, "SmmPolicyGateLib Request Tests", "SmmPolicyGateLib.Request", NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in CreateUnitTestSuite for PolicyGateTests\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  //
  // --------------Suite-----------Description--------------Name----------Function--------Pre---Post-------------------Context-----------
  //
  AddTestCase (PolicyGateTests, "Policy gate should catch requests listed on allow IO policy", "AllowIO", PolicyGateMatchEntryOnAllowIoList, CreateSingleIoPolicy, ClearTestPolicy, &PolicyContext);
  AddTestCase (PolicyGateTests, "Policy gate should catch requests listed on deny IO policy", "DenyIO", PolicyGateMatchEntryOnDenyIoList, CreateSingleIoPolicy, ClearTestPolicy, &PolicyContext);
  AddTestCase (PolicyGateTests, "Policy gate should catch potentially overflow IO request", "OverflowIO", PolicyGateOnOverflowIoRequests, CreateSingleIoPolicy, ClearTestPolicy, &PolicyContext);
  AddTestCase (PolicyGateTests, "Policy gate should catch requests listed on allow MSR policy", "AllowMsr", PolicyGateMatchEntryOnAllowMsrList, CreateSingleMsrPolicy, ClearTestPolicy, &PolicyContext);
  AddTestCase (PolicyGateTests, "Policy gate should catch requests listed on deny MSR policy", "DenyMsr", PolicyGateMatchEntryOnDenyMsrList, CreateSingleMsrPolicy, ClearTestPolicy, &PolicyContext);
  AddTestCase (PolicyGateTests, "Policy gate should catch requests listed on allow Instruction policy", "AllowIns", PolicyGateMatchEntryOnAllowInsList, CreateSingleInsPolicy, ClearTestPolicy, &PolicyContext);
  AddTestCase (PolicyGateTests, "Policy gate should catch requests listed on deny Instruction policy", "DenyIns", PolicyGateMatchEntryOnDenyInsList, CreateSingleInsPolicy, ClearTestPolicy, &PolicyContext);

  //
  // Execute the tests.
  //
  Status = RunAllTestSuites (Framework);

EXIT:
  if (Framework) {
    FreeUnitTestFramework (Framework);
  }

  return Status;
}

/**
  Standard POSIX C entry point for host based unit test execution.
**/
int
main (
  int   argc,
  char  *argv[]
  )
{
  return UnitTestingEntry ();
}
