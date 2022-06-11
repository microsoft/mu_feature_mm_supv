/** @file -- MmSupvRequestUnitTestApp.c

Tests for MM SUPV request operations.

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <SmmSecurePolicy.h>

#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/MmSupervisorRequestData.h>

#include <Protocol/MmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UnitTestLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define UNIT_TEST_APP_NAME        "MM Supervisor Request Test Cases"
#define UNIT_TEST_APP_VERSION     "1.0"

MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SupvCommunication = NULL;
VOID      *mMmSupvCommonCommBufferAddress = NULL;
UINTN     mMmSupvCommonCommBufferSize;

///================================================================================================
///================================================================================================
///
/// HELPER FUNCTIONS
///
///================================================================================================
///================================================================================================

/**
  This helper function preps the shared CommBuffer for use by the test step.

  @param[out] CommBuffer   Returns a pointer to the CommBuffer for the test step to use.

  @retval     EFI_SUCCESS         CommBuffer initialized and ready to use.
  @retval     EFI_ABORTED         Some error occurred.

**/
STATIC
EFI_STATUS
MmSupvRequestGetCommBuffer (
  OUT  MM_SUPERVISOR_REQUEST_HEADER  **CommBuffer
  )
{
  EFI_MM_COMMUNICATE_HEADER               *CommHeader;
  UINTN                                   CommBufferSize;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer not found!\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  // First, let's zero the comm buffer. Couldn't hurt.
  CommHeader = (EFI_MM_COMMUNICATE_HEADER*)mMmSupvCommonCommBufferAddress;
  CommBufferSize = sizeof (MM_SUPERVISOR_REQUEST_HEADER) + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  if (CommBufferSize > mMmSupvCommonCommBufferSize) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer is too small!\n", __FUNCTION__));
    return EFI_ABORTED;
  }
  ZeroMem (CommHeader, CommBufferSize);

  // MM Communication Parameters
  CopyGuid (&CommHeader->HeaderGuid, &gMmSupervisorRequestHandlerGuid);
  CommHeader->MessageLength = sizeof (MM_SUPERVISOR_REQUEST_HEADER);

  // Return a pointer to the CommBuffer for the test to modify.
  *CommBuffer = (MM_SUPERVISOR_REQUEST_HEADER*)CommHeader->Data;

  return EFI_SUCCESS;
}

/**
  This helper function actually sends the requested communication
  to the MM driver.

  @retval     EFI_SUCCESS         Communication was successful.
  @retval     EFI_ABORTED         Some error occurred.

**/
STATIC
EFI_STATUS
MmSupvRequestDxeToMmCommunicate (
  VOID
  )
{
  EFI_STATUS                                    Status = EFI_SUCCESS;
  EFI_MM_COMMUNICATE_HEADER                     *CommHeader;
  UINTN                                         CommBufferSize;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer not found!\n" , __FUNCTION__));
    return EFI_ABORTED;
  }

  // Grab the CommBuffer
  CommHeader = (EFI_MM_COMMUNICATE_HEADER*)mMmSupvCommonCommBufferAddress;
  CommBufferSize = mMmSupvCommonCommBufferSize;

  // Locate the protocol, if not done yet.
  if (!SupvCommunication) {
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID**)&SupvCommunication);
  }

  // Signal MM.
  if (!EFI_ERROR (Status)) {
    Status = SupvCommunication->Communicate (SupvCommunication, CommHeader, &CommBufferSize);
    DEBUG ((DEBUG_VERBOSE, "[%a] - Communicate() = %r\n", __FUNCTION__, Status));
  }

  return ((MM_SUPERVISOR_REQUEST_HEADER *)CommHeader->Data)->Result;
}

///================================================================================================
///================================================================================================
///
/// PRE REQ FUNCTIONS
///
///================================================================================================
///================================================================================================

UNIT_TEST_STATUS
EFIAPI
LocateMmCommonCommBuffer (
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS                                Status;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    // Locate the communication buffer, if not done yet.
    if (!SupvCommunication) {
      Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID**)&SupvCommunication);
    }

    UT_ASSERT_NOT_EFI_ERROR (Status);

    // Use virtual start will be identical to physical start till translate event
    mMmSupvCommonCommBufferAddress = (VOID*)SupvCommunication->CommunicationRegion.VirtualStart;
    mMmSupvCommonCommBufferSize = EFI_PAGES_TO_SIZE (SupvCommunication->CommunicationRegion.NumberOfPages);
  }

  return UNIT_TEST_PASSED;
} // LocateMmCommonCommBuffer()

///================================================================================================
///================================================================================================
///
/// CLEANUP FUNCTIONS
///
///================================================================================================
///================================================================================================



///================================================================================================
///================================================================================================
///
/// TEST CASES
///
///================================================================================================
///================================================================================================

/*
  Test case to request version information from supervisor
*/
UNIT_TEST_STATUS
EFIAPI
RequestVersionInfo (
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS  Status;
  MM_SUPERVISOR_REQUEST_HEADER *CommBuffer;
  MM_SUPERVISOR_VERSION_INFO_BUFFER *VersionInfo;

  // Grab the CommBuffer and fill it in for this test
  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  CommBuffer->Signature  = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision   = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request    = MM_SUPERVISOR_REQUEST_VERSION_INFO;
  CommBuffer->Result     = EFI_SUCCESS;

  // This should cause the system to reboot.
  Status = MmSupvRequestDxeToMmCommunicate ();

  if (EFI_ERROR (Status)) {
    // We encountered some errors on our way fetching version information.
    UT_LOG_ERROR ("Supervisor did not successfully returned version info %r.", Status);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  // Get the real handler status code
  if ((UINTN)CommBuffer->Result != 0) {
    Status = ENCODE_ERROR ((UINTN)CommBuffer->Result);
  }
  UT_ASSERT_NOT_EFI_ERROR (Status);

  VersionInfo = (MM_SUPERVISOR_VERSION_INFO_BUFFER *)(CommBuffer + 1);
  UT_ASSERT_EQUAL (VersionInfo->MaxSupervisorRequestLevel, MM_SUPERVISOR_REQUEST_MAX_SUPPORTED);

  UT_LOG_INFO ("Supervisor version %x, patch level %x.", VersionInfo->Version, VersionInfo->PatchLevel);

  return UNIT_TEST_PASSED;
}

/*
  Test case to request unblocking memory from supervisor
*/
UNIT_TEST_STATUS
EFIAPI
RequestUnblockRegion (
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS  Status;
  MM_SUPERVISOR_REQUEST_HEADER  *CommBuffer;
  EFI_MEMORY_DESCRIPTOR         *MemDesc;
  VOID  *TargetPage;

  TargetPage = AllocatePages (1);
  if (TargetPage == NULL) {
    UT_LOG_ERROR ("Target memory allocation failed.");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  // Grab the CommBuffer and fill it in for this test
  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  CommBuffer->Signature  = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision   = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request    = MM_SUPERVISOR_REQUEST_UNBLOCK_MEM;
  CommBuffer->Result     = EFI_SUCCESS;

  MemDesc = (EFI_MEMORY_DESCRIPTOR*)(CommBuffer + 1);
  MemDesc->NumberOfPages = 1;
  MemDesc->PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)TargetPage;
  MemDesc->Attribute = 0;

  // This should cause the system to reboot.
  Status = MmSupvRequestDxeToMmCommunicate ();

  if (EFI_ERROR (Status)) {
    // We encountered some MM systematic errors on our way unblocking memory.
    UT_LOG_ERROR ("Supervisor did not successfully returned policy %r.", Status);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  // This unit test runs in shell, which is past unblock window (ready to lock)
  UT_ASSERT_STATUS_EQUAL (CommBuffer->Result, EFI_ACCESS_DENIED);

  return UNIT_TEST_PASSED;
}

/*
  Test case to request policy from supervisor
*/
UNIT_TEST_STATUS
EFIAPI
RequestSecurityPolicy (
  IN UNIT_TEST_CONTEXT           Context
  )
{
  EFI_STATUS  Status;
  MM_SUPERVISOR_REQUEST_HEADER *CommBuffer;
  SMM_SUPV_SECURE_POLICY_DATA_V1_0 *SecurityPolicy;

  // Grab the CommBuffer and fill it in for this test
  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  CommBuffer->Signature  = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision   = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request    = MM_SUPERVISOR_REQUEST_FETCH_POLICY;
  CommBuffer->Result     = EFI_SUCCESS;

  // This should cause the system to reboot.
  Status = MmSupvRequestDxeToMmCommunicate ();

  if (EFI_ERROR (Status)) {
    // We encountered some errors on our way fetching policy.
    UT_LOG_ERROR ("Supervisor did not successfully returned policy %r.", Status);
  }
  else {
    SecurityPolicy = (SMM_SUPV_SECURE_POLICY_DATA_V1_0*) (CommBuffer + 1);
    DUMP_HEX (DEBUG_INFO, 0, SecurityPolicy, SecurityPolicy->Size, "");
  }

  UT_ASSERT_NOT_EFI_ERROR (Status);

  return UNIT_TEST_PASSED;
}

///================================================================================================
///================================================================================================
///
/// TEST ENGINE
///
///================================================================================================
///================================================================================================

/**
  MmSupvRequestUnitTestAppEntryPoint

  @param[in] ImageHandle              The firmware allocated handle for the EFI image.
  @param[in] SystemTable              A pointer to the EFI System Table.

  @retval EFI_SUCCESS                 The entry point executed successfully.
  @retval other                       Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmSupvRequestUnitTestAppEntryPoint (
  IN EFI_HANDLE                       ImageHandle,
  IN EFI_SYSTEM_TABLE                 *SystemTable
  )
{
  EFI_STATUS                  Status = EFI_ABORTED;
  UNIT_TEST_FRAMEWORK_HANDLE  Fw = NULL;
  UNIT_TEST_SUITE_HANDLE      Misc = NULL;

  DEBUG((DEBUG_ERROR, "%a enter\n", __FUNCTION__));

  DEBUG(( DEBUG_ERROR, "%a %a v%a\n", __FUNCTION__, UNIT_TEST_APP_NAME, UNIT_TEST_APP_VERSION ));

  // Start setting up the test framework for running the tests.
  Status = InitUnitTestFramework( &Fw, UNIT_TEST_APP_NAME, gEfiCallerBaseName, UNIT_TEST_APP_VERSION );
  if (EFI_ERROR(Status) != FALSE) {
    DEBUG((DEBUG_ERROR, "%a Failed in InitUnitTestFramework. Status = %r\n", __FUNCTION__, Status));
    goto Cleanup;
  }

  // Misc test suite for all tests.
  CreateUnitTestSuite( &Misc, Fw, "MM Supervisor Request Test cases", "MmSupv.Miscellaneous", NULL, NULL);

  if (Misc == NULL) {
    DEBUG((DEBUG_ERROR, "%a Failed in CreateUnitTestSuite for TestSuite\n", __FUNCTION__));
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  AddTestCase(Misc, "Checksum calculation test", "MmSupv.Miscellaneous.MmSupvReqestVersion",
              RequestVersionInfo, LocateMmCommonCommBuffer, NULL, NULL );
  AddTestCase(Misc, "Memory unblock test", "MmSupv.Miscellaneous.MmSupvReqestUnblockMemory",
              RequestUnblockRegion, LocateMmCommonCommBuffer, NULL, NULL );
  AddTestCase(Misc, "Policy request test", "MmSupv.Miscellaneous.MmSupvReqestPolicy",
              RequestSecurityPolicy, LocateMmCommonCommBuffer, NULL, NULL );

  //
  // Execute the tests.
  //
  Status = RunAllTestSuites(Fw);

Cleanup:
  if (Fw != NULL) {
    FreeUnitTestFramework(Fw);
  }
  DEBUG((DEBUG_ERROR, "%a exit\n", __FUNCTION__));
  return Status;
} // MmSupvRequestUnitTestAppEntryPoint ()
