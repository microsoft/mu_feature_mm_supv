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
#include <Library/UefiCpuLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "MmPolicyMeasurementLevels.h"

#define UNIT_TEST_APP_NAME     "MM Supervisor Request Test Cases"
#define UNIT_TEST_APP_VERSION  "1.0"

#define UNDEFINED_LEVEL  MAX_UINT32

MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SupvCommunication              = NULL;
VOID                                  *mMmSupvCommonCommBufferAddress = NULL;
UINTN                                 mMmSupvCommonCommBufferSize;

/// ================================================================================================
/// ================================================================================================
///
/// HELPER FUNCTIONS
///
/// ================================================================================================
/// ================================================================================================

/*
  Helper function to check possible policy level on the MSR block
*/
EFI_STATUS
EFIAPI
VerifyMemPolicy (
  IN  VOID    *MemPolicy,
  IN  UINT32  MemPolicyCount,
  IN  UINT32  AccessAttr,
  OUT UINT32  *Level
  );

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
  EFI_MM_COMMUNICATE_HEADER  *CommHeader;
  UINTN                      CommBufferSize;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer not found!\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  // First, let's zero the comm buffer. Couldn't hurt.
  CommHeader     = (EFI_MM_COMMUNICATE_HEADER *)mMmSupvCommonCommBufferAddress;
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
  *CommBuffer = (MM_SUPERVISOR_REQUEST_HEADER *)CommHeader->Data;

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
  EFI_STATUS                 Status = EFI_SUCCESS;
  EFI_MM_COMMUNICATE_HEADER  *CommHeader;
  UINTN                      CommBufferSize;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer not found!\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  // Grab the CommBuffer
  CommHeader     = (EFI_MM_COMMUNICATE_HEADER *)mMmSupvCommonCommBufferAddress;
  CommBufferSize = mMmSupvCommonCommBufferSize;

  // Locate the protocol, if not done yet.
  if (!SupvCommunication) {
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&SupvCommunication);
  }

  // Signal MM.
  if (!EFI_ERROR (Status)) {
    Status = SupvCommunication->Communicate (SupvCommunication, CommHeader, &CommBufferSize);
    DEBUG ((DEBUG_VERBOSE, "[%a] - Communicate() = %r\n", __FUNCTION__, Status));
  }

  return ((MM_SUPERVISOR_REQUEST_HEADER *)CommHeader->Data)->Result;
}

/*
  Helper function to request policy from supervisor
*/
SMM_SUPV_SECURE_POLICY_DATA_V1_0 *
EFIAPI
FetchSecurityPolicyFromSupv (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS                        Status;
  MM_SUPERVISOR_REQUEST_HEADER      *CommBuffer;
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SecurityPolicy;

  SecurityPolicy = NULL;

  // Grab the CommBuffer and fill it in for this test
  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  CommBuffer->Signature = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request   = MM_SUPERVISOR_REQUEST_FETCH_POLICY;
  CommBuffer->Result    = EFI_SUCCESS;

  // This should cause the system to reboot.
  Status = MmSupvRequestDxeToMmCommunicate ();

  if (EFI_ERROR (Status)) {
    // We encountered some errors on our way fetching policy.
    UT_LOG_ERROR ("Supervisor did not successfully returned policy %r.", Status);
  } else {
    SecurityPolicy = (SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)(CommBuffer + 1);
    DUMP_HEX (DEBUG_INFO, 0, SecurityPolicy, SecurityPolicy->Size, "");
  }

  return SecurityPolicy;
}

/*
  Helper function to check possible policy level on the MSR block
*/
EFI_STATUS
EFIAPI
VerifyIoPolicy (
  IN  VOID    *IoPolicy,
  IN  UINT32  IoPolicyCount,
  IN  UINT32  AccessAttr,
  OUT UINT32  *Level
  )
{
  SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0  *IoEntries;
  UINTN                                      Index1;
  UINTN                                      Index2;
  CONST IO_ENTRY                             *ReferenceTable;
  UINTN                                      ReferenceTableSize;
  IO_ENTRY                                   Target;
  BOOLEAN                                    MatchFound;

  if ((IoPolicy == NULL) || (Level == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  IoEntries = (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0 *)IoPolicy;

  // The method is very brute force...

  // First set the level to at most 10, failing everything here
  // will not make it below that value
  *Level = SMM_POLICY_LEVEL_10;

  // Check level 20
  ReferenceTable     = SCPC_LVL20_IO;
  ReferenceTableSize = sizeof (SCPC_LVL20_IO) / sizeof (SCPC_LVL20_IO[0]);

  // Level 20 is a deny list
  for (Index1 = 0; Index1 < ReferenceTableSize; Index1++) {
    Target     = ReferenceTable[Index1];
    MatchFound = FALSE;
    for (Index2 = 0; Index2 < IoPolicyCount; Index2++) {
      if (IoEntries[Index2].Attributes & SECURE_POLICY_RESOURCE_ATTR_STRICT_WIDTH) {
        if ((IoEntries[Index2].IoAddress == Target.IoPortNumber) &&
            (IoEntries[Index2].LengthOrWidth == Target.IoWidth))
        {
          MatchFound = TRUE;
          break;
        }
      } else if ((IoEntries[Index2].IoAddress <= Target.IoPortNumber) &&
                 (IoEntries[Index2].IoAddress + IoEntries[Index2].LengthOrWidth >=
                  Target.IoPortNumber + Target.IoWidth))
      {
        MatchFound = TRUE;
        break;
      }
    }

    if ((MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW)) ||
        (!MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)))
    {
      goto Done;
    } else if (MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) {
      // If it is found in a deny list but the attribute does not block, bail as well
      if ((IoEntries[Index2].Attributes & (SECURE_POLICY_RESOURCE_ATTR_WRITE)) == 0) {
        goto Done;
      }
    }
  }

  // So level 20 passed, set it to at least level 20
  *Level = SMM_POLICY_LEVEL_20;

  // At this point, IO will not prevent the measurement level to be the highest
  *Level = MAX_SUPPORTED_LEVEL;

Done:
  return EFI_SUCCESS;
}

/*
  Helper function to check possible policy level on the MSR block
*/
EFI_STATUS
EFIAPI
VerifyMsrPolicy (
  IN  VOID    *MsrPolicy,
  IN  UINT32  MsrPolicyCount,
  IN  UINT32  AccessAttr,
  OUT UINT32  *Level
  )
{
  SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0  *MsrEntries;
  UINTN                                       Index1;
  UINTN                                       Index2;
  CONST UINT64                                *ReferenceTable;
  UINTN                                       ReferenceTableSize;
  UINT64                                      Target;
  BOOLEAN                                     MatchFound;

  if ((MsrPolicy == NULL) || (Level == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  MsrEntries = (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0 *)MsrPolicy;

  // The method is very brute force...

  // First set the level to at most 10, failing everything here
  // will not make it below that value
  *Level = SMM_POLICY_LEVEL_10;

  // Check level 20
  if (StandardSignatureIsAuthenticAMD ()) {
    ReferenceTable     = SCPC_LVL20_MSR_AMD;
    ReferenceTableSize = sizeof (SCPC_LVL20_MSR_AMD) / sizeof (SCPC_LVL20_MSR_AMD[0]);
  } else {
    ReferenceTable     = SCPC_LVL20_MSR_INTEL;
    ReferenceTableSize = sizeof (SCPC_LVL20_MSR_INTEL) / sizeof (SCPC_LVL20_MSR_INTEL[0]);
  }

  // Level 20 is a deny list
  for (Index1 = 0; Index1 < ReferenceTableSize; Index1++) {
    Target     = ReferenceTable[Index1];
    MatchFound = FALSE;
    for (Index2 = 0; Index2 < MsrPolicyCount; Index2++) {
      if ((MsrEntries[Index2].MsrAddress <= Target) &&
          (MsrEntries[Index2].MsrAddress + MsrEntries[Index2].Length > Target))
      {
        MatchFound = TRUE;
        break;
      }
    }

    if ((MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW)) ||
        (!MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)))
    {
      goto Done;
    } else if (MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) {
      // If it is found in a deny list but the attribute does not block, bail as well
      if ((MsrEntries[Index2].Attributes & (SECURE_POLICY_RESOURCE_ATTR_READ | SECURE_POLICY_RESOURCE_ATTR_WRITE)) !=
          (SECURE_POLICY_RESOURCE_ATTR_READ | SECURE_POLICY_RESOURCE_ATTR_WRITE))
      {
        goto Done;
      }
    }
  }

  // So level 20 passed, set it to at least level 20
  *Level = SMM_POLICY_LEVEL_20;

  if (StandardSignatureIsAuthenticAMD ()) {
    ReferenceTable     = SCPC_LVL30_MSR_AMD;
    ReferenceTableSize = sizeof (SCPC_LVL30_MSR_AMD) / sizeof (SCPC_LVL30_MSR_AMD[0]);
  } else {
    ReferenceTable     = SCPC_LVL30_MSR_INTEL;
    ReferenceTableSize = sizeof (SCPC_LVL30_MSR_INTEL) / sizeof (SCPC_LVL30_MSR_INTEL[0]);
  }

  // Level 30 is also a deny list
  for (Index1 = 0; Index1 < ReferenceTableSize; Index1++) {
    Target     = ReferenceTable[Index1];
    MatchFound = FALSE;
    for (Index2 = 0; Index2 < MsrPolicyCount; Index2++) {
      if ((MsrEntries[Index2].MsrAddress <= Target) &&
          (MsrEntries[Index2].MsrAddress + MsrEntries[Index2].Length > Target))
      {
        MatchFound = TRUE;
        break;
      }
    }

    if ((MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW)) ||
        (!MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)))
    {
      goto Done;
    } else if (MatchFound && (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) {
      // If it is found in a deny list but the attribute does not block, bail as well
      if ((MsrEntries[Index2].Attributes & (SECURE_POLICY_RESOURCE_ATTR_READ | SECURE_POLICY_RESOURCE_ATTR_WRITE)) !=
          (SECURE_POLICY_RESOURCE_ATTR_READ | SECURE_POLICY_RESOURCE_ATTR_WRITE))
      {
        goto Done;
      }
    }
  }

  // And level 30 passed, set it to at least level 30
  *Level = SMM_POLICY_LEVEL_30;

  // At this point, MSR will not prevent the measurement level to be the highest
  *Level = MAX_SUPPORTED_LEVEL;

Done:
  return EFI_SUCCESS;
}

/*
  Helper function to check possible policy level on the Save State block
*/
EFI_STATUS
EFIAPI
VerifySvstPolicy (
  IN  VOID    *SvstPolicy,
  IN  UINT32  SvstPolicyCount,
  IN  UINT32  AccessAttr,
  OUT UINT32  *Level
  )
{
  SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0  *SvstEntries;
  UINTN                                              Index;

  if ((SvstPolicy == NULL) || (Level == NULL) || (AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) {
    return EFI_INVALID_PARAMETER;
  }

  SvstEntries = (SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0 *)SvstPolicy;

  // The method is very brute force...

  // First set the level to at most 20, failing everything here
  // will not make it below that value
  *Level = SMM_POLICY_LEVEL_20;

  // Level 20 is a deny list
  for (Index = 0; Index < SvstPolicyCount; Index++) {
    if ((SvstEntries[Index].MapField == SECURE_POLICY_SVST_IO_TRAP) &&
        (SvstEntries[Index].Attributes == SECURE_POLICY_RESOURCE_ATTR_READ))
    {
      continue;
    }

    if ((SvstEntries[Index].MapField == SECURE_POLICY_SVST_RAX) &&
        (SvstEntries[Index].Attributes == SECURE_POLICY_RESOURCE_ATTR_COND_READ) &&
        (SvstEntries[Index].AccessCondition == SECURE_POLICY_SVST_CONDITION_IO_WR))
    {
      continue;
    }

    if ((SvstEntries[Index].MapField == SECURE_POLICY_SVST_RAX) &&
        (SvstEntries[Index].Attributes == SECURE_POLICY_RESOURCE_ATTR_COND_WRITE) &&
        (SvstEntries[Index].AccessCondition == SECURE_POLICY_SVST_CONDITION_IO_RD))
    {
      continue;
    }

    goto Done;
  }

  // So level 30 passed, set it to at least level 30
  *Level = SMM_POLICY_LEVEL_30;

  // At this point, IO will not prevent the measurement level to be the highest
  *Level = MAX_SUPPORTED_LEVEL;

Done:
  return EFI_SUCCESS;
}

/// ================================================================================================
/// ================================================================================================
///
/// PRE REQ FUNCTIONS
///
/// ================================================================================================
/// ================================================================================================

UNIT_TEST_STATUS
EFIAPI
LocateMmCommonCommBuffer (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    // Locate the communication buffer, if not done yet.
    if (!SupvCommunication) {
      Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&SupvCommunication);
    }

    UT_ASSERT_NOT_EFI_ERROR (Status);

    // Use virtual start will be identical to physical start till translate event
    mMmSupvCommonCommBufferAddress = (VOID *)SupvCommunication->CommunicationRegion.VirtualStart;
    mMmSupvCommonCommBufferSize    = EFI_PAGES_TO_SIZE (SupvCommunication->CommunicationRegion.NumberOfPages);
  }

  return UNIT_TEST_PASSED;
} // LocateMmCommonCommBuffer()

/// ================================================================================================
/// ================================================================================================
///
/// CLEANUP FUNCTIONS
///
/// ================================================================================================
/// ================================================================================================

/// ================================================================================================
/// ================================================================================================
///
/// TEST CASES
///
/// ================================================================================================
/// ================================================================================================

/*
  Test case to request version information from supervisor
*/
UNIT_TEST_STATUS
EFIAPI
RequestVersionInfo (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS                         Status;
  MM_SUPERVISOR_REQUEST_HEADER       *CommBuffer;
  MM_SUPERVISOR_VERSION_INFO_BUFFER  *VersionInfo;

  // Grab the CommBuffer and fill it in for this test
  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  CommBuffer->Signature = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request   = MM_SUPERVISOR_REQUEST_VERSION_INFO;
  CommBuffer->Result    = EFI_SUCCESS;

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
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS                    Status;
  MM_SUPERVISOR_REQUEST_HEADER  *CommBuffer;
  EFI_MEMORY_DESCRIPTOR         *MemDesc;
  VOID                          *TargetPage;

  TargetPage = AllocatePages (1);
  if (TargetPage == NULL) {
    UT_LOG_ERROR ("Target memory allocation failed.");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  // Grab the CommBuffer and fill it in for this test
  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  CommBuffer->Signature = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request   = MM_SUPERVISOR_REQUEST_UNBLOCK_MEM;
  CommBuffer->Result    = EFI_SUCCESS;

  MemDesc                = (EFI_MEMORY_DESCRIPTOR *)(CommBuffer + 1);
  MemDesc->NumberOfPages = 1;
  MemDesc->PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)TargetPage;
  MemDesc->Attribute     = 0;

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
  IN UNIT_TEST_CONTEXT  Context
  )
{
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SecurityPolicy;

  SecurityPolicy = FetchSecurityPolicyFromSupv (Context);

  UT_ASSERT_NOT_NULL (SecurityPolicy);

  return UNIT_TEST_PASSED;
}

/*
  Test case to inspect requested policy
*/
UNIT_TEST_STATUS
EFIAPI
InspectSecurityPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SecurityPolicy;
  SMM_SUPV_POLICY_ROOT_V1           *PolicyRoot;
  EFI_STATUS                        Status;
  UINTN                             Index0;
  UINT32                            MsrLevel;
  UINT32                            IoLevel;
  UINT32                            MemLevel;
  UINT32                            SvstLevel;
  UINT32                            FinalLevel;

  MsrLevel   = UNDEFINED_LEVEL;
  IoLevel    = UNDEFINED_LEVEL;
  MemLevel   = UNDEFINED_LEVEL;
  SvstLevel  = UNDEFINED_LEVEL;
  FinalLevel = 0;

  SecurityPolicy = FetchSecurityPolicyFromSupv (Context);

  UT_ASSERT_NOT_NULL (SecurityPolicy);

  UT_ASSERT_EQUAL (SecurityPolicy->VersionMajor, 0x0001);

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SecurityPolicy + SecurityPolicy->PolicyRootOffset);
  for (Index0 = 0; Index0 < SecurityPolicy->PolicyRootCount; Index0++) {
    if ((PolicyRoot[Index0].AccessAttr != SMM_SUPV_ACCESS_ATTR_ALLOW) &&
        (PolicyRoot[Index0].AccessAttr != SMM_SUPV_ACCESS_ATTR_DENY))
    {
      continue;
    }

    switch (PolicyRoot[Index0].Type) {
      case SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO:
        if (IoLevel != UNDEFINED_LEVEL) {
          Status = EFI_ALREADY_STARTED;
          break;
        }

        Status = VerifyIoPolicy ((UINT8 *)SecurityPolicy + PolicyRoot[Index0].Offset, PolicyRoot[Index0].Count, PolicyRoot[Index0].AccessAttr, &IoLevel);
        break;
      case SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR:
        if (MsrLevel != UNDEFINED_LEVEL) {
          Status = EFI_ALREADY_STARTED;
          break;
        }

        Status = VerifyMsrPolicy ((UINT8 *)SecurityPolicy + PolicyRoot[Index0].Offset, PolicyRoot[Index0].Count, PolicyRoot[Index0].AccessAttr, &MsrLevel);
        break;
      case SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM:
        if (MemLevel != UNDEFINED_LEVEL) {
          Status = EFI_ALREADY_STARTED;
          break;
        }

        Status = VerifyMemPolicy ((UINT8 *)SecurityPolicy + PolicyRoot[Index0].Offset, PolicyRoot[Index0].Count, PolicyRoot[Index0].AccessAttr, &MemLevel);
        break;
      case SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE:
        if (SvstLevel != UNDEFINED_LEVEL) {
          Status = EFI_ALREADY_STARTED;
          break;
        }

        Status = VerifySvstPolicy ((UINT8 *)SecurityPolicy + PolicyRoot[Index0].Offset, PolicyRoot[Index0].Count, PolicyRoot[Index0].AccessAttr, &SvstLevel);
        break;
      default:
        // Do nothing
        break;
    }

    if (EFI_ERROR (Status)) {
      // Should not happen, if so, bail the test
      DEBUG ((DEBUG_ERROR, "%a Failed to verify %x type entries - %r\n", __FUNCTION__, PolicyRoot[Index0].Type, Status));
      UT_ASSERT_NOT_EFI_ERROR (Status);
      break;
    }
  }

  if (MemLevel == UNDEFINED_LEVEL) {
    // Without specifying above, at most get level 0
    goto Done;
  }

  FinalLevel = MemLevel;

  if ((IoLevel == UNDEFINED_LEVEL) || (MsrLevel == UNDEFINED_LEVEL)) {
    // Without specifying above, at most get level 10
    FinalLevel = MIN (FinalLevel, SMM_POLICY_LEVEL_10);
    goto Done;
  }

  FinalLevel = MIN (FinalLevel, IoLevel);
  FinalLevel = MIN (FinalLevel, MsrLevel);

  if (SvstLevel == UNDEFINED_LEVEL) {
    // Without specifying above, at most get level 20
    FinalLevel = MIN (FinalLevel, SMM_POLICY_LEVEL_20);
    goto Done;
  }

  FinalLevel = MIN (FinalLevel, SvstLevel);

Done:
  DEBUG ((DEBUG_INFO, "The fetch policy is at level %d\n", FinalLevel));
  UT_LOG_INFO ("The fetch policy is at level %d", FinalLevel);

  // If we can get policy but still get 0 mm measurement level, something is messed up...
  UT_ASSERT_TRUE (FinalLevel > 0);

  return UNIT_TEST_PASSED;
}

/// ================================================================================================
/// ================================================================================================
///
/// TEST ENGINE
///
/// ================================================================================================
/// ================================================================================================

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
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status = EFI_ABORTED;
  UNIT_TEST_FRAMEWORK_HANDLE  Fw     = NULL;
  UNIT_TEST_SUITE_HANDLE      Misc   = NULL;

  DEBUG ((DEBUG_ERROR, "%a enter\n", __FUNCTION__));

  DEBUG ((DEBUG_ERROR, "%a %a v%a\n", __FUNCTION__, UNIT_TEST_APP_NAME, UNIT_TEST_APP_VERSION));

  // Start setting up the test framework for running the tests.
  Status = InitUnitTestFramework (&Fw, UNIT_TEST_APP_NAME, gEfiCallerBaseName, UNIT_TEST_APP_VERSION);
  if (EFI_ERROR (Status) != FALSE) {
    DEBUG ((DEBUG_ERROR, "%a Failed in InitUnitTestFramework. Status = %r\n", __FUNCTION__, Status));
    goto Cleanup;
  }

  // Misc test suite for all tests.
  CreateUnitTestSuite (&Misc, Fw, "MM Supervisor Request Test cases", "MmSupv.Miscellaneous", NULL, NULL);

  if (Misc == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Failed in CreateUnitTestSuite for TestSuite\n", __FUNCTION__));
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  AddTestCase (
    Misc,
    "Checksum calculation test",
    "MmSupv.Miscellaneous.MmSupvReqestVersion",
    RequestVersionInfo,
    LocateMmCommonCommBuffer,
    NULL,
    NULL
    );
  AddTestCase (
    Misc,
    "Memory unblock test",
    "MmSupv.Miscellaneous.MmSupvReqestUnblockMemory",
    RequestUnblockRegion,
    LocateMmCommonCommBuffer,
    NULL,
    NULL
    );
  AddTestCase (
    Misc,
    "Policy request test",
    "MmSupv.Miscellaneous.MmSupvReqestPolicy",
    RequestSecurityPolicy,
    LocateMmCommonCommBuffer,
    NULL,
    NULL
    );
  AddTestCase (
    Misc,
    "Policy security inspection",
    "MmSupv.Miscellaneous.MmSupvPolicyInspection",
    InspectSecurityPolicy,
    LocateMmCommonCommBuffer,
    NULL,
    NULL
    );

  //
  // Execute the tests.
  //
  Status = RunAllTestSuites (Fw);

Cleanup:
  if (Fw != NULL) {
    FreeUnitTestFramework (Fw);
  }

  DEBUG ((DEBUG_ERROR, "%a exit\n", __FUNCTION__));
  return Status;
} // MmSupvRequestUnitTestAppEntryPoint ()
