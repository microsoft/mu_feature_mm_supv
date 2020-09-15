/** @file
Include file for MM Supervisor policy related implementation.

Copyright (c) 2011 - 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_POLICY_H_
#define _MM_SUPV_POLICY_H_

#include <SmmSecurePolicy.h>

extern SMM_SUPV_SECURE_POLICY_DATA_V1_0  *FirmwarePolicy;
extern SMM_SUPV_SECURE_POLICY_DATA_V1_0  *MemPolicySnapshot;

/**
  Dump a single memory policy data.
**/
VOID
DumpMemPolicyEntry (
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemoryPolicy
  );

/**
  Helper function that populates memory policy on demands.

  @param[in] SmmPolicyBuffer   Input buffer points to the entire v1.0 policy.
  @param[in] Cr3               CR3 value to be converted, if input is zero, check the real HW register.

  @param[in] CpuIndex Logical number assigned to CPU.
**/
EFI_STATUS
EFIAPI
PopulateMemoryPolicyEntries (
  IN  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyBuffer,
  IN  UINT64                            MaxPolicySize
  );

/**
  Compare memory policy in two SmmPolicy.

  @param  SmmPolicyData1    The first data to compare.
  @param  SmmPolicyData2    The second data to compare.

  @retval FALSE       If two memory policy not identical.

**/
BOOLEAN
CompareMemoryPolicy (
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyData1,
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyData2
  );

/**
  Prepare a snapshot of memory policy, this will be compared against the one generated when requested.

  @retval EFI_SUCCESS               The security policy is successfully gathered.
  @retval EFI_NOT_STARTED           No memory policy snapshot buffer prepared.
  @retval Errors                    Other error during populating memory errors.
**/
EFI_STATUS
PrepareMemPolicySnapshot (
  VOID
  );

/**
  Allocate a static buffer for taking snapshot of memory policy when we lock down page table.

  @retval EFI_SUCCESS               Buffer is allocated properly.
  @retval EFI_OUT_OF_RESOURCES      Cannot allocate enough resources for snapshot.
**/
EFI_STATUS
AllocateMemForPolicySnapshot (
  VOID
  );

/**
  Policy validity check for a given security policy. Check covers policy range
  overlap, policy entry header type mismatch, etc.

  @param[in]  SmmSecurityPolicy - The address of applied SMM secure policy.

  @retval EFI_SECURITY_VIOLATION  The supplied policy failed checking due to
                                  overlapping, type mismatch, etc.
          EFI_INVALID_PARAMETER   The supplied policy pointer is a null pointer.
          EFI_SUCCESS             The supplied policy has passed supervisor
                                  checking.
**/
EFI_STATUS
SecurityPolicyCheck (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy
  );

/**
  Dump the smm policy data.
**/
VOID
DumpSmmPolicyData (
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *Data
  );

/**
  Routine for initializing policy data provided by firmware.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval Errors                The supervisor is unable to locate or protect the policy from firmware.

**/
EFI_STATUS
InitializePolicy (
  VOID
  );

#endif // _MM_SUPV_POLICY_H_
