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

#define MEM_POLICY_SNAPSHOT_SIZE  0x400   // 1K should be more than enough to describe allowed non-MMRAM regions

/**
  Dump a single memory policy data.
**/
VOID
EFIAPI
DumpMemPolicyEntry (
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemoryPolicy
  );

/**
  Helper function that populates memory policy on demands.

  @param[in] SmmPolicyBuffer   Input buffer points to the entire v1.0 policy.
  @param[in] MaxPolicySize     Maximum size of the policy buffer.
  @param[in] Cr3               CR3 value to be converted, if input is zero, check the real HW register.

  @param[in] CpuIndex Logical number assigned to CPU.
**/
EFI_STATUS
EFIAPI
PopulateMemoryPolicyEntries (
  IN  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyBuffer,
  IN  UINT64                            MaxPolicySize,
  IN  UINT64                            Cr3
  );

/**
  Compare memory policy in two SmmPolicy.

  @param  SmmPolicyData1    The first data to compare.
  @param  SmmPolicyData2    The second data to compare.

  @retval FALSE       If two memory policy not identical.

**/
BOOLEAN
EFIAPI
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
EFIAPI
PrepareMemPolicySnapshot (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *MemPolicySnapshot
  );

/**
  Allocate a static buffer for taking snapshot of memory policy when we lock down page table.

  @retval EFI_SUCCESS               Buffer is allocated properly.
  @retval EFI_OUT_OF_RESOURCES      Cannot allocate enough resources for snapshot.
**/
EFI_STATUS
EFIAPI
AllocateMemForPolicySnapshot (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  **MemPolicySnapshot
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
EFIAPI
SecurityPolicyCheck (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy
  );

/**
  Dump the smm policy data.
**/
VOID
EFIAPI
DumpSmmPolicyData (
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *Data
  );

#endif // _MM_SUPV_POLICY_H_
