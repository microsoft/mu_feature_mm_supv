/** @file

  Provides SMM policy verification.

  Copyright (C) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SMM_POLICY_GATE_H__
#define __SMM_POLICY_GATE_H__

/**
  Given an IO port address and size, determine if the request is allowed by
  our policy.

  @param[in]  SmmSecurityPolicy - The address of applied SMM secure policy.
  @param[in]  IoAddress         - The address of the IO port.
  @param[in]  IoWidth           - The size of the requested access, has to
                                  be one type from EFI_MM_IO_WIDTH.
  @param[in]  AccessMask        - One of SECURE_POLICY_RESOURCE_ATTR_READ or
                                  SECURE_POLICY_RESOURCE_ATTR_WRITE.

  @retval EFI_ACCESS_DENIED     The requested operation is not allowed by
                                the policy.
          EFI_INVALID_PARAMETER The AccessMask needs to be either
                                SECURE_POLICY_RESOURCE_ATTR_READ or
                                SECURE_POLICY_RESOURCE_ATTR_WRITE.
          EFI_SUCCESS           The requested operation is allowed by the
                                policy.
**/
EFI_STATUS
EFIAPI
IsIoReadWriteAllowed (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy,
  IN UINT32                            IoAddress,
  IN EFI_MM_IO_WIDTH                   IoWidth,
  IN UINT32                            AccessMask
  );

/**
  Given an MSR Address and an access mask, determine if it is within policy to
  allow access to the register specified.

  @param[in]  SmmSecurityPolicy - The address of applied SMM secure policy.
  @param[in]  MsrAddress        - The address of the IO port.
  @param[in]  AccessMask        - One of SECURE_POLICY_RESOURCE_ATTR_READ or
                                  SECURE_POLICY_RESOURCE_ATTR_WRITE.

  @retval EFI_ACCESS_DENIED     The requested operation is not allowed by
                                the policy.
          EFI_INVALID_PARAMETER The AccessMask needs to be either
                                SECURE_POLICY_RESOURCE_ATTR_READ or
                                SECURE_POLICY_RESOURCE_ATTR_WRITE.
          EFI_SUCCESS           The requested operation is allowed by the
                                policy.
**/
EFI_STATUS
EFIAPI
IsMsrReadWriteAllowed (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy,
  IN UINT32                            MsrAddress,
  IN UINT32                            AccessMask
  );

/**
  Given an instruction index defined in SECURE_POLICY_INSTRUCTION, determine if
  it is within policy to allow execution.

  @param[in]  SmmSecurityPolicy - The address of applied SMM secure policy.
  @param[in]  InstructionIndex  - The instruction index defined in
                                  SECURE_POLICY_INSTRUCTION.

  @retval EFI_ACCESS_DENIED     The requested operation is not whitelisted by
                                the policy.
          EFI_INVALID_PARAMETER The InstructionIndex needs to be within the
                                range of [0, SECURE_POLICY_INSTRUCTION_COUNT).
          EFI_SUCCESS           The requested operation is allowed by the
                                policy.
**/
EFI_STATUS
EFIAPI
IsInstructionExecutionAllowed (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy,
  IN UINT16                            InstructionIndex
  );

/**
  Given a save state index defined in SECURE_POLICY_SVST, determine if it is
  within policy to allow execution.

  @param[in]  SmmSecurityPolicy - The address of applied SMM secure policy.
  @param[in]  SaveStateMapField - The instruction index defined in
                                  SECURE_POLICY_SVST.

  @retval EFI_ACCESS_DENIED     The requested operation is not whitelisted by
                                the policy.
          EFI_INVALID_PARAMETER The SaveStateMapField needs to be within the
                                range of [0, SECURE_POLICY_INSTRUCTION_COUNT).
          EFI_SUCCESS           The requested operation is allowed by the
                                policy.
**/
EFI_STATUS
EFIAPI
IsSaveStateWriteAllowed (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy,
  IN UINT32                            SaveStateMapField
  );

#endif
