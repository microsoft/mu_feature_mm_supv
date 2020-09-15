/** @file SmmPolicyGateLib.c

  This file enforces our SMM policies that were configured
  with the SmmPolicyGeneratorTool.

  Copyright (C) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <SmmSecurePolicy.h>
#include <Protocol/MmCpuIo.h>
#include <Library/DebugLib.h>
#include <Library/SmmPolicyGateLib.h>
#include <Library/SysCallLib.h>

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
  )
{
  EFI_STATUS                                 Status        = EFI_SUCCESS;
  SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0  *IoDescriptor = NULL;
  SMM_SUPV_POLICY_ROOT_V1                    *PolicyRoot   = NULL;
  UINT32                                     IoSize        = 0;
  UINT32                                     i;
  BOOLEAN                                    FoundMatch = FALSE;

  //
  // Check to ensure that only one of SECURE_POLICY_RESOURCE_ATTR_READ
  // or SECURE_POLICY_RESOURCE_ATTR_WRITE was specified.
  //
  if (((AccessMask & SECURE_POLICY_RESOURCE_ATTR_READ) != SECURE_POLICY_RESOURCE_ATTR_READ) &&
      ((AccessMask & SECURE_POLICY_RESOURCE_ATTR_WRITE) != SECURE_POLICY_RESOURCE_ATTR_WRITE))
  {
    DEBUG ((DEBUG_ERROR, "%a Invalid Access Mask specified.\n", __FUNCTION__));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  //
  // Check to ensure that incoming IO width is in spec.
  //
  if (IoWidth == MM_IO_UINT8) {
    IoSize = sizeof (UINT8);
  } else if (IoWidth == MM_IO_UINT16) {
    IoSize = sizeof (UINT16);
  } else if (IoWidth == MM_IO_UINT32) {
    IoSize = sizeof (UINT32);
  } else {
    DEBUG ((DEBUG_ERROR, "%a Invalid Access Mask specified.\n", __FUNCTION__));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmSecurityPolicy + SmmSecurityPolicy->PolicyRootOffset);
  for (i = 0; i < SmmSecurityPolicy->PolicyRootCount; i++) {
    if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO) {
      PolicyRoot = &PolicyRoot[i];
      break;
    }
  }

  if (i >= SmmSecurityPolicy->PolicyRootCount) {
    DEBUG ((DEBUG_WARN, "%a Could not find IO policy root, bail to be on the safe side.\n", __FUNCTION__));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  IoDescriptor = (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot->Offset);
  for (i = 0; i < PolicyRoot->Count; i++) {
    //
    // See if this IO request address is covered by the current Security
    // Descriptor.
    //
    if ((IoDescriptor[i].Attributes & SECURE_POLICY_RESOURCE_ATTR_STRICT_WIDTH) &&
        (IoAddress == (UINT32)IoDescriptor[i].IoAddress) &&
        (IoSize == (UINT32)IoDescriptor[i].LengthOrWidth))
    {
      //
      // We found an exactly matched policy for the address and size in question.
      //
      if (IoDescriptor[i].Attributes & AccessMask) {
        //
        // Someone is trying to access something that matches policy.
        //
        DEBUG ((DEBUG_VERBOSE, "%a Strict width access matches an entry of Security Policy.\n", __FUNCTION__));
        FoundMatch = TRUE;
      }

      //
      // We are finished.
      //
      break;
    } else if (((IoDescriptor[i].Attributes & SECURE_POLICY_RESOURCE_ATTR_STRICT_WIDTH) == 0) &&
               (((IoAddress >= (UINT32)IoDescriptor[i].IoAddress) &&
                 (IoAddress < (UINT32)IoDescriptor[i].IoAddress + IoDescriptor[i].LengthOrWidth)) ||
                ((IoAddress + (UINT32)IoSize > (UINT32)IoDescriptor[i].IoAddress) &&
                 (IoAddress + (UINT32)IoSize <= (UINT32)IoDescriptor[i].IoAddress + IoDescriptor[i].LengthOrWidth))))
    {
      //
      // We found a policy for the address in question.
      //
      if (IoDescriptor[i].Attributes & AccessMask) {
        //
        // Someone is trying to access something that matches policy.
        //
        DEBUG ((DEBUG_VERBOSE, "%a Access matches an entry of the Security Policy.\n", __FUNCTION__));
        FoundMatch = TRUE;
      }

      //
      // We are finished.
      //
      break;
    }
  }

  if ((FoundMatch && (PolicyRoot->AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) ||
      (!FoundMatch && (PolicyRoot->AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW)))
  {
    //
    // We reject access based on:
    // 1. found a matching policy, reject access if this is a deny list
    // 2. did not find a matching policy, reject access if this is an allow list
    //
    DEBUG ((
      DEBUG_ERROR,
      "%a Rejecting IO access based on policy walk through: Index: %d, AccessAttr: 0x%x.\n",
      __FUNCTION__,
      i,
      PolicyRoot->AccessAttr
      ));
    Status = EFI_ACCESS_DENIED;
  }

Exit:

  return Status;
}

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
  )
{
  EFI_STATUS                                  Status         = EFI_SUCCESS;
  SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0  *MsrDescriptor = NULL;
  SMM_SUPV_POLICY_ROOT_V1                     *PolicyRoot    = NULL;
  UINT32                                      i;
  BOOLEAN                                     FoundMatch = FALSE;

  //
  // Check to ensure that only one of SECURE_POLICY_RESOURCE_ATTR_READ
  // or SECURE_POLICY_RESOURCE_ATTR_WRITE was specified.
  //
  if (((AccessMask & SECURE_POLICY_RESOURCE_ATTR_READ) != SECURE_POLICY_RESOURCE_ATTR_READ) &&
      ((AccessMask & SECURE_POLICY_RESOURCE_ATTR_WRITE) != SECURE_POLICY_RESOURCE_ATTR_WRITE))
  {
    DEBUG ((DEBUG_ERROR, "%a Invalid Access Mask specified.\n", __FUNCTION__));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmSecurityPolicy + SmmSecurityPolicy->PolicyRootOffset);
  for (i = 0; i < SmmSecurityPolicy->PolicyRootCount; i++) {
    if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR) {
      PolicyRoot = &PolicyRoot[i];
      break;
    }
  }

  if (i >= SmmSecurityPolicy->PolicyRootCount) {
    DEBUG ((DEBUG_WARN, "%a Could not find MSR policy root, bail to be on the safe side.\n", __FUNCTION__));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  MsrDescriptor = (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot->Offset);
  for (i = 0; i < PolicyRoot->Count; i++) {
    //
    // See if this request is in the current descriptor
    //
    if ((MsrAddress >= MsrDescriptor[i].MsrAddress) &&
        (MsrAddress < MsrDescriptor[i].MsrAddress + MsrDescriptor[i].Length))
    {
      //
      // We found a policy for the address in question.
      //
      if (MsrDescriptor[i].Attributes & AccessMask) {
        //
        // Someone is trying to access something that matches policy.
        //
        DEBUG ((DEBUG_VERBOSE, "%a Access matches an entry of the Security Policy\n", __FUNCTION__));
        FoundMatch = TRUE;
      }

      //
      // We are finished.
      //
      break;
    }
  }

  if ((FoundMatch && (PolicyRoot->AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) ||
      (!FoundMatch && (PolicyRoot->AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW)))
  {
    //
    // We reject access based on:
    // 1. found a matching policy, reject access if this is a deny list
    // 2. did not find a matching policy, reject access if this is an allow list
    //
    DEBUG ((
      DEBUG_ERROR,
      "%a Rejecting MSR access based on policy walk through: Index: %d, AccessAttr: 0x%x.\n",
      __FUNCTION__,
      i,
      PolicyRoot->AccessAttr
      ));
    Status = EFI_ACCESS_DENIED;
  }

Exit:
  return Status;
}

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
  )
{
  EFI_STATUS                                          Status           = EFI_SUCCESS;
  SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0  *InstrDescriptor = NULL;
  SMM_SUPV_POLICY_ROOT_V1                             *PolicyRoot      = NULL;
  UINT32                                              i;
  BOOLEAN                                             FoundMatch = FALSE;

  //
  // Check to ensure that only one of SECURE_POLICY_INSTRUCTION was requested.
  //
  if (InstructionIndex >= SECURE_POLICY_INSTRUCTION_COUNT) {
    DEBUG ((DEBUG_ERROR, "%a Invalid instruction index requested.\n", __FUNCTION__));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmSecurityPolicy + SmmSecurityPolicy->PolicyRootOffset);
  for (i = 0; i < SmmSecurityPolicy->PolicyRootCount; i++) {
    if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION) {
      PolicyRoot = &PolicyRoot[i];
      break;
    }
  }

  if (i >= SmmSecurityPolicy->PolicyRootCount) {
    DEBUG ((DEBUG_WARN, "%a Could not find Instruction policy root, bail to be on the safe side.\n", __FUNCTION__));
    Status = EFI_ACCESS_DENIED;
    goto Exit;
  }

  InstrDescriptor = (SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot->Offset);
  for (i = 0; i < PolicyRoot->Count; i++) {
    //
    // See if this request is in the current descriptor
    //
    if (InstructionIndex == InstrDescriptor[i].InstructionIndex) {
      //
      // We found a policy for the instruction specified.
      //
      if (InstrDescriptor[i].Attributes & SECURE_POLICY_RESOURCE_ATTR_EXECUTE) {
        //
        // Requested instruction found in policy execution is prohibited.
        //
        DEBUG ((DEBUG_INFO, "%a Execution matches an entry of the Security Policy\n", __FUNCTION__));
        FoundMatch = TRUE;
      }

      //
      // We are finished.
      //
      break;
    }
  }

  if ((FoundMatch && (PolicyRoot->AccessAttr == SMM_SUPV_ACCESS_ATTR_DENY)) ||
      (!FoundMatch && (PolicyRoot->AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW)))
  {
    //
    // We reject access based on:
    // 1. found a matching policy, reject access if this is a deny list
    // 2. did not find a matching policy, reject access if this is an allow list
    //
    DEBUG ((
      DEBUG_ERROR,
      "%a Rejecting Instruction access based on policy walk through: Index: %d, AccessAttr: 0x%x.\n",
      __FUNCTION__,
      i,
      PolicyRoot->AccessAttr
      ));
    Status = EFI_ACCESS_DENIED;
  }

Exit:
  return Status;
}

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
  )
{
  // TODO: Not implemented here
  return EFI_ACCESS_DENIED;
}
