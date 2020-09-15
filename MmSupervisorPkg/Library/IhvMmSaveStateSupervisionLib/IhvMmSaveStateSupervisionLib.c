/** @file
  Instance of SMM SaveState supervision layer. This library provides supervision
  over SMM SaveState.

  Copyright (c) Microsoft Corporation.
  Copyright(C) 2020 Advanced Micro Devices, Inc. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>

#include <Protocol/MmCpu.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IhvSmmSaveStateSupervisionLib.h>

#include "IhvMmSaveStateSupervisionCoreSvcs.h"

/**
  @brief Determine if access condition given policy matches current MMI scenario.

  @param SaveStatePolicy    - The address of supplied SMM secure policy.
  @param CpuIndex           - Cpu index requested.
  @param AllowedWidth       - Allowed width for current request, determine by condition
                              and requested map field.
  @param IoInfo             - Pointer to IoInfo fetched during this validation.

  @retval EFI_SUCCESS           The requested operation is allowed by the policy.
  @retval EFI_NOT_FOUND         Failed to fetch certain save state information to determine
                                accessibility.
  @retval EFI_INVALID_PARAMETER Input arguments are null pointers, or policy mapfield and/or
                                attribute is unrecognized, or save state read has failed.
  @retval EFI_UNSUPPORTED       The condition mismatches with the one described in policy.
**/
STATIC
EFI_STATUS
InspectReadCondition (
  IN  SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0  *SaveStatePolicy,
  IN  UINTN                                              CpuIndex,
  OUT UINTN                                              *AllowedWidth,
  OUT EFI_MM_SAVE_STATE_IO_INFO                          *IoInfo
  )
{
  EFI_STATUS  Status;

  if ((SaveStatePolicy == NULL) || (AllowedWidth == NULL) || (IoInfo == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // Grab IoInfo for this CpuIndex, we will need it to determine access later
  // But we are executing on supervisor stack, no need to worry about info leakage
  Status = SmmReadSaveState (NULL, sizeof (*IoInfo), EFI_MM_SAVE_STATE_REGISTER_IO, CpuIndex, IoInfo);
  if (EFI_ERROR (Status)) {
    // Cannot get IoInfo, possible due to this CpuIndex has incorrect type, or invalid SMI flag
    return Status;
  }

  if (SaveStatePolicy->MapField == SECURE_POLICY_SVST_IO_TRAP) {
    *AllowedWidth = sizeof (EFI_MM_SAVE_STATE_IO_INFO);
  } else if (SaveStatePolicy->MapField == SECURE_POLICY_SVST_RAX) {
    *AllowedWidth = IoInfo->IoWidth;
  } else {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  // If the attribute is unconditional read, it is a matching "condition"
  if (SaveStatePolicy->Attributes & SECURE_POLICY_RESOURCE_ATTR_READ) {
    if (SaveStatePolicy->AccessCondition == SECURE_POLICY_SVST_UNCONDITIONAL) {
      return EFI_SUCCESS;
    } else {
      // Not sure what this means other than bad policy, should not happen
      ASSERT (FALSE);
      return EFI_INVALID_PARAMETER;
    }
  }

  if ((SaveStatePolicy->Attributes & SECURE_POLICY_RESOURCE_ATTR_COND_READ) == 0) {
    // Save state policy only supports normal read or conditional read.
    // The conditional read bit has to be set if we can get here.
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  // Really need to check condition now
  if ((IoInfo->IoType == EFI_MM_SAVE_STATE_IO_TYPE_OUTPUT) &&
      (SaveStatePolicy->AccessCondition == SECURE_POLICY_SVST_CONDITION_IO_WR))
  {
    // Trying to read IoData on a IO write is the condition spec specified, match found
    return EFI_SUCCESS;
  }

  // Should not print IoData since it is blocked by policy
  DEBUG ((
    DEBUG_ERROR,
    "%a MMI is triggered by this CPU, but the security policy condition (0x%x) does not allow access per its IO type (0x%x).\n",
    __FUNCTION__,
    SaveStatePolicy->AccessCondition,
    IoInfo->IoType
    ));
  return EFI_UNSUPPORTED;
}

/**
  @brief Given Smm save state address and access width, determine if it is
  allowed to access by parsing the policy

  @param SmmSecurityPolicy  - The address of applied SMM secure policy.
  @param CpuIndex           - Cpu index of this request.
  // MU_CHANGE: For MM Supervisor, this will be the repurposed to EFI_MM_SAVE_STATE_REGISTER.
  @param Register           - Specifies the CPU register to read form the save state.
  @param Width              - Access width
  // MU_CHANGE: This is not needed for MM supervisor.
  @param CpuSmmData         - Not used

  @retval EFI_ACCESS_DENIED     The requested operation is not whitelisted by
                                the policy.
          // MU_CHANGE Starts:  Below error is only allowed for MM supervisor
  @retval EFI_NOT_FOUND         Failed to fetch certain save state information to determine
                                accessibility.
          // MU_CHANGE Ends.
  @retval EFI_INVALID_PARAMETER The SaveStateMapField needs to be within the
                                range of [0, SECURE_POLICY_INSTRUCTION_COUNT).
  @retval EFI_SUCCESS           The requested operation is allowed by the
                                policy.
**/
EFI_STATUS
EFIAPI
IsIhvSmmSaveStateReadAllowed (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmSecurityPolicy,
  IN UINTN                             CpuIndex,
  IN EFI_MM_SAVE_STATE_REGISTER        Register,
  IN UINTN                             Width,
  IN GATELIB_CPU_SMM_DATA              *CpuSmmData
  )
{
  EFI_STATUS                                         Status          = EFI_SUCCESS;
  SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0  *SvstDescriptor = NULL;
  SMM_SUPV_POLICY_ROOT_V1                            *PolicyRoot     = NULL;
  UINT32                                             i;
  BOOLEAN                                            FoundMatch = FALSE;
  SECURE_POLICY_SVST                                 TargetMapField;
  UINTN                                              AllowedWidth;
  EFI_MM_SAVE_STATE_IO_INFO                          IoInfo;

  if (SmmSecurityPolicy == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmSecurityPolicy + SmmSecurityPolicy->PolicyRootOffset);
  for (i = 0; i < SmmSecurityPolicy->PolicyRootCount; i++) {
    if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE) {
      PolicyRoot = &PolicyRoot[i];
      break;
    }
  }

  if (i >= SmmSecurityPolicy->PolicyRootCount) {
    DEBUG ((DEBUG_WARN, "%a No policy root found for save state, this is level 20 policy. Allow all read access!\n", __FUNCTION__));
    return EFI_SUCCESS;
  }

  // Convert EFI_MM_SAVE_STATE_REGISTER to SECURE_POLICY_SVST for easier validation
  switch (Register) {
    case EFI_MM_SAVE_STATE_REGISTER_RAX:
      TargetMapField = SECURE_POLICY_SVST_RAX;
      break;
    case EFI_MM_SAVE_STATE_REGISTER_IO:
      TargetMapField = SECURE_POLICY_SVST_IO_TRAP;
      break;
    // MU_CHANGE Starts: Do not enforce Processor ID
    case EFI_MM_SAVE_STATE_REGISTER_PROCESSOR_ID:
      return EFI_SUCCESS;
    // MU_CHANGE Ends.
    default:
      goto Exit;
      break;
  }

  ZeroMem (&IoInfo, sizeof (IoInfo));
  SvstDescriptor = (SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot->Offset);
  for (i = 0; i < PolicyRoot->Count; i++) {
    //
    // See if this request is in the current descriptor
    //
    if (TargetMapField == (SECURE_POLICY_SVST)SvstDescriptor[i].MapField) {
      //
      // We found a policy potentially applicable for the register in request.
      //
      if ((SvstDescriptor[i].Attributes & SECURE_POLICY_RESOURCE_ATTR_COND_READ) ||
          (SvstDescriptor[i].Attributes & SECURE_POLICY_RESOURCE_ATTR_READ))
      {
        DEBUG ((DEBUG_VERBOSE, "%a Located a potentially matching policy.\n", __FUNCTION__));
        //
        // Find the current condition to see if it matches.
        //
        Status = InspectReadCondition (&SvstDescriptor[i], CpuIndex, &AllowedWidth, &IoInfo);
        if (Status == EFI_UNSUPPORTED) {
          // This is just a mismatched condition. Do not treat as error. Proceed with access attribute evaluation.
          DEBUG ((DEBUG_WARN, "%a Mismatched condition detected, potential policy violation.\n", __FUNCTION__));
          Status = EFI_SUCCESS;
          goto Exit;
        } else if (EFI_ERROR (Status)) {
          // Other real errors, bail here to propagate the error code to caller.
          goto Exit;
        } else if (Width > AllowedWidth) {
          DEBUG ((DEBUG_ERROR, "%a Attempting to access save state region (0x%x) larger than allowed (0x%x)\n", __FUNCTION__, Width, AllowedWidth));
          Status = EFI_ACCESS_DENIED;
          goto Exit;
        } else {
          DEBUG ((DEBUG_VERBOSE, "%a Access matches an entry of the Security Policy - Field: 0x%x on CPU 0x%x\n", __FUNCTION__, TargetMapField, CpuIndex));
          FoundMatch = TRUE;
        }
      }

      if (FoundMatch) {
        if (TargetMapField == SECURE_POLICY_SVST_IO_TRAP) {
          // EFI_MM_SAVE_STATE_REGISTER_IO includes IO data, which is essentially RAX access
          // Recurse call to validate RAX access here
          // Note: The save state read routine for RAX needs to be consistent with this IoInfo.IoWidth derivation!!
          Status = IsIhvSmmSaveStateReadAllowed (SmmSecurityPolicy, CpuIndex, EFI_MM_SAVE_STATE_REGISTER_RAX, IoInfo.IoWidth, CpuSmmData);
          if (EFI_ERROR (Status)) {
            DEBUG ((DEBUG_ERROR, "%a Accessing IO type/port/width is granted but IO data access is rejected %r\n", __FUNCTION__, Status));
            goto Exit;
          }
        }
      }

      //
      // We are finished.
      //
      break;
    }
  }

Exit:
  if (EFI_ERROR (Status)) {
    // Propagate error code if any, no need to evaluate access attribute from policy root.

    // Note: Error print here is intentionally omitted avoid excessive print lines, since there could
    // be a lot of IO information queries, but only the CpuIndex that traps MMI will be allowed for
    // reading (others will return EFI_NOT_FOUND).
    return Status;
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
      "%a Rejecting save state access (Register: 0x%x, Width: 0x%x, CPU Index: 0x%x) based on policy walk through: Index: %d, AccessAttr: 0x%x.\n",
      __FUNCTION__,
      Register,
      Width,
      CpuIndex,
      i,
      PolicyRoot->AccessAttr
      ));
    Status = EFI_ACCESS_DENIED;
  }

  return Status;
}

/**
  Read data from SmmSaveStateAddr with given Width

  @param Ret                - Point to return value
  @param CpuIndex           - Cpu
  @param Register           - Specifies the CPU register to read form the save state. // MU_CHANGE: For MM Supervisor, this will be the repurposed to
  @param Width              - Access width
**/
VOID
EFIAPI
IhvSmmSaveStateRead (
  IN OUT                            VOID  *Ret,
  IN UINTN                                CpuIndex,
  IN EFI_MM_SAVE_STATE_REGISTER           Register,
  IN UINTN                                Width
  )
{
  // Not implemented for MM supervisor
}
