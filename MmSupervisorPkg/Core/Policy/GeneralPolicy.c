/** @file
Implementation of SMM policy related routine.

Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>

#include "MmSupervisorCore.h"
#include "Policy/Policy.h"

SMM_SUPV_SECURE_POLICY_DATA_V1_0  *FirmwarePolicy;

/**
  Check overlap status between two region.

  @param  Address1         The start address of region 1.
  @param  Size1            The size of region 1.
  @param  Address2         The start address of region 2.
  @param  Size2            The offset of region 2.
  @param  IsOverlapping    Boolean to return if it's overlap.

  @retval EFI_SUCCESS      There aren't any overflow occurred and overlap status have checked.
  @retval EFI_SECURITY_VIOLATION   There is a overflow occurred.

**/
STATIC
EFI_STATUS
OverlapStatus (
  IN  UINTN    Address1,
  IN  UINTN    Size1,
  IN  UINTN    Address2,
  IN  UINTN    Size2,
  OUT BOOLEAN  *IsOverlapping
  )
{
  UINTN  End1 = Address1 + Size1 - 1;
  UINTN  End2 = Address2 + Size2 - 1;

  // Potential underflow
  if ((Size1 == 0) || (Size2 == 0)) {
    return EFI_SECURITY_VIOLATION;
  }

  // Overflow
  if (End1 < Address1) {
    return EFI_SECURITY_VIOLATION;
  }

  // Overflow
  if (End2 < Address2) {
    return EFI_SECURITY_VIOLATION;
  }

  if ((Address1 <= End2) && (Address2 <= End1)) {
    *IsOverlapping = TRUE;
  } else {
    *IsOverlapping = FALSE;
  }

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS                                          Status;
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0          *MemDescriptors     = NULL;
  SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0           *IoDescriptors      = NULL;
  SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0          *MsrDescriptors     = NULL;
  SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0  *InstrDescriptors   = NULL;
  SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0   *SvstDescriptors    = NULL;
  SMM_SUPV_POLICY_ROOT_V1                             *PolicyRoot         = NULL;
  UINT64                                              TypeDuplicationFlag = 0;
  UINTN                                               Index0;
  UINTN                                               Index1;
  UINTN                                               Index2;
  UINTN                                               TempAddress;
  UINTN                                               TempSize;
  UINTN                                               TotalScannedSize;
  BOOLEAN                                             IsOverlapping;

  DEBUG ((DEBUG_INFO, "%a - Policy overlap check entry ...\n", __FUNCTION__));

  if (SmmSecurityPolicy == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  if ((SmmSecurityPolicy->Reserved != 0) &&
      (SmmSecurityPolicy->Flags != 0) &&
      (SmmSecurityPolicy->Capabilities != 0))
  {
    DEBUG ((DEBUG_ERROR, "%a - Secure policy header has unrecognized bits set.\n", __FUNCTION__));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Keep a total size to indicate all the scanned portions, the final size should match the size from header
  TotalScannedSize = sizeof (SMM_SUPV_SECURE_POLICY_DATA_V1_0);

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmSecurityPolicy + SmmSecurityPolicy->PolicyRootOffset);
  for (Index0 = 0; Index0 < SmmSecurityPolicy->PolicyRootCount; Index0++) {
    if (PolicyRoot[Index0].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO) {
      // IO Policy Overlap Check
      if (TypeDuplicationFlag & (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO)) {
        DEBUG ((DEBUG_INFO, "%a - Duplicated IO policy root found ...\n", __FUNCTION__));
        Status = EFI_SECURITY_VIOLATION;
        goto Exit;
      }

      TypeDuplicationFlag |= (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO);
      IoDescriptors        = (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot[Index0].Offset);
      for (Index1 = 0; Index1 < PolicyRoot[Index0].Count; Index1++) {
        for (Index2 = 0; Index2 < Index1; Index2++) {
          TempAddress = IoDescriptors[Index1].IoAddress;
          TempSize    = IoDescriptors[Index1].LengthOrWidth;

          // Naively iterate through all entries to check overlap
          if (IoDescriptors[Index2].Attributes & SECURE_POLICY_RESOURCE_ATTR_STRICT_WIDTH) {
            // Strict width entry will only be shadowed by its superset
            if ((TempAddress <= IoDescriptors[Index2].IoAddress) &&
                (TempAddress + TempSize >= (UINT32)IoDescriptors[Index2].IoAddress + IoDescriptors[Index2].LengthOrWidth))
            {
              DEBUG ((DEBUG_ERROR, "%a - IO policy strict width overlap check failed\n", __FUNCTION__));
              Status = EFI_SECURITY_VIOLATION;
              goto Exit;
            }
          } else {
            // Otherwise, any overlap will count as policy check failure
            Status = OverlapStatus (
                       (UINTN)IoDescriptors[Index2].IoAddress,
                       (UINTN)IoDescriptors[Index2].LengthOrWidth,
                       TempAddress,
                       TempSize,
                       &IsOverlapping
                       );
            if (EFI_ERROR (Status) || IsOverlapping) {
              DEBUG ((DEBUG_ERROR, "%a - IO policy overlap check failed - %r\n", __FUNCTION__, Status));
              Status = EFI_SECURITY_VIOLATION;
              goto Exit;
            }
          }
        }

        if (IoDescriptors[Index1].Reserved != 0) {
          DEBUG ((DEBUG_ERROR, "%a - IO policy has non zero reserved field.\n", __FUNCTION__));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        TotalScannedSize += sizeof (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0);
      }

      TotalScannedSize += sizeof (SMM_SUPV_POLICY_ROOT_V1);
    } else if (PolicyRoot[Index0].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM) {
      // Memory Policy Overlap Check
      if (TypeDuplicationFlag & (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM)) {
        DEBUG ((DEBUG_INFO, "%a - Duplicated Memory policy root found ...\n", __FUNCTION__));
        Status = EFI_SECURITY_VIOLATION;
        goto Exit;
      }

      TypeDuplicationFlag |= (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM);
      MemDescriptors       = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot[Index0].Offset);
      for (Index1 = 0; Index1 < PolicyRoot[Index0].Count; Index1++) {
        for (Index2 = 0; Index2 < Index1; Index2++) {
          TempAddress = MemDescriptors[Index1].BaseAddress;
          TempSize    = MemDescriptors[Index1].Size;

          // Naively iterate through all entries to check overlap
          Status = OverlapStatus (
                     (UINTN)MemDescriptors[Index2].BaseAddress,
                     (UINTN)MemDescriptors[Index2].Size,
                     TempAddress,
                     TempSize,
                     &IsOverlapping
                     );
          if (EFI_ERROR (Status) || IsOverlapping) {
            DEBUG ((DEBUG_ERROR, "%a - Memory policy overlap check failed - %r\n", __FUNCTION__, Status));
            Status = EFI_SECURITY_VIOLATION;
            goto Exit;
          }
        }

        if (MemDescriptors[Index1].Reserved != 0) {
          DEBUG ((DEBUG_ERROR, "%a - Mem policy has non zero reserved field.\n", __FUNCTION__));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        TotalScannedSize += sizeof (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0);
      }

      TotalScannedSize += sizeof (SMM_SUPV_POLICY_ROOT_V1);
    } else if (PolicyRoot[Index0].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR) {
      // MSR Policy Overlap Check
      if (TypeDuplicationFlag & (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR)) {
        DEBUG ((DEBUG_INFO, "%a - Duplicated MSR policy root found ...\n", __FUNCTION__));
        Status = EFI_SECURITY_VIOLATION;
        goto Exit;
      }

      TypeDuplicationFlag |= (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR);
      MsrDescriptors       = (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot[Index0].Offset);
      for (Index1 = 0; Index1 < PolicyRoot[Index0].Count; Index1++) {
        for (Index2 = 0; Index2 < Index1; Index2++) {
          TempAddress = MsrDescriptors[Index1].MsrAddress;
          TempSize    = MsrDescriptors[Index1].Length;

          // Naively iterate through all entries to check overlap
          Status = OverlapStatus (
                     (UINTN)MsrDescriptors[Index2].MsrAddress,
                     (UINTN)MsrDescriptors[Index2].Length,
                     TempAddress,
                     TempSize,
                     &IsOverlapping
                     );
          if (EFI_ERROR (Status) || IsOverlapping) {
            DEBUG ((DEBUG_ERROR, "%a - MSR policy overlap check failed - %r\n", __FUNCTION__, Status));
            Status = EFI_SECURITY_VIOLATION;
            goto Exit;
          }
        }

        TotalScannedSize += sizeof (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0);
      }

      TotalScannedSize += sizeof (SMM_SUPV_POLICY_ROOT_V1);
    } else if (PolicyRoot[Index0].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION) {
      // Instruction Policy Duplication Check
      if (TypeDuplicationFlag & (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION)) {
        DEBUG ((DEBUG_INFO, "%a - Duplicated Instruction policy root found ...\n", __FUNCTION__));
        Status = EFI_SECURITY_VIOLATION;
        goto Exit;
      }

      TypeDuplicationFlag |= (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION);
      InstrDescriptors     = (SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot[Index0].Offset);
      for (Index1 = 0; Index1 < PolicyRoot[Index0].Count; Index1++) {
        for (Index2 = 0; Index2 < Index1; Index2++) {
          // Naively iterate through all entries to check duplication
          if (InstrDescriptors[Index1].InstructionIndex == InstrDescriptors[Index2].InstructionIndex) {
            DEBUG ((DEBUG_ERROR, "%a - Instruction policy duplication check failed - %r\n", __FUNCTION__, Status));
            Status = EFI_SECURITY_VIOLATION;
            goto Exit;
          }
        }

        if (InstrDescriptors[Index1].Reserved != 0) {
          DEBUG ((DEBUG_ERROR, "%a - Instruction policy has non zero reserved field.\n", __FUNCTION__));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        TotalScannedSize += sizeof (SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0);
      }

      TotalScannedSize += sizeof (SMM_SUPV_POLICY_ROOT_V1);
    } else if (PolicyRoot[Index0].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE) {
      // Save State Policy Duplication Check
      if (TypeDuplicationFlag & (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE)) {
        DEBUG ((DEBUG_INFO, "%a - Duplicated Save state policy root found ...\n", __FUNCTION__));
        Status = EFI_SECURITY_VIOLATION;
        goto Exit;
      }

      TypeDuplicationFlag |= (BIT0 << SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE);
      SvstDescriptors      = (SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0 *)((UINTN)SmmSecurityPolicy + PolicyRoot[Index0].Offset);
      for (Index1 = 0; Index1 < PolicyRoot[Index0].Count; Index1++) {
        for (Index2 = 0; Index2 < Index1; Index2++) {
          // Naively iterate through all entries to check duplication
          // Two policy entries with the same map field, regardless of their attributes, will not be allowed
          if (SvstDescriptors[Index1].MapField == SvstDescriptors[Index2].MapField) {
            DEBUG ((DEBUG_ERROR, "%a - Save state policy duplication check failed - %r\n", __FUNCTION__, Status));
            Status = EFI_SECURITY_VIOLATION;
            goto Exit;
          }
        }

        // Make sure no write-access related attribute is reported in the policy. This supervisor does not support it.
        // Although SMM level 30 specification permits RAX to be written on a trapped IO read, no
        // existing implementations require this feature, so it is blocked as well
        if (((SvstDescriptors[Index1].Attributes & (SECURE_POLICY_RESOURCE_ATTR_WRITE | SECURE_POLICY_RESOURCE_ATTR_COND_WRITE)) != 0) ||
            ((SvstDescriptors[Index1].Attributes & (SECURE_POLICY_RESOURCE_ATTR_READ | SECURE_POLICY_RESOURCE_ATTR_COND_READ)) ==
             (SECURE_POLICY_RESOURCE_ATTR_READ | SECURE_POLICY_RESOURCE_ATTR_COND_READ)))
        {
          DEBUG ((
            DEBUG_ERROR,
            "%a - Save state policy has unsupported attributes %x.\n",
            __FUNCTION__,
            SvstDescriptors[Index1].Attributes
            ));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        // Unconditional entries shall not have conditions specified
        // Only conditional read is checked here since we do not allow write attributes
        if (((SvstDescriptors[Index1].Attributes & SECURE_POLICY_RESOURCE_ATTR_COND_READ) == 0) &&
            (SvstDescriptors[Index1].AccessCondition != SECURE_POLICY_SVST_UNCONDITIONAL))
        {
          DEBUG ((DEBUG_ERROR, "%a - Save state policy has conflicting condition on attributes.\n", __FUNCTION__));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        if (SvstDescriptors[Index1].Reserved != 0) {
          DEBUG ((DEBUG_ERROR, "%a - Save state policy has non zero reserved field.\n", __FUNCTION__));
          Status = EFI_SECURITY_VIOLATION;
          goto Exit;
        }

        TotalScannedSize += sizeof (SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0);
      }

      TotalScannedSize += sizeof (SMM_SUPV_POLICY_ROOT_V1);
    } else {
      DEBUG ((DEBUG_ERROR, "%a - Unrecognized policy type check %x\n", __FUNCTION__, PolicyRoot[Index0].Type));
      Status = EFI_SECURITY_VIOLATION;
      goto Exit;
    }

    if (!IsZeroBuffer (PolicyRoot[Index0].Reserved, sizeof (PolicyRoot[Index0].Reserved))) {
      DEBUG ((DEBUG_ERROR, "%a - Policy root has non zero reserved field.\n", __FUNCTION__));
      Status = EFI_SECURITY_VIOLATION;
      goto Exit;
    }
  }

  // Legacy Memory Policy Existence Check
  if (SmmSecurityPolicy->MemoryPolicyCount != 0) {
    DEBUG ((DEBUG_ERROR, "%a - Legacy memory policy detected, not supported!\n", __FUNCTION__));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if (TotalScannedSize != SmmSecurityPolicy->Size) {
    DEBUG ((
      DEBUG_ERROR,
      "%a - Unrecognized bytes detected in the policy (expecting 0x%x, has 0x%x), not allowed!\n",
      __FUNCTION__,
      TotalScannedSize,
      SmmSecurityPolicy->Size
      ));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Policy overlap check failed - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
  }

  DEBUG ((DEBUG_INFO, "%a - Policy overlap check exit ...\n", __FUNCTION__));
  return Status;
}

/**
  Dump the smm policy data.
**/
VOID
DumpSmmPolicyData (
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *Data
  )
{
  UINT32  i;
  UINT32  j;

  SMM_SUPV_POLICY_ROOT_V1                             *PolicyRoot;
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0          *MemoryPolicy;
  SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0           *IoPolicy;
  SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0          *MsrPolicy;
  SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0  *InstructionPolicy;
  SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0   *SaveStatePolicy;

  DEBUG ((DEBUG_INFO, "SMM_SUPV_SECURE_POLICY_DATA_V1_0:\n"));
  DEBUG ((DEBUG_INFO, "Version Major:%x\n", Data->VersionMajor));
  DEBUG ((DEBUG_INFO, "Version Minor:%x\n", Data->VersionMinor));
  DEBUG ((DEBUG_INFO, "Size:0x%x\n", Data->Size));
  DEBUG ((DEBUG_INFO, "MemoryPolicyOffset:0x%x\n", Data->MemoryPolicyOffset));
  DEBUG ((DEBUG_INFO, "MemoryPolicyCount:0x%x\n", Data->MemoryPolicyCount));
  DEBUG ((DEBUG_INFO, "Flags:%x\n", Data->Flags));
  DEBUG ((DEBUG_INFO, "Capabilities:%x\n", Data->Capabilities));
  DEBUG ((DEBUG_INFO, "PolicyRootOffset:0x%x\n", Data->PolicyRootOffset));
  DEBUG ((DEBUG_INFO, "PolicyRootCount:0x%x\n", Data->PolicyRootCount));

  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)Data + Data->PolicyRootOffset);
  // Iterate through each policy root
  for (i = 0; i < Data->PolicyRootCount; i++) {
    DEBUG ((DEBUG_INFO, "Policy Root:\n"));
    DEBUG ((DEBUG_INFO, "  Version: %x\n", PolicyRoot[i].Version));
    DEBUG ((DEBUG_INFO, "  PolicyRootSize: %x\n", PolicyRoot[i].PolicyRootSize));
    DEBUG ((DEBUG_INFO, "  Type: %x\n", PolicyRoot[i].Type));
    DEBUG ((DEBUG_INFO, "  Offset: %x\n", PolicyRoot[i].Offset));
    DEBUG ((DEBUG_INFO, "  Count: %x\n", PolicyRoot[i].Count));
    DEBUG ((DEBUG_INFO, "  AccessAttr: %a\n", (PolicyRoot[i].AccessAttr == SMM_SUPV_ACCESS_ATTR_ALLOW) ? "ALLOW" : "DENY"));
    // Iterate through each policy descriptor described by this policy root
    for (j = 0; j < PolicyRoot[i].Count; j++) {
      if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM) {
        // Dump Memory Policy
        MemoryPolicy = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *)((UINTN)Data + PolicyRoot[i].Offset);
        DumpMemPolicyEntry (&MemoryPolicy[j]);
      } else if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_IO) {
        // Dump IoPolicy
        IoPolicy = (SMM_SUPV_SECURE_POLICY_IO_DESCRIPTOR_V1_0 *)((UINTN)Data + PolicyRoot[i].Offset);
        DEBUG ((
          DEBUG_INFO,
          "IO: [%lx-%lx] %a %a\n", \
          IoPolicy[j].IoAddress, \
          IoPolicy[j].IoAddress + IoPolicy[j].LengthOrWidth - 1, \
          (IoPolicy[j].Attributes & SECURE_POLICY_RESOURCE_ATTR_READ) ? "R" : ".", \
          (IoPolicy[j].Attributes & SECURE_POLICY_RESOURCE_ATTR_WRITE) ? "W" : "." \
          ));
      } else if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MSR) {
        // Dump MsrPolicy
        MsrPolicy = (SMM_SUPV_SECURE_POLICY_MSR_DESCRIPTOR_V1_0 *)((UINTN)Data + PolicyRoot[i].Offset);
        DEBUG ((
          DEBUG_INFO,
          "MSR: [%lx-%lx] %a %a\n", \
          MsrPolicy[j].MsrAddress, \
          MsrPolicy[j].MsrAddress + MsrPolicy[j].Length - 1, \
          (MsrPolicy[j].Attributes & SECURE_POLICY_RESOURCE_ATTR_READ) ? "R" : ".", \
          (MsrPolicy[j].Attributes & SECURE_POLICY_RESOURCE_ATTR_WRITE) ? "W" : "." \
          ));
      } else if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_INSTRUCTION) {
        // Dump InstructionPolicy
        InstructionPolicy = (SMM_SUPV_SECURE_POLICY_INSTRUCTION_DESCRIPTOR_V1_0 *)((UINTN)Data + PolicyRoot[i].Offset);
        DEBUG ((
          DEBUG_INFO,
          "INSTRUCTION: [%lx] %a\n", \
          InstructionPolicy[j].InstructionIndex, \
          (InstructionPolicy[j].Attributes & SECURE_POLICY_RESOURCE_ATTR_EXECUTE) ? "X" : "."
          ));
      } else if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_SAVE_STATE) {
        // Dump SaveStatePolicy
        SaveStatePolicy = (SMM_SUPV_SECURE_POLICY_SAVE_STATE_DESCRIPTOR_V1_0 *)((UINTN)Data + PolicyRoot[i].Offset);
        DEBUG ((
          DEBUG_INFO,
          "SAVESTATE: [%lx] %x %a\n", \
          SaveStatePolicy[j].MapField, \
          (SaveStatePolicy[j].Attributes), \
          ((SaveStatePolicy[j].AccessCondition == SECURE_POLICY_SVST_UNCONDITIONAL) ? "Unconditional" :
           ((SaveStatePolicy[j].AccessCondition == SECURE_POLICY_SVST_CONDITION_IO_RD) ? "IoRead" : "IoWrite"))
          ));
      } else {
        DEBUG ((DEBUG_ERROR, "Unrecognized policy root type found %x, bailing!!!\n", PolicyRoot[i].Type));
        return;
      }
    }
  }
}

/**
  Routine for initializing policy data provided by firmware.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval Errors                The supervisor is unable to locate or protect the policy from firmware.

**/
EFI_STATUS
InitializePolicy (
  VOID
  )
{
  EFI_STATUS           Status;
  EFI_FFS_FILE_HEADER  *FileHeader;
  VOID                 *SectionData;
  UINTN                SectionDataSize;
  UINTN                PolicySize;

  FirmwarePolicy = NULL;

  //
  // First try to find the policy file based on the GUID specified.
  //
  FileHeader = NULL;
  do {
    Status =  FfsFindNextFile (
                EFI_FV_FILETYPE_FREEFORM,
                (EFI_FIRMWARE_VOLUME_HEADER *)gMmCorePrivate->StandaloneBfvAddress,
                &FileHeader
                );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Failed to locate firmware policy file from given FV - %r\n",
        __FUNCTION__,
        Status
        ));
      break;
    }

    if (!CompareGuid (&FileHeader->Name, &gMmSupervisorPolicyFileGuid)) {
      continue;
    }

    DEBUG ((
      DEBUG_INFO,
      "[%a] Discovered policy file in FV at 0x%p.\n",
      __FUNCTION__,
      FileHeader
      ));

    Status = FfsFindSectionData (
               EFI_SECTION_RAW,
               FileHeader,
               &SectionData,
               &SectionDataSize
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Failed to find raw section from discovered policy file - %r\n",
        __FUNCTION__,
        Status
        ));
      break;
    }

    PolicySize = ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)SectionData)->Size;
    if (PolicySize > SectionDataSize) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Policy data size 0x%x > blob size 0x%x.\n",
        __FUNCTION__,
        PolicySize,
        SectionDataSize
        ));
      Status = EFI_BAD_BUFFER_SIZE;
      break;
    }

    FirmwarePolicy = AllocateAlignedPages (EFI_SIZE_TO_PAGES (PolicySize), EFI_PAGE_SIZE);
    if (FirmwarePolicy == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Cannot allocate page for firmware provided policy - %r\n",
        __FUNCTION__,
        Status
        ));
      break;
    }

    CopyMem (FirmwarePolicy, SectionData, PolicySize);

    DEBUG_CODE_BEGIN ();
    DumpSmmPolicyData (FirmwarePolicy);
    DEBUG_CODE_END ();

    // We found one valid firmware policy, do not need to proceed further on this FV.
    break;
  } while (TRUE);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Unable to locate a valid firmware policy from given FV, bail here - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  // Prepare the buffer for Mem policy snapshot, it will be compared against when non-MM entity requested
  Status = AllocateMemForPolicySnapshot ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate buffer for memory policy snapshot - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  Status = SecurityPolicyCheck (FirmwarePolicy);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Policy check failed on policy blob from firmware - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

Done:
  return Status;
}
