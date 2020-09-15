/** @file
  Function to support fetching secure policy through MM Supervisor communicate protocol.

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (C) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <SmmSecurePolicy.h>

#include <Guid/MmSupervisorRequestData.h>

#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>

#include "MmSupervisorCore.h"
#include "Policy/Policy.h"
#include "Mem/Mem.h"

/**
  Function that combines current memory policy and firmware secure policy for requestor.
  Calling this function will also block the supervisor memory pages from being updated.

  @param[out] DrtmSmmPolicyData     Input buffer points to the entire v1.0 policy.
  @param[in]  SuppliedBufferSize    Maximal buffer size supplied by caller.

  @retval EFI_SUCCESS               The security policy is successfully gathered.
  @retval EFI_SECURITY_VIOLATION    Security policy does not meet minimal security requirements.
  @retval EFI_INVALID_PARAMETER     Input arguments contain NULL pointers.
  @retval EFI_BUFFER_TOO_SMALL      Input buffer is not big enough to contain the entire security policy.
**/
EFI_STATUS
FetchNUpdateSecurityPolicy (
  OUT     SMM_SUPV_SECURE_POLICY_DATA_V1_0  *DrtmSmmPolicyData,
  IN      UINT64                            SuppliedBufferSize
  )
{
  EFI_STATUS  Status;
  UINT64      MaxPolicyBufferSize;

  if (!mMmReadyToLockDone) {
    // Policy requested prior to ready to lock event, then this is the ready to lock event...
    DEBUG ((DEBUG_WARN, "%a Policy requested prior to ready to lock, enforcing ready to lock here!\n", __FUNCTION__));
    Status = MmReadyToLockHandler (NULL, NULL, NULL, NULL);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Ready to lock handler returned with error %r!!!\n", __FUNCTION__, Status));
      goto Exit;
    }
  }

  if (DrtmSmmPolicyData == NULL) {
    Status = EFI_INVALID_PARAMETER;
    DEBUG ((DEBUG_ERROR, "%a Input argument is a null pointer!!!\n", __FUNCTION__));
    goto Exit;
  }

  Status = VerifyRequestSupvCommBuffer (DrtmSmmPolicyData, SuppliedBufferSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Input buffer %p is illegal - %r!!!\n", __FUNCTION__, DrtmSmmPolicyData, Status));
    goto Exit;
  }

  if (FirmwarePolicy == NULL) {
    Status = EFI_SECURITY_VIOLATION;
    DEBUG ((
      DEBUG_ERROR,
      "%a Firmware policy is not initialized, cannot proceed!!!\n",
      __FUNCTION__
      ));
    goto Exit;
  }

  MaxPolicyBufferSize = mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].PhysicalStart +
                        EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].NumberOfPages) -
                        (UINTN)DrtmSmmPolicyData;
  MaxPolicyBufferSize = (SuppliedBufferSize < MaxPolicyBufferSize) ? SuppliedBufferSize : MaxPolicyBufferSize;
  if (MaxPolicyBufferSize < (sizeof (MM_SUPERVISOR_REQUEST_HEADER) + FirmwarePolicy->Size)) {
    Status = EFI_BUFFER_TOO_SMALL;
    DEBUG ((DEBUG_ERROR, "%a Buffer is too small to fit even just headers: 0x%x\n", __FUNCTION__, MaxPolicyBufferSize));
    goto Exit;
  }

  ZeroMem (DrtmSmmPolicyData, MaxPolicyBufferSize);

  // First off, copy the firmware policy to the buffer
  CopyMem (DrtmSmmPolicyData, FirmwarePolicy, FirmwarePolicy->Size);

  // Then leave the heavy lifting job to the library
  Status = PopulateMemoryPolicyEntries (DrtmSmmPolicyData, MaxPolicyBufferSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Fail to PopulateMemoryPolicyEntries %r\n", __FUNCTION__, Status));
    goto Exit;
  }

  if (CompareMemoryPolicy (DrtmSmmPolicyData, MemPolicySnapshot) == FALSE) {
    DEBUG ((DEBUG_ERROR, "%a Memory policy changed since the snapshot!!!\n", __FUNCTION__));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Status = SecurityPolicyCheck (DrtmSmmPolicyData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Policy check failed - %r\n", __FUNCTION__, Status));
    goto Exit;
  }

  DEBUG_CODE_BEGIN ();
  DumpSmmPolicyData (DrtmSmmPolicyData);
  DEBUG_CODE_END ();

Exit:
  return Status;
}
