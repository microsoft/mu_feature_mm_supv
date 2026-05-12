/** @file
  The internal header file includes routines supporting MM Supervisor requests.

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_REQUEST_H_
#define _MM_SUPV_REQUEST_H_

/**
  Routine used to validate and unblock requested region to be accessible in MM
  environment. Given this routine could received untrusted data, the requested
  memory region has to be already mapped as "not present" prior to this request.
  For requests that pass security checks, the region will be marked as R/W data
  page, while the page ownership (supervisor vs. user) is determined by whether
  EFI_MEMORY_SP bit of memory descriptor's attribute is set or not.

  @param[in]  UnblockMemParams  Input unblock parameters conveyed from non-MM environment

  @retval EFI_SUCCESS             The requested region properly unblocked.
  @retval EFI_ACCESS_DENIED       The request was made post lock down event.
  @retval EFI_INVALID_PARAMETER   UnblockMemParams or its ID GUID is null pointer.
  @retval EFI_SECURITY_VIOLATION  The requested region has illegal page attributes.
  @retval EFI_OUT_OF_RESOURCES    The unblocked database failed to log new entry after
                                  processing this request.
  @retval Others                  Page attribute setting/clearing routine has failed.

**/
EFI_STATUS
ProcessUnblockPages (
  IN MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *UnblockMemParams
  );

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
  );

/**
  Function that returns supervisor version information to requesting entity.
  Calling this function will also block the supervisor memory pages from being updated.

  @param[out] VersionInfoBuffer     Pointer to hold returned version information structure.

  @retval EFI_SUCCESS               The security policy is successfully gathered.
  @retval EFI_SECURITY_VIOLATION    If VersionInfoBuffer buffer is not pointing to designated supervisor buffer
  @retval EFI_ACCESS_DENIED         If request occurs before MM foundation is setup.
  @retval EFI_COMPROMISED_DATA      Supervisor image buffer does not pass minimal PeCoff check.

 **/
EFI_STATUS
ProcessVersionInfoRequest (
  OUT MM_SUPERVISOR_VERSION_INFO_BUFFER  *VersionInfoBuffer
  );

/**
  Routine used to update communication buffers and core private mailbox region
  to the updated location. Given this routine could receive untrusted data, the
  old memory region has to be already properly unblocked prior to this request and
  the received new buffer has to persist exactly the same memory length and attribute
  as before. For requests that pass security checks, the new region will be marked
  as R/W supervisor data page. The old buffers will be blocked after this routine,
  and new return status will be populated to the new address. The caller should be
  prepared to check data from newly supplied region upon returning.

  @param[in]  UpdateCommBuffer  Input new comm buffer parameters conveyed from non-MM environment

  @retval EFI_SUCCESS             The requested region properly unblocked.
  @retval EFI_ACCESS_DENIED       The request was made post lock down event.
  @retval EFI_INVALID_PARAMETER   UnblockMemParams or its ID GUID is null pointer.
  @retval EFI_SECURITY_VIOLATION  The requested region has illegal page attributes.
  @retval EFI_OUT_OF_RESOURCES    The unblocked database failed to log new entry after
                                  processing this request.
  @retval Others                  Page attribute setting/clearing routine has failed.

**/
EFI_STATUS
ProcessUpdateCommBufferRequest (
  IN MM_SUPERVISOR_COMM_UPDATE_BUFFER  *UpdateCommBuffer
  );

#endif // _MM_SUPV_REQUEST_H_
