/** @file
  Routines of gathering version information for MmSupervisor

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (C) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Guid/MmSupervisorRequestData.h>

#include <Library/BaseLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/SafeIntLib.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"

/**
  Get the version and SPL value of SmmSupervisor driver from its image in MMRAM

  @param[out] Version             Pointer to hold returned supervisor image version.
  @param[out] SmmSupSplValue      Pointer to hold returned supervisor patch level version.

  @retval  EFI_SUCCESS            The versions are successfully located.
  @retval  EFI_INVALID_PARAMETER  Input pointers are NULL.
  @retval  EFI_COMPROMISED_DATA   Failed minimal check for PeCoff of supervisor image.
**/
STATIC
EFI_STATUS
GetSmmSupervisorVersionAndSplValue (
  OUT UINT32  *Version,
  OUT UINT32  *SmmSupSplValue
  )
{
  VOID                    *LocalRomImage;
  EFI_IMAGE_DOS_HEADER    *ImageDosHdr;
  EFI_IMAGE_NT_HEADERS64  *ImageNt64Hdr;

  if ((Version == NULL) || (SmmSupSplValue == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  LocalRomImage = (VOID *)(UINTN)mMmCoreDriverEntry->ImageBuffer;

  ImageDosHdr = (EFI_IMAGE_DOS_HEADER *)LocalRomImage;
  if (ImageDosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "Failed to get SmmSupervisor version: invalid Dos signature\n"));
    return EFI_COMPROMISED_DATA;
  }

  ImageNt64Hdr = (EFI_IMAGE_NT_HEADERS64 *)(((CHAR8 *)ImageDosHdr) + ImageDosHdr->e_lfanew);
  if (ImageNt64Hdr->Signature != EFI_IMAGE_NT_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "Failed to get SmmSupervisor version: invalid NT signature\n"));
    return EFI_COMPROMISED_DATA;
  }

  if (ImageNt64Hdr->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    DEBUG ((DEBUG_ERROR, "Failed to get SmmSupervisor version: invalid PE64 signature\n"));
    return EFI_COMPROMISED_DATA;
  }

  *Version        = ((ImageNt64Hdr->OptionalHeader.MajorSubsystemVersion << 16) | (ImageNt64Hdr->OptionalHeader.MinorSubsystemVersion));
  *SmmSupSplValue = ((ImageNt64Hdr->OptionalHeader.MajorImageVersion << 16) | (ImageNt64Hdr->OptionalHeader.MinorImageVersion));

  DEBUG ((DEBUG_INFO, "MmSupervisor version: 0x%x, Patch level: 0x%x\n", *Version, *SmmSupSplValue));

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;

  if (!mCoreInitializationComplete) {
    // The pool is not open yet...
    return EFI_ACCESS_DENIED;
  }

  if (VersionInfoBuffer == NULL) {
    Status = EFI_INVALID_PARAMETER;
    DEBUG ((DEBUG_ERROR, "%a Input argument is a null pointer!!!\n", __FUNCTION__));
    goto Exit;
  }

  Status = VerifyRequestSupvCommBuffer (VersionInfoBuffer, sizeof (MM_SUPERVISOR_VERSION_INFO_BUFFER));
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Input buffer %p is illegal - %r!!!\n", __FUNCTION__, VersionInfoBuffer, Status));
    goto Exit;
  }

  // Enough complaints, now get to work.
  VersionInfoBuffer->MaxSupervisorRequestLevel = MM_SUPERVISOR_REQUEST_MAX_SUPPORTED;
  DEBUG ((
    DEBUG_ERROR,
    "%a Current supervisor maximal request level is 0x%x\n",
    __FUNCTION__,
    VersionInfoBuffer->MaxSupervisorRequestLevel
    ));

  Status = GetSmmSupervisorVersionAndSplValue (
             &VersionInfoBuffer->Version,
             &VersionInfoBuffer->PatchLevel
             );

Exit:
  ASSERT_EFI_ERROR (Status);
  return Status;
} // ProcessVersionInfoRequest()
