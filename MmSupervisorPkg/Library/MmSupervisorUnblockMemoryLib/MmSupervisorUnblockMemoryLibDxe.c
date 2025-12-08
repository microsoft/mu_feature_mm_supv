/** @file
  MM Unblock Page Library Implementation.

  This library provides an abstraction layer of requesting certain page access to be unblocked
  by MM supervisor through MmSupervisorUnblockMemoryProtocol.

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Protocol/MmSupervisorUnblockMemoryProtocol.h>

#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

/**
  This API provides a way to unblock certain data pages to be accessible inside MM environment.

  @param  UnblockAddress          The address of buffer caller requests to unblock, the address
                                  has to be page aligned.
  @param  NumberOfPages           The number of pages requested to be unblocked from MM
                                  environment.

  @return EFI_SUCCESS             The request goes through successfully.
  @return EFI_NOT_AVAILABLE_YET   The requested functionality is not produced yet.
  @return EFI_UNSUPPORTED         The requested functionality is not supported on current platform.
  @return EFI_SECURITY_VIOLATION  The requested address failed to pass security check for
                                  unblocking.
  @return EFI_INVALID_PARAMETER   Input address either NULL pointer or not page aligned.
  @return EFI_ACCESS_DENIED       The request is rejected due to system has passed certain boot
                                  phase.

**/
EFI_STATUS
EFIAPI
MmUnblockMemoryRequest (
  IN EFI_PHYSICAL_ADDRESS  UnblockAddress,
  IN UINT64                NumberOfPages
  )
{
  EFI_STATUS                             Status;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PROTOCOL  *MmSupvUnblockMemoryProtocol = NULL;

  if (gBS == NULL) {
    Status = EFI_NOT_AVAILABLE_YET;
    goto Done;
  }

  Status = gBS->LocateProtocol (&gMmSupervisorUnblockMemoryProtocolGuid, NULL, (VOID **)&MmSupvUnblockMemoryProtocol);
  if (EFI_ERROR (Status)) {
    // Should not happen due to depex requirement
    DEBUG ((DEBUG_ERROR, "%a The unblock protocol has failed to locate - %r\n", __func__, Status));
    Status = EFI_NOT_AVAILABLE_YET;
    goto Done;
  }

  Status = MmSupvUnblockMemoryProtocol->RequestUnblockPages (UnblockAddress, NumberOfPages, &gEfiCallerIdGuid);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a The unblock request has failed - %r\n", __func__, Status));
  }

Done:
  return Status;
}
