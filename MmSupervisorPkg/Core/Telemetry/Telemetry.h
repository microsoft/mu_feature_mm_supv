/** @file
Include file for MM Supervisor telemetry reporting implementation.

Copyright (c) 2011 - 2015, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_TELEMETRY_H_
#define _MM_SUPV_TELEMETRY_H_

/**
  Routine for error reporting inside supervisor exception handlers.

  Note: This routine should be called atomically.

  @param  InterruptType         Defines which interrupt or exception to hook. Type EFI_EXCEPTION_TYPE and
                                the valid values for this parameter are defined in EFI_DEBUG_SUPPORT_PROTOCOL
                                of the UEFI 2.0 specification.
  @param  SystemContext         Pointer to EFI_SYSTEM_CONTEXT, inherited from register exception handlers.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval EFI_OUT_OF_RESOURCES  Telemetry data cannot fit in the user page supervisor allocated.
  @retval EFI_NOT_READY         There is no error reporting handler registered at the point of exception.
  @retval EFI Errors            Other errors from other routines inside this function.

**/
EFI_STATUS
EFIAPI
PrepareNReportError (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  );

/**
  Initialize exception handler for all unregistered types.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed.
  @retval EFI Errors            Other errors from other routines inside this function.
**/
EFI_STATUS
CoalesceLooseExceptionHandlers (
  VOID
  );

#endif // _MM_SUPV_TELEMETRY_H_
