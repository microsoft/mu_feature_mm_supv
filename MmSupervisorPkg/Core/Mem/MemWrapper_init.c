/** @file
  Init (MmSupervisorInit) communicate-buffer validation stub.

  Linked only into MmSupervisorInit.  At init time there is no MMI dispatcher
  to invoke and no internal supervisor communicate buffer has been allocated,
  so any caller asking us to validate a supervisor communicate buffer is
  asserted to never happen and is rejected as a security violation.
  The runtime equivalent lives in MemWrapper_core.c.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/DebugLib.h>

/**
  Helper function to validate legitimacy for incoming supervisor communcate buffer for MMI handlers.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestSupvCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize
  )
{
  ASSERT (FALSE);
  return EFI_SECURITY_VIOLATION;
}
