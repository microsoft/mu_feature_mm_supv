/** @file
  Instance of MM memory check library.

  MM memory check library library implementation. This library consumes MM_ACCESS_PROTOCOL
  to get MMRAM information. In order to use this library instance, the platform should produce
  all MMRAM range via MM_ACCESS_PROTOCOL, including the range for firmware (like MM Core
  and MM driver) and/or specific dedicated hardware.

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/SysCallLib.h>

/**
  This function check if the buffer is valid per processor architecture and not overlap with MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This buffer is valid per processor architecture and not overlap with MMRAM.
  @retval FALSE This buffer is not valid per processor architecture or overlap with MMRAM.
**/
BOOLEAN
EFIAPI
MmIsBufferOutsideMmValid (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  UINT64  Ret;

  Ret = SysCall (SMM_MM_UNBLOCKED, Buffer, Length, 0);

  return (BOOLEAN)Ret;
}

/**
  This function should be used for MMI handlers to check if the communicate buffer is valid.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This communicate buffer is valid per processor architecture.
  @retval FALSE This communicate buffer is not valid per processor architecture.
**/
BOOLEAN
EFIAPI
MmCommBufferValid (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  EFI_STATUS  Ret;

  Ret = (EFI_STATUS)SysCall (SMM_MM_IS_COMM_BUFF, Buffer, Length, 0);

  return !EFI_ERROR (Ret);
}
