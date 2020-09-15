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
#include "MmSupervisorMemoryUnblockServices.h"

//
// Maximum support address used to check input buffer
//
extern EFI_PHYSICAL_ADDRESS  mMmMemLibInternalMaximumSupportAddress;
extern EFI_MMRAM_DESCRIPTOR  *mMmMemLibInternalMmramRanges;
extern UINTN                 mMmMemLibInternalMmramCount;

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
  );

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
  UINTN  Index;

  //
  // Check override.
  // NOTE: (B:0->L:4G) is invalid for IA32, but (B:1->L:4G-1)/(B:4G-1->L:1) is valid.
  //
  if ((Length > mMmMemLibInternalMaximumSupportAddress) ||
      (Buffer > mMmMemLibInternalMaximumSupportAddress) ||
      ((Length != 0) && (Buffer > (mMmMemLibInternalMaximumSupportAddress - (Length - 1)))))
  {
    //
    // Overflow happen
    //
    DEBUG ((
      DEBUG_ERROR,
      "MmIsBufferOutsideMmValid: Overflow: Buffer (0x%lx) - Length (0x%lx), MaximumSupportAddress (0x%lx)\n",
      Buffer,
      Length,
      mMmMemLibInternalMaximumSupportAddress
      ));
    return FALSE;
  }

  for (Index = 0; Index < mMmMemLibInternalMmramCount; Index++) {
    if (((Buffer >= mMmMemLibInternalMmramRanges[Index].CpuStart) &&
         (Buffer < mMmMemLibInternalMmramRanges[Index].CpuStart + mMmMemLibInternalMmramRanges[Index].PhysicalSize)) ||
        ((mMmMemLibInternalMmramRanges[Index].CpuStart >= Buffer) &&
         (mMmMemLibInternalMmramRanges[Index].CpuStart < Buffer + Length)))
    {
      DEBUG ((
        DEBUG_ERROR,
        "MmIsBufferOutsideMmValid: Overlap: Buffer (0x%lx) - Length (0x%lx), ",
        Buffer,
        Length
        ));
      DEBUG ((
        DEBUG_ERROR,
        "CpuStart (0x%lx) - PhysicalSize (0x%lx)\n",
        mMmMemLibInternalMmramRanges[Index].CpuStart,
        mMmMemLibInternalMmramRanges[Index].PhysicalSize
        ));
      return FALSE;
    }
  }

  return IsWithinUnblockedRegion (Buffer, Length);
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
  EFI_STATUS  Status;

  Status = VerifyRequestSupvCommBuffer (
             (VOID *)(UINTN)Buffer,
             Length
             );
  return !EFI_ERROR (Status);
}
