/** @file
  MM Core Main Entry Point

  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Register/Msr.h>
#include <Register/Cpuid.h>

#include <Library/BaseLib.h>
#include <Library/SafeIntLib.h>
#include <Library/BaseMemoryLib.h>

#include "Runtime/StmRuntime.h"

/**
  Helper function to check if two ranges overlap.

  @param[in] Start1    Start address of the first range.
  @param[in] Size1     Size of the first range.
  @param[in] Start2    Start address of the second range.
  @param[in] Size2     Size of the second range.
  @param[out] Overlap  TRUE if the two ranges overlap, FALSE otherwise.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  Overlap is NULL.
  @retval other error value
**/
EFI_STATUS
EFIAPI
TwoRangesOverlap (
  IN UINT64    Start1,
  IN UINT64    Size1,
  IN UINT64    Start2,
  IN UINT64    Size2,
  OUT BOOLEAN  *Overlap
  )
{
  UINT64      End1;
  UINT64      End2;
  EFI_STATUS  Status;

  if (Overlap == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SafeUint64Add (Start1, Size1, &End1);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Status = SafeUint64Add (Start2, Size2, &End2);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  *Overlap = FALSE;

  // For two ranges to overlap, one of the following conditions must be true:
  // 1. Start1 falls into range 2
  // 2. Start2 falls into range 1
  if ((Start1 <= Start2) && (Start2 < End1)) {
    *Overlap = TRUE;
  }

  if ((Start2 <= Start1) && (Start1 < End2)) {
    *Overlap = TRUE;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length in bytes to be checked.

  @retval TRUE  This buffer is not part of MMRAM.
  @retval FALSE This buffer is from MMRAM.
**/
BOOLEAN
EFIAPI
IsBufferInsideMmram (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  UINT64                          MmRamBase;
  UINT64                          MmRamLength;
  UINT64                          MmrrMask;
  UINT32                          MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX  VirPhyAddressSize;
  UINT64                          MtrrValidBitsMask;
  UINT64                          MtrrValidAddressMask;
  BOOLEAN                         IsInside;
  EFI_STATUS                      Status;

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunction, NULL, NULL, NULL);

  if (MaxExtendedFunction >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  MtrrValidBitsMask    = LShiftU64 (1, VirPhyAddressSize.Bits.PhysicalAddressBits) - 1;
  MtrrValidAddressMask = MtrrValidBitsMask & 0xfffffffffffff000ULL;

  MmRamBase = AsmReadMsr64 (MSR_IA32_SMRR_PHYSBASE);
  MmrrMask  = AsmReadMsr64 (MSR_IA32_SMRR_PHYSMASK);
  // Extend the mask to account for the reserved bits.
  MmrrMask   |= 0xffffffff00000000ULL;
  MmRamLength = ((~(MmrrMask & MtrrValidAddressMask)) & MtrrValidBitsMask) + 1;

  Status = Range1InsideRange2 (Buffer, Length, MmRamBase, MmRamLength, &IsInside);
  if (EFI_ERROR (Status)) {
    IsInside = FALSE;
  }

  return IsInside;
}
