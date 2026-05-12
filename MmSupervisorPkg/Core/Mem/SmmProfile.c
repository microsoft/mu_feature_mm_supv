/** @file
Enable SMM profile.

Copyright (c) 2012 - 2023, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017 - 2020, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"
#include "SmmProfileInternal.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"

//
// The flag indicates if BTS is supported by processor.
//
BOOLEAN  mBtsSupported = TRUE;

/**
  Get CPU Index from APIC ID.

**/
UINTN
GetCpuIndex (
  VOID
  )
{
  UINTN   Index;
  UINT32  ApicId;

  ApicId = GetApicId ();

  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId == ApicId) {
      return Index;
    }
  }

  ASSERT (FALSE);
  return 0;
}

/**
  Update page table according to protected memory ranges and the 4KB-page mapped memory ranges.

**/
VOID
InitPaging (
  VOID
  )
{
  RETURN_STATUS  Status;
  UINTN          Index;
  UINTN          PageTable;
  UINT64         Base;
  UINT64         Limit;
  UINT64         PreviousAddress;
  UINT64         MemoryAttrMask;

  PERF_FUNCTION_BEGIN ();

  GetPageTable (&PageTable, NULL);
  if (sizeof (UINTN) == sizeof (UINT32)) {
    Limit = BASE_4GB;
  } else {
    Limit = (IsRestrictedMemoryAccess ()) ? LShiftU64 (1, mPhysicalAddressBits) : BASE_4GB;
  }

  //
  // [0, 4k] may be non-present.
  //
  // MU_CHANGE: MM_SUPV: Null pointer is enabled regardless for this module
  PreviousAddress = BASE_4KB;

  DEBUG ((DEBUG_INFO, "Patch page table start ...\n"));
  MemoryAttrMask = EFI_MEMORY_XP;
  for (Index = 0; Index < mSmmCpuSmramRangeCount; Index++) {
    Base = mSmmCpuSmramRanges[Index].CpuStart;
    if (Base > PreviousAddress) {
      //
      // Mark the ranges not in mSmmCpuSmramRanges as NX.
      //
      Status = ConvertMemoryPageAttributes (PageTable, mPagingMode, PreviousAddress, Base - PreviousAddress, MemoryAttrMask, TRUE, NULL);
      ASSERT_RETURN_ERROR (Status);
    }

    PreviousAddress = mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize;
  }

  if (PreviousAddress < Limit) {
    //
    // Set the last remaining range to EFI_MEMORY_RP/EFI_MEMORY_XP.
    // This path applies to both SmmProfile enable/disable case.
    //
    Status = ConvertMemoryPageAttributes (PageTable, mPagingMode, PreviousAddress, Limit - PreviousAddress, MemoryAttrMask, TRUE, NULL);
    ASSERT_RETURN_ERROR (Status);
  }

  //
  // Flush TLB
  //
  CpuFlushTlb ();
  DEBUG ((DEBUG_INFO, "Patch page table done!\n"));

  PERF_FUNCTION_END ();
}
