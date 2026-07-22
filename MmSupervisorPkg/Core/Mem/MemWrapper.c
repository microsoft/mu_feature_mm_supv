/** @file
  SMM Memory page management functions.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/SmmCpuFeaturesLib.h>

#include "MmSupervisorCore.h"
#include "Mem.h"

/**
  Allocate pages for code.

  @param[in]  Pages Number of pages to be allocated.

  @return Allocated memory.
**/
VOID *
AllocateCodePages (
  IN UINTN  Pages
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Memory;

  if (Pages == 0) {
    return NULL;
  }

  Status = gMmCoreMmst.MmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, Pages, &Memory);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return (VOID *)(UINTN)Memory;
}

/**
  Helper function that will evaluate the page where the input address is located belongs to a
  user page that is mapped inside MM.

  @param  Address           Target address to be inspected.
  @param  Size              Address range to be inspected.
  @param  IsUserRange       Pointer to hold inspection result, TRUE if the region is in User pages, FALSE if
                            the page is in supervisor pages. Should not be used if return value is not EFI_SUCCESS.

  @return     The result of inspection operation.

**/
EFI_STATUS
InspectTargetRangeOwnership (
  IN  EFI_PHYSICAL_ADDRESS  Address,
  IN  UINTN                 Size,
  OUT BOOLEAN               *IsUserRange
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  AlignedAddress;
  UINT64                Attributes;

  if ((Address < EFI_PAGE_SIZE) || (Size == 0) || (IsUserRange == NULL)) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  AlignedAddress = ALIGN_VALUE (Address - EFI_PAGE_SIZE + 1, EFI_PAGE_SIZE);

  // To cover head portion from "Address" alignment adjustment
  Status = SafeUintnAdd (Size, Address - AlignedAddress, &Size);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // To cover the tail portion of requested buffer range
  Status = SafeUintnAdd (Size, EFI_PAGE_SIZE - 1, &Size);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Size &= ~(EFI_PAGE_SIZE - 1);

  // Go through page table and grab the entry attribute
  Status = SmmGetMemoryAttributes (AlignedAddress, Size, &Attributes);
  if (!EFI_ERROR (Status)) {
    *IsUserRange = ((Attributes & EFI_MEMORY_SP) == 0);
    goto Done;
  }

Done:
  return Status;
}
