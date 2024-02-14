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
  Allocate aligned pages for code.

  @param[in]  Pages                 Number of pages to be allocated.
  @param[in]  Alignment             The requested alignment of the allocation.
                                    Must be a power of two.
                                    If Alignment is zero, then byte alignment is used.

  @return Allocated memory.
**/
VOID *
AllocateAlignedCodePages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Memory;
  UINTN                 AlignedMemory;
  UINTN                 AlignmentMask;
  UINTN                 UnalignedPages;
  UINTN                 RealPages;

  //
  // Alignment must be a power of two or zero.
  //
  ASSERT ((Alignment & (Alignment - 1)) == 0);

  if (Pages == 0) {
    return NULL;
  }

  if (Alignment > EFI_PAGE_SIZE) {
    //
    // Calculate the total number of pages since alignment is larger than page size.
    //
    AlignmentMask = Alignment - 1;
    RealPages     = Pages + EFI_SIZE_TO_PAGES (Alignment);
    //
    // Make sure that Pages plus EFI_SIZE_TO_PAGES (Alignment) does not overflow.
    //
    ASSERT (RealPages > Pages);

    Status = gMmCoreMmst.MmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, RealPages, &Memory);
    if (EFI_ERROR (Status)) {
      return NULL;
    }

    AlignedMemory  = ((UINTN)Memory + AlignmentMask) & ~AlignmentMask;
    UnalignedPages = EFI_SIZE_TO_PAGES (AlignedMemory - (UINTN)Memory);
    if (UnalignedPages > 0) {
      //
      // Free first unaligned page(s).
      //
      Status = gMmCoreMmst.MmFreePages (Memory, UnalignedPages);
      ASSERT_EFI_ERROR (Status);
    }

    Memory         = AlignedMemory + EFI_PAGES_TO_SIZE (Pages);
    UnalignedPages = RealPages - Pages - UnalignedPages;
    if (UnalignedPages > 0) {
      //
      // Free last unaligned page(s).
      //
      Status = gMmCoreMmst.MmFreePages (Memory, UnalignedPages);
      ASSERT_EFI_ERROR (Status);
    }
  } else {
    //
    // Do not over-allocate pages in this case.
    //
    Status = gMmCoreMmst.MmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, Pages, &Memory);
    if (EFI_ERROR (Status)) {
      return NULL;
    }

    AlignedMemory = (UINTN)Memory;
  }

  return (VOID *)AlignedMemory;
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

/**
  Helper function to validate legitimacy for incoming communcate buffer for MMI handler.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.
  @param  CommBufferType  Type of the CommBuffer being evaluated, i.e. MM_SUPERVISOR_BUFFER_T or
                          MM_USER_BUFFER_T.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize,
  IN  UINTN  CommBufferType
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  CommBuffStart;
  EFI_PHYSICAL_ADDRESS  CommBuffEnd;
  EFI_PHYSICAL_ADDRESS  InternalBuffSize;
  EFI_PHYSICAL_ADDRESS  InternalBuffEnd;

  if (CommBufferType >= MM_OPEN_BUFFER_CNT) {
    DEBUG ((DEBUG_ERROR, "%a Unrecognized buffer type requested - %x!!!\n", __FUNCTION__, CommBufferType));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  CommBuffStart = (EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer;
  Status        = SafeUint64Add (CommBuffStart, CommBufferSize, &CommBuffEnd);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Buffer end calculation failed - %r!!!\n", __FUNCTION__, Status));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Status = SafeUint64Mult (mMmSupervisorAccessBuffer[CommBufferType].NumberOfPages, EFI_PAGE_SIZE, &InternalBuffSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Supervisor buffer size calculation failed - %r!!!\n", __FUNCTION__, Status));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  Status = SafeUint64Add ((UINTN)mInternalCommBufferCopy[CommBufferType], InternalBuffSize, &InternalBuffEnd);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Supervisor buffer end calculation failed - %r!!!\n", __FUNCTION__, Status));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  if ((CommBuffStart < (EFI_PHYSICAL_ADDRESS)(UINTN)mInternalCommBufferCopy[CommBufferType]) ||
      (CommBuffEnd > InternalBuffEnd))
  {
    Status = EFI_SECURITY_VIOLATION;
    DEBUG ((
      DEBUG_ERROR,
      "%a Input argument %p - %p does not reside in designated communication buffer %p - %p\n",
      __FUNCTION__,
      CommBuffer,
      CommBuffEnd,
      mInternalCommBufferCopy[CommBufferType],
      InternalBuffEnd
      ));
    goto Exit;
  }

Exit:
  return Status;
}

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
  return VerifyRequestCommBuffer (
           CommBuffer,
           CommBufferSize,
           MM_SUPERVISOR_BUFFER_T
           );
}

/**
  Helper function to validate legitimacy for incoming user communcate buffer for MMI handlers.

  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return EFI_SUCCESS             The incoming communicate buffer is legitimate.
  @return EFI_SECURITY_VIOLATION  The incoming communicate buffer violate certain security rules.
**/
EFI_STATUS
EFIAPI
VerifyRequestUserCommBuffer (
  IN  VOID   *CommBuffer,
  IN  UINTN  CommBufferSize
  )
{
  return VerifyRequestCommBuffer (
           CommBuffer,
           CommBufferSize,
           MM_USER_BUFFER_T
           );
}
