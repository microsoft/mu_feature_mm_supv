/** @file
  EFI MM Scratch Page Allocation Protocol.

  This protocol provides a means of allocating pages that will be accessible during
  runtime and MM environment.

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SCRATCH_PAGE_ALLOC_H_
#define _MM_SCRATCH_PAGE_ALLOC_H_

#define MM_SUPERVISOR_PAGE_ALLOCATION_PROTOCOL_GUID \
  { \
    0x3a5446ad, 0x2023, 0x45f9, { 0xad, 0xdf, 0xba, 0x48, 0xf3, 0xa6, 0xe2, 0xbc } \
  }

typedef struct _MM_ALLOCATE_SCRATCH_PAGE MM_ALLOCATE_SCRATCH_PAGE;

extern EFI_GUID  gMmScratchPageAllocationProtocolGuid;

/**
  This API provides a way to allocate scratch for third party usage.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.
  @param  MemoryType            Only suppots EfiACPIMemoryNVS and EfiRuntimeServicesData.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
typedef
VOID *
(EFIAPI *ALLOCATE_SCRATCH_PAGE)(
  IN UINTN              Pages,
  IN EFI_MEMORY_TYPE    MemoryType
  );

struct _MM_ALLOCATE_SCRATCH_PAGE {
  ALLOCATE_SCRATCH_PAGE    MmAllocateScratchPages;
};

#endif
