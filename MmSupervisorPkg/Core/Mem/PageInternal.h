/** @file
  Internal declarations shared between Page.c (the SMM memory page management
  store, linked into both Core and Init builds) and Page_init.c (Init-only
  HOB serialization that walks the same gMemoryMap list).

  These declarations are intentionally NOT exported via Mem/Mem.h -- they are
  private to this pair of source files.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_PAGE_INTERNAL_H_
#define _MM_SUPV_PAGE_INTERNAL_H_

#define MEMORY_MAP_SIGNATURE  SIGNATURE_32 ('m', 'm', 'a', 'p')

typedef struct {
  UINTN              Signature;
  LIST_ENTRY         Link;

  BOOLEAN            FromStack;
  BOOLEAN            IsSupervisorPage;
  EFI_MEMORY_TYPE    Type;
  UINT64             Start;
  UINT64             End;
} MEMORY_MAP;

extern LIST_ENTRY  gMemoryMap;

#endif // _MM_SUPV_PAGE_INTERNAL_H_
