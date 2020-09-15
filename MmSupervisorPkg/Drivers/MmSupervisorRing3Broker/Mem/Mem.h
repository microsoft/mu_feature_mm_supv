/** @file
  The internal header file that declared a data structure that is shared
  between the MM IPL and the MM Core.

  Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_USER_MEM_H_
#define MM_USER_MEM_H_

//
// Pool management
//

//
// MIN_POOL_SHIFT must not be less than 5
//
#define MIN_POOL_SHIFT  6
#define MIN_POOL_SIZE   (1 << MIN_POOL_SHIFT)

//
// MAX_POOL_SHIFT must not be less than EFI_PAGE_SHIFT - 1
//
#define MAX_POOL_SHIFT  (EFI_PAGE_SHIFT - 1)
#define MAX_POOL_SIZE   (1 << MAX_POOL_SHIFT)

//
// MAX_POOL_INDEX are calculated by maximum and minimum pool sizes
//
#define MAX_POOL_INDEX  (MAX_POOL_SHIFT - MIN_POOL_SHIFT + 1)

#define POOL_HEAD_SIGNATURE  SIGNATURE_32('s','p','h','d')

typedef struct {
  UINT32             Signature;
  BOOLEAN            Available;
  EFI_MEMORY_TYPE    Type;
  UINTN              Size;
} POOL_HEADER;

#define POOL_TAIL_SIGNATURE  SIGNATURE_32('s','p','t','l')

typedef struct {
  UINT32    Signature;
  UINT32    Reserved;
  UINTN     Size;
} POOL_TAIL;

#define POOL_OVERHEAD  (sizeof(POOL_HEADER) + sizeof(POOL_TAIL))

#define HEAD_TO_TAIL(a)   \
  ((POOL_TAIL *) (((CHAR8 *) (a)) + (a)->Size - sizeof(POOL_TAIL)));

typedef struct {
  POOL_HEADER    Header;
  LIST_ENTRY     Link;
} FREE_POOL_HEADER;

typedef enum {
  MmPoolTypeCode,
  MmPoolTypeData,
  MmPoolTypeMax,
} MM_POOL_TYPE;

extern LIST_ENTRY  mMmMemoryMap;
extern LIST_ENTRY  mMmPoolLists[MmPoolTypeMax][MAX_POOL_INDEX];

#endif
