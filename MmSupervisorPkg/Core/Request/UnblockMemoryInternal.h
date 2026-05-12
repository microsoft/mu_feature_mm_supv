/** @file
  Internal declarations shared among the unblock memory request handler trio:
    * UnblockMemory.c       -- shared list helpers and VerifyUnblockRequest
    * UnblockMemory_core.c  -- Core build (MmSupervisorCore.inf) function bodies
    * UnblockMemory_init.c  -- Init build (MmSupervisorInit.inf) function bodies

  These declarations are intentionally NOT exported via Request/Request.h --
  they are private to this trio of source files.

  Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
  Copyright (C) Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_UNBLOCK_MEMORY_INTERNAL_H_
#define _MM_SUPV_UNBLOCK_MEMORY_INTERNAL_H_

#include <Guid/MmSupervisorRequestData.h>

typedef struct {
  LIST_ENTRY                             Link;
  MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS    UnblockMemData;
} UNBLOCKED_MEM_LIST;

extern LIST_ENTRY  mUnblockedMemoryList;

/**
  Check if requested memory region is already unblocked.

  Defined in shared UnblockMemory.c; consumed by ProcessUnblockPages in both
  UnblockMemory_core.c and UnblockMemory_init.c.

  @return Status Code

**/
EFI_STATUS
VerifyUnblockRequest (
  IN CONST MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *RequestedData
  );

#endif // _MM_SUPV_UNBLOCK_MEMORY_INTERNAL_H_
