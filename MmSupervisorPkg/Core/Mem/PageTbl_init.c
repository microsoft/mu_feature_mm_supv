/** @file
  Init (MmSupervisorInit) page-table runtime stubs.

  Linked only into MmSupervisorInit.  At init time we never own the SMI entry
  asm thunk and we never service #PF exceptions, so SmiPagingPatch5LevelHook()
  is a no-op and SmiPFHandler() is not provided at all.  See PageTbl_core.c
  for the runtime implementations.

  Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

/**
  Patch the prebuilt SMI-entry assembly thunk's 5-level-paging-needed slot.

  No-op for the init driver: we do not own the SMI entry handler.

  @param[in]  M5LevelPagingNeeded  Ignored.
**/
VOID
SmiPagingPatch5LevelHook (
  IN BOOLEAN  M5LevelPagingNeeded
  )
{
}
