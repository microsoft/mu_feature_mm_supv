/** @file
  Provides unblocked memory query function interfaces implemented
  in MM Supervisor.

Copyright (C) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPV_MEM_UNBLOCK_SERVICES_
#define MM_SUPV_MEM_UNBLOCK_SERVICES_

/**
  Helper function to check if range requested is within boundary of unblocked lists.
  This routine is simple and do not merge adjacent regions from two entries into one.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @return TRUE      The queried region is within unblocked range.
  @return FALSE     The queried region is outside of unblocked range.

**/
BOOLEAN
EFIAPI
IsWithinUnblockedRegion (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  );

#endif // MM_SUPV_MEM_UNBLOCK_SERVICES_
