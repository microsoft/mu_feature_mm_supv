/** @file
Include file for construction of the MM Supervisor HOB list.

Init (MmSupervisorInit) only: the runtime MmSupervisorCore driver consumes the
HOB list this module produces, it never builds one.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPV_INIT_HOBS_H_
#define MM_SUPV_INIT_HOBS_H_

//
// Tracks construction of the supervisor HOB list. The region is sized and
// allocated up front by SupvInitHobsInit, then each producer appends at
// Cursor and reports how much space it used so the builder can advance.
//
typedef struct {
  EFI_PHYSICAL_ADDRESS    Base;
  EFI_PHYSICAL_ADDRESS    Cursor;
  UINT64                  Remaining;
} MM_SUPV_INIT_HOB_BUILDER;

/**
  Size, allocate and seed the supervisor HOB region.

  Reserves a supervisor allocation large enough for the inbound HOB list plus the
  MMRAM descriptors that get regenerated later, copies the inbound list into it,
  and leaves the builder positioned just after the copied entries. Also publishes
  the region through mMmHobStart / mMmHobSize.

  The inbound MMRAM descriptor HOBs are dropped on the way in, because
  SupvInitHobsAddMmramDescriptors rebuilds them from the final memory map once
  every supervisor allocation is done.

  Does not return if the region cannot be sized or allocated.

  @param[out]  Builder  Receives the initialized builder state.
**/
VOID
SupvInitHobsInit (
  OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  );

/**
  Append the memory allocation module HOBs describing the supervisor core, the
  user module and every driver discovered for dispatch.

  Must be called after the modules have been loaded.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to append to.

  @retval EFI_SUCCESS            The module allocation HOBs were successfully appended.
  @retval EFI_BUFFER_TOO_SMALL   The HOB region is too small to hold the module allocation HOBs.
  @retval EFI_INVALID_PARAMETER  The Builder is NULL or invalid.
**/
EFI_STATUS
SupvInitHobsAddModuleAllocations (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  );

/**
  Append the pass down HOB describing what the supervisor set up for the runtime.

  Must be called after the common buffers and the firmware policy are in place.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to append to.

  @retval EFI_SUCCESS           The pass down HOB was successfully appended.
  @retval EFI_INVALID_PARAMETER One or more of the input parameters are invalid.
  @retval EFI_BUFFER_TOO_SMALL  The HOB region is too small to append the pass down HOB.
**/
EFI_STATUS
SupvInitHobsAddPassDown (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  );

/**
  Append the guided HOB describing the final MMRAM layout.

  Must be called after the lock step, which is the last thing that allocates, so
  that the supervisor memory map this is derived from is final.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to append to.
**/
VOID
SupvInitHobsAddMmramDescriptors (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  );

/**
  Terminate the supervisor HOB list with an end-of-HOB marker.

  Does not return if the supervisor HOB region is too small.

  @param[in,out]  Builder  The HOB builder to terminate.
**/
VOID
SupvInitHobsFinalize (
  IN OUT MM_SUPV_INIT_HOB_BUILDER  *Builder
  );

#endif // MM_SUPV_INIT_HOBS_H_
