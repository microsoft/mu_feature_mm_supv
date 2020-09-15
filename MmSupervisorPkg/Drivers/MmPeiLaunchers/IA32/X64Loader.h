/** @file
  Internal interface definition used to thunk system into long mode to launch MM core.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef X64_LOADER_H_
#define X64_LOADER_H_

/**
  Locates the X64Relay image entry point, and execute it in long mode.

  @param[in]  MmEntryPoint    Pointer to MM core image entrypoint.
  @param[in]  HobStart        Pointer to the start of HOBs in non-MM environment.

  @retval EFI_SUCCESS     MM foundation is set successfully.
  @retval EFI_NOT_FOUND   Failed to locate the X64Relay image.
  @retval Others          Other failures returned from MM Core or during long mode bootstrap.

 **/
EFI_STATUS
SetMmFoundationInX64Relay (
  IN  STANDALONE_MM_FOUNDATION_ENTRY_POINT  MmEntryPoint,
  IN  VOID                                  *HobStart
  );

#endif // X64_LOADER_H_
