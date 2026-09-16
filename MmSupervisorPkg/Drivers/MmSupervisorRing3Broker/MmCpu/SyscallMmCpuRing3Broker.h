/** @file
  Internal header with function declarations for Syscall MM CPU protocol

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#pragma once

extern EFI_MM_CPU_PROTOCOL  mMmCpu;

EFI_STATUS
EFIAPI
SysCallMmReadSaveState (
  IN CONST EFI_MM_CPU_PROTOCOL   *This,
  IN UINTN                       Width,
  IN EFI_MM_SAVE_STATE_REGISTER  Register,
  IN UINTN                       CpuIndex,
  OUT VOID                       *Buffer
  );
