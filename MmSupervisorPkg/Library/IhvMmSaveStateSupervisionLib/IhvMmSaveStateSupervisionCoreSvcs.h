/** @file
  Header file that includes supervisor services.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef IHV_MM_SAVE_STATE_CORE_SVCS_H_
#define IHV_MM_SAVE_STATE_CORE_SVCS_H_

/**
  Read information from the CPU save state.

  @param  This      EFI_SMM_CPU_PROTOCOL instance
  @param  Width     The number of bytes to read from the CPU save state.
  @param  Register  Specifies the CPU register to read form the save state.
  @param  CpuIndex  Specifies the zero-based index of the CPU save state.
  @param  Buffer    Upon return, this holds the CPU register value read from the save state.

  @retval EFI_SUCCESS   The register was read from Save State
  @retval EFI_NOT_FOUND The register is not defined for the Save State of Processor
  @retval EFI_INVALID_PARAMETER   This or Buffer is NULL.

**/
EFI_STATUS
EFIAPI
SmmReadSaveState (
  IN CONST EFI_MM_CPU_PROTOCOL   *This,
  IN UINTN                       Width,
  IN EFI_MM_SAVE_STATE_REGISTER  Register,
  IN UINTN                       CpuIndex,
  OUT VOID                       *Buffer
  );

#endif // IHV_MM_SAVE_STATE_CORE_SVCS_H_
