/** @file
  SMM STM support

  Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_STM_H_
#define _SMM_STM_H_

#include <Protocol/SmMonitorInit.h>

/**

  Create 4G page table for STM.
  2M PAE page table in X64 version.

  @param PageTableBase        The page table base in MSEG

**/
VOID
StmGen4GPageTable (
  IN UINTN  PageTableBase
  );

/**
  This is SMM exception handle.
  Consumed by STM when exception happen.

  @param Context  STM protection exception stack frame

  @return the EBX value for STM reference.
          EBX = 0: resume SMM guest using register state found on exception stack.
          EBX = 1 to 0x0F: EBX contains a BIOS error code which the STM must record in the
                           TXT.ERRORCODE register and subsequently reset the system via
                           TXT.CMD.SYS_RESET. The value of the TXT.ERRORCODE register is calculated as
                           follows: TXT.ERRORCODE = (EBX & 0x0F) | STM_CRASH_BIOS_PANIC
          EBX = 0x10 to 0xFFFFFFFF - reserved, do not use.

**/
UINT32
EFIAPI
SmmStmExceptionHandler (
  IN OUT STM_PROTECTION_EXCEPTION_STACK_FRAME  Context
  );

/**

  Get STM state.

  @return STM state

**/
EFI_SM_MONITOR_STATE
EFIAPI
GetMonitorState (
  VOID
  );

/**

  Load STM image to MSEG.

  @param StmImage      STM image
  @param StmImageSize  STM image size

  @retval EFI_SUCCESS            Load STM to MSEG successfully
  @retval EFI_BUFFER_TOO_SMALL   MSEG is smaller than minimal requirement of STM image

**/
EFI_STATUS
EFIAPI
LoadMonitor (
  IN EFI_PHYSICAL_ADDRESS  StmImage,
  IN UINTN                 StmImageSize
  );

/**
  This function initialize STM configuration table.
**/
VOID
StmSmmConfigurationTableInit (
  VOID
  );

/**
  This function return BIOS STM resource.

  @return BIOS STM resource

**/
VOID *
GetStmResource (
  VOID
  );

#endif
