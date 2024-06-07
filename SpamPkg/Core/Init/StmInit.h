/** @file
  STM initialization header file

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _STM_INIT_H_
#define _STM_INIT_H_

#include "Stm.h"

/**

  This function create page table for STM host.
  The SINIT/StmLoader should already configured 4G paging, so here
  we just create >4G paging for X64 mode.

**/
VOID
CreateHostPaging (
  VOID
  );

/**
  Check if 1-GByte pages is supported by processor or not.

  @retval TRUE   1-GByte pages is supported.
  @retval FALSE  1-GByte pages is not supported.

**/
BOOLEAN
Is1GPageSupport (
  VOID
  );

/**

  This function initialize event log.

**/
VOID
InitializeEventLog (
  VOID
  );

#endif
