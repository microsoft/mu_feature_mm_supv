/** @file
  Internal header with function declarations for Syscall MM Handler protocol

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SYSCALL_MMI_HANDLER_PROFILE_H_
#define _SYSCALL_MMI_HANDLER_PROFILE_H_

/**
  Initialize MmiHandler profile feature for user space.
**/
VOID
MmUserInitializeSmiHandlerProfile (
  VOID
  );

#endif
