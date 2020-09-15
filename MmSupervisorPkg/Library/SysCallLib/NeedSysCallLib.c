/** @file
Agent Module to load other modules to deploy SMM Entry Vector for X86 CPU.

Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/SysCallLib.h>

/**
 Check if high privilege instruction need go through Syscall


 @param  NONE

 @return TRUE  Syscall required
 @return FALSE Syscall not required

**/
BOOLEAN
NeedSysCall (
  VOID
  )
{
  UINT16  CS;

  CS = AsmReadCs ();
  if ((CS & CPL_BITMASK) == SYSCALL_REQUIRED_CPL) {
    return TRUE;
  }

  return FALSE;
}
