/** @file
SMM profile header file.

Copyright (c) 2012 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_PROFILE_H_
#define _SMM_PROFILE_H_

#include "SmmProfileInternal.h"

//
// External functions
//

/**
  Check if feature is supported by a processor.

**/
VOID
CheckFeatureSupported (
  VOID
  );

/**
  Update page table according to protected memory ranges and the 4KB-page mapped memory ranges.

**/
VOID
InitPaging (
  VOID
  );

/**
  Get CPU Index from APIC ID.

**/
UINTN
GetCpuIndex (
  VOID
  );

//
// The flag indicates if execute-disable is supported by processor.
//
extern BOOLEAN  mXdSupported;

#endif // _SMM_PROFILE_H_
