/** @file
  CpuBreakpoint function.

  Copyright (c) 2006 - 2021, Intel Corporation. All rights reserved.<BR>
  Copyright (C), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/**
  Microsoft Visual Studio 7.1 Function Prototypes for I/O Intrinsics.
**/

#include <Library/RegisterFilterLib.h>

unsigned __int64
__readmsr (
  int register
  );

#pragma intrinsic(__readmsr)

#include    <Uefi.h>
#include    <Library/BaseLib.h>
#include    <Library/SysCallLib.h>

/**
  Read data to MSR.

  @param  Index                Register index of MSR.

  @return Value read from MSR.

**/
UINT64
EFIAPI
AsmReadMsr64 (
  IN UINT32  Index
  )
{
  UINT64   Value;
  BOOLEAN  Flag;

  Flag = FilterBeforeMsrRead (Index, &Value);
  if (Flag) {
    Value = SysCall (SMM_SC_RDMSR, Index, 0, 0);
  }

  FilterAfterMsrRead (Index, &Value);

  return Value;
}
