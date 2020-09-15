/** @file
  CpuBreakpoint function.

  Copyright (c) 2006 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/**
  Microsoft Visual Studio 7.1 Function Prototypes for I/O Intrinsics.
**/

#include <Library/RegisterFilterLib.h>

void
__writemsr (
  unsigned long     Register,
  unsigned __int64  Value
  );

#pragma intrinsic(__writemsr)

#include    <Uefi.h>
#include    <Library/BaseLib.h>
#include    <Library/SysCallLib.h>

/**
  Write data to MSR.

  @param  Index                The register index of MSR.
  @param  Value                Data wants to be written.

  @return Value written to MSR.

**/
UINT64
EFIAPI
AsmWriteMsr64 (
  IN UINT32  Index,
  IN UINT64  Value
  )
{
  BOOLEAN  Flag;

  Flag = FilterBeforeMsrWrite (Index, &Value);
  if (Flag) {
    SysCall (SMM_SC_WRMSR, Index, (UINTN)Value, 0);
  }

  FilterAfterMsrWrite (Index, &Value);

  return Value;
}
