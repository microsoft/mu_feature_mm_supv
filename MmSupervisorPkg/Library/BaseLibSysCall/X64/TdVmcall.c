/** @file

  Copyright (c) 2020-2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseLib.h>
#include <Register/Intel/Cpuid.h>

/**
  TDVMALL is a leaf function 0 for TDCALL. It helps invoke services from the
  host VMM to pass/receive information.

  @param[in]     Leaf        Number of sub-functions
  @param[in]     Arg1        Arg1
  @param[in]     Arg2        Arg2
  @param[in]     Arg3        Arg3
  @param[in]     Arg4        Arg4
  @param[in,out] Results     Returned result of the sub-function

  @return 0               A successful call
  @return Other           See individual sub-functions

**/
UINTN
EFIAPI
TdVmCall (
  IN UINT64    Leaf,
  IN UINT64    Arg1,
  IN UINT64    Arg2,
  IN UINT64    Arg3,
  IN UINT64    Arg4,
  IN OUT VOID  *Results
  )
{
  // We should not even invoke this function for supervised environment.
  ASSERT (FALSE);
  return MAX_UINTN;
}
