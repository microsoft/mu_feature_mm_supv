/** @file
  SEA CPU Information library header file

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SEA_CPU_INFORMATION_LIB_
#define SEA_CPU_INFORMATION_LIB_

/**
  Return the Platform CPU core count.

  @retval The number of CPU cores on the system

**/
UINTN
EFIAPI
GetPlatformCoreCount (
  VOID
  );

#endif
