/** @file
  GCC inline implementation of BaseLib processor specific functions.

  Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
  Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "BaseLibInternals.h"

/**
  Used to serialize load and store operations.

  All loads and stores that proceed calls to this function are guaranteed to be
  globally visible when this function returns.

**/
VOID
EFIAPI
MemoryFence (
  VOID
  )
{
  // This is a little bit of overkill and it is more about the compiler that it is
  // actually processor synchronization. This is like the _ReadWriteBarrier
  // Microsoft specific intrinsic
  __asm__ __volatile__ ("":::"memory");
}

/**
  Requests CPU to pause for a short period of time.

  Requests CPU to pause for a short period of time. Typically used in MP
  systems to prevent memory starvation while waiting for a spin lock.

**/
VOID
EFIAPI
CpuPause (
  VOID
  )
{
  __asm__ __volatile__ ("pause");
}

/**
  Generates a breakpoint on the CPU.

  Generates a breakpoint on the CPU. The breakpoint must be implemented such
  that code can resume normal execution after the breakpoint.

**/
VOID
EFIAPI
CpuBreakpoint (
  VOID
  )
{
  __asm__ __volatile__ ("int $3");
}

/**
  Reads the current value of the EFLAGS register.

  Reads and returns the current value of the EFLAGS register. This function is
  only available on IA-32 and X64. This returns a 32-bit value on IA-32 and a
  64-bit value on X64.

  @return EFLAGS on IA-32 or RFLAGS on X64.

**/
UINTN
EFIAPI
AsmReadEflags (
  VOID
  )
{
  UINTN  Eflags;

  __asm__ __volatile__ (
    "pushfq         \n\t"
    "pop     %0         "
    : "=r" (Eflags)       // %0
  );

  return Eflags;
}

/**
  Reads the current value of Time Stamp Counter (TSC).

  Reads and returns the current value of TSC. This function is only available
  on IA-32 and X64.

  @return The current value of TSC

**/
UINT64
EFIAPI
AsmReadTsc (
  VOID
  )
{
  UINT32  LowData;
  UINT32  HiData;

  __asm__ __volatile__ (
    "rdtsc"
    : "=a" (LowData),
      "=d" (HiData)
  );

  return (((UINT64)HiData) << 32) | LowData;
}
