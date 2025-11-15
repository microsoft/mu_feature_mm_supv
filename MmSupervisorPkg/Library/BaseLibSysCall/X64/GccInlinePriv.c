/** @file
  GCC inline implementation of BaseLib processor specific functions that use
  privlidged instructions.

  Copyright (c) 2006 - 2021, Intel Corporation. All rights reserved.<BR>
  Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "BaseLibInternals.h"
#include <Library/RegisterFilterLib.h>
#include <Library/SysCallLib.h>

/**
  Disables CPU interrupts.

  Disables CPU interrupts.

**/
VOID
EFIAPI
DisableInterrupts (
  VOID
  )
{
  SysCall (SMM_SC_CLI, 0, 0, 0);
}

/**
  Returns a 64-bit Machine Specific Register(MSR).

  Reads and returns the 64-bit MSR specified by Index. No parameter checking is
  performed on Index, and some Index values may cause CPU exceptions. The
  caller must either guarantee that Index is valid, or the caller must set up
  exception handlers to catch the exceptions. This function is only available
  on IA-32 and X64.

  @param  Index The 32-bit MSR index to read.

  @return The value of the MSR identified by Index.

**/
UINT64
EFIAPI
AsmReadMsr64 (
  IN      UINT32  Index
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

/**
  Writes a 64-bit value to a Machine Specific Register(MSR), and returns the
  value.

  Writes the 64-bit value specified by Value to the MSR specified by Index. The
  64-bit value written to the MSR is returned. No parameter checking is
  performed on Index or Value, and some of these may cause CPU exceptions. The
  caller must either guarantee that Index and Value are valid, or the caller
  must establish proper exception handlers. This function is only available on
  IA-32 and X64.

  @param  Index The 32-bit MSR index to write.
  @param  Value The 64-bit value to write to the MSR.

  @return Value

**/
UINT64
EFIAPI
AsmWriteMsr64 (
  IN      UINT32  Index,
  IN      UINT64  Value
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

/**
  Reads the current value of Code Segment Register (CS).

  Reads and returns the current value of CS. This function is only available on
  IA-32 and X64.

  @return The current value of CS.

**/
UINT16
EFIAPI
AsmReadCs (
  VOID
  )
{
  UINT16  Data;

  __asm__ __volatile__ (
    "mov   %%cs, %0"
    :"=a" (Data)
  );

  return Data;
}

/**
  Reads the current value of a Performance Counter (PMC).

  Reads and returns the current value of performance counter specified by
  Index. This function is only available on IA-32 and X64.

  @param  Index The 32-bit Performance Counter index to read.

  @return The value of the PMC specified by Index.

**/
UINT64
EFIAPI
AsmReadPmc (
  IN      UINT32  Index
  )
{
  UINT32  LowData;
  UINT32  HiData;

  __asm__ __volatile__ (
    "rdpmc"
    : "=a" (LowData),
      "=d" (HiData)
    : "c"  (Index)
  );

  return (((UINT64)HiData) << 32) | LowData;
}

/**
  Sets up a monitor buffer that is used by AsmMwait().

  Executes a MONITOR instruction with the register state specified by Eax, Ecx
  and Edx. Returns Eax. This function is only available on IA-32 and X64.

  @param  Eax The value to load into EAX or RAX before executing the MONITOR
              instruction.
  @param  Ecx The value to load into ECX or RCX before executing the MONITOR
              instruction.
  @param  Edx The value to load into EDX or RDX before executing the MONITOR
              instruction.

  @return Eax

**/
UINTN
EFIAPI
AsmMonitor (
  IN      UINTN  Eax,
  IN      UINTN  Ecx,
  IN      UINTN  Edx
  )
{
  __asm__ __volatile__ (
    "monitor"
    :
    : "a" (Eax),
      "c" (Ecx),
      "d" (Edx)
  );

  return Eax;
}

/**
  Executes an MWAIT instruction.

  Executes an MWAIT instruction with the register state specified by Eax and
  Ecx. Returns Eax. This function is only available on IA-32 and X64.

  @param  Eax The value to load into EAX or RAX before executing the MONITOR
              instruction.
  @param  Ecx The value to load into ECX or RCX before executing the MONITOR
              instruction.

  @return Eax

**/
UINTN
EFIAPI
AsmMwait (
  IN      UINTN  Eax,
  IN      UINTN  Ecx
  )
{
  __asm__ __volatile__ (
    "mwait"
    :
    : "a"  (Eax),
      "c"  (Ecx)
  );

  return Eax;
}

/**
  Executes a WBINVD instruction.

  Executes a WBINVD instruction. This function is only available on IA-32 and
  X64.

**/
VOID
EFIAPI
AsmWbinvd (
  VOID
  )
{
  SysCall (SMM_SC_WBINVD, 0, 0, 0);
}

/**
  Flushes a cache line from all the instruction and data caches within the
  coherency domain of the CPU.

  Flushed the cache line specified by LinearAddress, and returns LinearAddress.
  This function is only available on IA-32 and X64.

  @param  LinearAddress The address of the cache line to flush. If the CPU is
                        in a physical addressing mode, then LinearAddress is a
                        physical address. If the CPU is in a virtual
                        addressing mode, then LinearAddress is a virtual
                        address.

  @return LinearAddress
**/
VOID *
EFIAPI
AsmFlushCacheLine (
  IN      VOID  *LinearAddress
  )
{
  __asm__ __volatile__ (
    "clflush (%0)"
    :
    : "r" (LinearAddress)
    : "memory"
  );

  return LinearAddress;
}
