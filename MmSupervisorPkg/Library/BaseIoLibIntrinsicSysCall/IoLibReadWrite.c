/** @file
  I/O library read and write routines.

  Copyright (c) 2006 - 2021, Intel Corporation. All rights reserved.<BR>
  Copyright (C) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "BaseIoLibIntrinsicInternal.h"
#include "IoLibTdx.h"
#include <Uefi.h>
#include <Library/SysCallLib.h>
#include <Protocol/MmCpuIo.h>

//
// _ReadWriteBarrier() forces memory reads and writes to complete at the point
// in the call. This is only a hint to the compiler and does emit code.
// In past versions of the compiler, _ReadWriteBarrier was enforced only
// locally and did not affect functions up the call tree. In Visual C++
// 2005, _ReadWriteBarrier is enforced all the way up the call tree.
//

/**
  Reads an 8-bit I/O port.

  Reads the 8-bit I/O port specified by Port. The 8-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 8-bit I/O port operations are not supported, then ASSERT().

  For Td guest TDVMCALL_IO is invoked to read I/O port.

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT8
EFIAPI
IoRead8 (
  IN      UINTN  Port
  )
{
  UINT8    Value;
  BOOLEAN  Flag;

  Flag = FilterBeforeIoRead (FilterWidth8, Port, &Value);
  if (Flag) {
    if (IsTdxGuest ()) {
      Value = TdIoRead8 (Port);
    } else {
      Value = (UINT8)SysCall (SMM_SC_IO_READ, Port, MM_IO_UINT8, 0);
    }
  }

  FilterAfterIoRead (FilterWidth8, Port, &Value);

  return Value;
}

/**
  Writes an 8-bit I/O port.

  Writes the 8-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 8-bit I/O port operations are not supported, then ASSERT().

  For Td guest TDVMCALL_IO is invoked to write I/O port.

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written to the I/O port.

**/
UINT8
EFIAPI
IoWrite8 (
  IN      UINTN  Port,
  IN      UINT8  Value
  )
{
  BOOLEAN  Flag;

  Flag = FilterBeforeIoWrite (FilterWidth8, Port, &Value);
  if (Flag) {
    if (IsTdxGuest ()) {
      TdIoWrite8 (Port, Value);
    } else {
      SysCall (SMM_SC_IO_WRITE, Port, MM_IO_UINT8, (UINTN)Value);
    }
  }

  FilterAfterIoWrite (FilterWidth8, Port, &Value);

  return Value;
}

/**
  Reads a 16-bit I/O port.

  Reads the 16-bit I/O port specified by Port. The 16-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 16-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 16-bit boundary, then ASSERT().

  For Td guest TDVMCALL_IO is invoked to read I/O port.

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT16
EFIAPI
IoRead16 (
  IN      UINTN  Port
  )
{
  UINT16   Value;
  BOOLEAN  Flag;

  ASSERT ((Port & 1) == 0);

  Flag = FilterBeforeIoRead (FilterWidth16, Port, &Value);
  if (Flag) {
    if (IsTdxGuest ()) {
      Value = TdIoRead16 (Port);
    } else {
      Value = (UINT16)SysCall (SMM_SC_IO_READ, Port, MM_IO_UINT16, 0);
    }
  }

  FilterBeforeIoRead (FilterWidth16, Port, &Value);

  return Value;
}

/**
  Writes a 16-bit I/O port.

  Writes the 16-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 16-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 16-bit boundary, then ASSERT().

  For Td guest TDVMCALL_IO is invoked to write I/O port.

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written to the I/O port.

**/
UINT16
EFIAPI
IoWrite16 (
  IN      UINTN   Port,
  IN      UINT16  Value
  )
{
  BOOLEAN  Flag;

  ASSERT ((Port & 1) == 0);

  Flag = FilterBeforeIoWrite (FilterWidth16, Port, &Value);
  if (Flag) {
    if (IsTdxGuest ()) {
      TdIoWrite16 (Port, Value);
    } else {
      SysCall (SMM_SC_IO_WRITE, Port, MM_IO_UINT16, (UINTN)Value);
    }
  }

  FilterAfterIoWrite (FilterWidth16, Port, &Value);

  return Value;
}

/**
  Reads a 32-bit I/O port.

  Reads the 32-bit I/O port specified by Port. The 32-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 32-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 32-bit boundary, then ASSERT().

  For Td guest TDVMCALL_IO is invoked to read I/O port.

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT32
EFIAPI
IoRead32 (
  IN      UINTN  Port
  )
{
  UINT32   Value;
  BOOLEAN  Flag;

  ASSERT ((Port & 3) == 0);

  Flag = FilterBeforeIoRead (FilterWidth32, Port, &Value);
  if (Flag) {
    if (IsTdxGuest ()) {
      Value = TdIoRead32 (Port);
    } else {
      Value = (UINT32)SysCall (SMM_SC_IO_READ, Port, MM_IO_UINT32, 0);
    }
  }

  FilterAfterIoRead (FilterWidth32, Port, &Value);

  return Value;
}

/**
  Writes a 32-bit I/O port.

  Writes the 32-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 32-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 32-bit boundary, then ASSERT().

  For Td guest TDVMCALL_IO is invoked to write I/O port.

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written to the I/O port.

**/
UINT32
EFIAPI
IoWrite32 (
  IN      UINTN   Port,
  IN      UINT32  Value
  )
{
  BOOLEAN  Flag;

  ASSERT ((Port & 3) == 0);

  Flag = FilterBeforeIoWrite (FilterWidth32, Port, &Value);
  if (Flag) {
    if (IsTdxGuest ()) {
      TdIoWrite32 (Port, Value);
    } else {
      SysCall (SMM_SC_IO_WRITE, Port, MM_IO_UINT32, (UINTN)Value);
    }
  }

  FilterAfterIoWrite (FilterWidth32, Port, &Value);

  return Value;
}
