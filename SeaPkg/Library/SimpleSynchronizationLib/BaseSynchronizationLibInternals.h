/** @file
  Declaration of internal functions in BaseSynchronizationLib.

  Copyright (c) 2006 - 2010, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __BASE_SYNCHRONIZATION_LIB_INTERNALS__
#define __BASE_SYNCHRONIZATION_LIB_INTERNALS__

#include <Base.h>
#include <Library/SynchronizationLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

/**
  Performs an atomic increment of an 32-bit unsigned integer.

  Performs an atomic increment of the 32-bit unsigned integer specified by
  Value and returns the incremented value. The increment operation must be
  performed using MP safe mechanisms. The state of the return value is not
  guaranteed to be MP safe.

  @param  Value A pointer to the 32-bit value to increment.

  @return The incremented value.

**/
UINT32
EFIAPI
InternalSyncIncrement (
  IN      volatile UINT32  *Value
  );

/**
  Performs an atomic decrement of an 32-bit unsigned integer.

  Performs an atomic decrement of the 32-bit unsigned integer specified by
  Value and returns the decrement value. The decrement operation must be
  performed using MP safe mechanisms. The state of the return value is not
  guaranteed to be MP safe.

  @param  Value A pointer to the 32-bit value to decrement.

  @return The decrement value.

**/
UINT32
EFIAPI
InternalSyncDecrement (
  IN      volatile UINT32  *Value
  );

/**
  Performs an atomic compare exchange operation on a 32-bit unsigned integer.

  Performs an atomic compare exchange operation on the 32-bit unsigned integer
  specified by Value.  If Value is equal to CompareValue, then Value is set to
  ExchangeValue and CompareValue is returned.  If Value is not equal to CompareValue,
  then Value is returned.  The compare exchange operation must be performed using
  MP safe mechanisms.

  @param  Value         A pointer to the 32-bit value for the compare exchange
                        operation.
  @param  CompareValue  A 32-bit value used in compare operation.
  @param  ExchangeValue A 32-bit value used in exchange operation.

  @return The original *Value before exchange.

**/
UINT32
EFIAPI
InternalSyncCompareExchange32 (
  IN      volatile UINT32  *Value,
  IN      UINT32           CompareValue,
  IN      UINT32           ExchangeValue
  );

/**
  Performs an atomic compare exchange operation on a 64-bit unsigned integer.

  Performs an atomic compare exchange operation on the 64-bit unsigned integer specified
  by Value.  If Value is equal to CompareValue, then Value is set to ExchangeValue and
  CompareValue is returned.  If Value is not equal to CompareValue, then Value is returned.
  The compare exchange operation must be performed using MP safe mechanisms.

  @param  Value         A pointer to the 64-bit value for the compare exchange
                        operation.
  @param  CompareValue  A 64-bit value used in compare operation.
  @param  ExchangeValue A 64-bit value used in exchange operation.

  @return The original *Value before exchange.

**/
UINT64
EFIAPI
InternalSyncCompareExchange64 (
  IN      volatile UINT64  *Value,
  IN      UINT64           CompareValue,
  IN      UINT64           ExchangeValue
  );

#endif
