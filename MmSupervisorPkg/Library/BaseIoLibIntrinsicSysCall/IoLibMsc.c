/** @file
  I/O Library. This file has compiler specifics for Microsoft C as there is no
  ANSI C standard for doing IO.

  MSC - uses intrinsic functions and the optimize will remove the function call
  overhead.

  We don't advocate putting compiler specifics in libraries or drivers but there
  is no other way to make this work.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (C) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include "BaseIoLibIntrinsicInternal.h"
#include "IoLibTdx.h"

//
// Microsoft Visual Studio 7.1 Function Prototypes for I/O Intrinsics.
//

int
_inp (
  unsigned short  port
  );

unsigned short
_inpw (
  unsigned short  port
  );

unsigned long
_inpd (
  unsigned short  port
  );

int
_outp (
  unsigned short  port,
  int             databyte
  );

unsigned short
_outpw (
  unsigned short  port,
  unsigned short  dataword
  );

unsigned long
_outpd (
  unsigned short  port,
  unsigned long   dataword
  );

void
_ReadWriteBarrier (
  void
  );

#pragma intrinsic(_inp)
#pragma intrinsic(_inpw)
#pragma intrinsic(_inpd)
#pragma intrinsic(_outp)
#pragma intrinsic(_outpw)
#pragma intrinsic(_outpd)
#pragma intrinsic(_ReadWriteBarrier)
