/** @file
  SMM runtime header file

  Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _STM_RUNTIME_H_
#define _STM_RUNTIME_H_

#include "Stm.h"

/**

  This function return CPU index according to APICID.

  @param ApicId APIC ID

  @return CPU index

**/
UINT32
ApicToIndex (
  IN UINT32  ApicId
  );

/**

  This function validate input address region.
  Address region is not allowed to overlap with MSEG.
  Address region is not allowed to exceed STM accessable region.

  @param Address              Address to be validated
  @param Length               Address length to be validated
  @param FromProtectedDomain  If this request is from protected domain
                              TRUE means this address region is allowed to overlap with MLE protected region.
                              FALSE means this address region is not allowed to overlap with MLE protected region.

  @retval TRUE  Validation pass
  @retval FALSE Validation fail

**/
BOOLEAN
IsGuestAddressValid (
  IN UINTN    Address,
  IN UINTN    Length,
  IN BOOLEAN  FromProtectedDomain
  );

/**

  This function checks Pending Mtf before resume.

  @param Index CPU index

**/
VOID
CheckPendingMtf (
  IN UINT32  Index
  );

/**

  This function issue TXT reset.

  @param ErrorCode            TXT reset error code

**/
VOID
StmTxtReset (
  IN UINT32  ErrorCode
  );

#endif
