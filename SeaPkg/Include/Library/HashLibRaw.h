/** @file
  This library abstract TPM2 hash calculation.
  The platform can choose multiply hash, while caller just need invoke these API.
  Then all hash value will be returned and/or extended.

Copyright (c) 2013 - 2016, Intel Corporation. All rights reserved. <BR>
Copyright (c), Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef HASH_LIB_RAW_H_
#define HASH_LIB_RAW_H_

/**
  Hash data and return the digest list.

  @param DataToHash    Data to be hashed.
  @param DataToHashLen Data size.
  @param DigestList    Digest list.

  @retval EFI_SUCCESS     Hash data and DigestList is returned.
**/
EFI_STATUS
EFIAPI
HashOnly (
  IN VOID                 *DataToHash,
  IN UINTN                DataToHashLen,
  OUT TPML_DIGEST_VALUES  *DigestList
  );

#endif
