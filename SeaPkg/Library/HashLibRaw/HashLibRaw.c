/** @file
  This library uses TPM2 device to calculation hash.

Copyright (c) 2013 - 2018, Intel Corporation. All rights reserved. <BR>
(C) Copyright 2015 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>

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
  )
{
  UINTN        AlgoIdCount;
  TPM_ALG_ID   AlgoIds[1];
  TPM2B_EVENT  EventData;
  BOOLEAN      Sha256Result;
  VOID         *Sha256Ctx;
  UINT8        Digest[SHA256_DIGEST_SIZE];

  DEBUG ((DEBUG_INFO, "\n %a Entry \n", __func__));

  if (DigestList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // HACKHACK
  AlgoIds[0]  = TPM_ALG_SHA256;
  AlgoIdCount = 1;

  if ((AlgoIdCount == 0) && (DataToHashLen <= sizeof (EventData.buffer))) {
    return EFI_DEVICE_ERROR;
  }

  ZeroMem (DigestList, sizeof (*DigestList));

  Sha256Ctx    = AllocatePages (EFI_SIZE_TO_PAGES (Sha256GetContextSize ()));
  Sha256Result = Sha256Init (Sha256Ctx);
  if (!Sha256Result) {
    return EFI_DEVICE_ERROR;
  }

  DEBUG ((DEBUG_INFO, "\n Sha256Init Success \n"));

  Sha256Result = Sha256Update (Sha256Ctx, DataToHash, DataToHashLen);
  if (!Sha256Result) {
    return EFI_DEVICE_ERROR;
  }

  DEBUG ((DEBUG_INFO, "\n Sha256Update Success \n"));

  Sha256Result = Sha256Final (
                   Sha256Ctx,
                   Digest
                   );
  if (!Sha256Result) {
    return EFI_DEVICE_ERROR;
  }

  FreePages (Sha256Ctx, EFI_SIZE_TO_PAGES (Sha256GetContextSize ()));

  DEBUG ((DEBUG_INFO, "\n Sha256Final Success \n"));

  DigestList->count              = 1;
  DigestList->digests[0].hashAlg = AlgoIds[0];
  CopyMem (&DigestList->digests[0].digest, Digest, sizeof (Digest));

  return EFI_SUCCESS;
}
