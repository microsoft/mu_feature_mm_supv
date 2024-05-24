/** @file
  This library uses TPM2 device to calculation hash.

Copyright (c) 2013 - 2018, Intel Corporation. All rights reserved. <BR>
(C) Copyright 2015 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/HashLib.h>
#include <Library/PcdLib.h>

typedef struct {
  TPM_ALG_ID    AlgoId;
  UINT32        Mask;
} TPM2_HASH_MASK;

TPM2_HASH_MASK  mTpm2HashMask[] = {
  { TPM_ALG_SHA1,    HASH_ALG_SHA1    },
  { TPM_ALG_SHA256,  HASH_ALG_SHA256  },
  { TPM_ALG_SHA384,  HASH_ALG_SHA384  },
  { TPM_ALG_SHA512,  HASH_ALG_SHA512  },
  { TPM_ALG_SM3_256, HASH_ALG_SM3_256 },
};

/**
  The function get algorithm from hash mask info.

  @return Hash algorithm
**/
EFI_STATUS
EFIAPI
Tpm2GetAlgoFromHashMask (
  OUT TPM_ALG_ID  *AlgoIds,
  OUT UINTN       *Count
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINTN       AlgoIdCount;
  UINT32      TpmHashAlgorithmBitmap;
  UINT32      ActivePcrBanks;

  if ((AlgoIds == NULL) || (Count == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Tpm2GetCapabilitySupportedAndActivePcrs (&TpmHashAlgorithmBitmap, &ActivePcrBanks);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  AlgoIdCount = 0;
  for (Index = 0; Index < sizeof (mTpm2HashMask)/sizeof (mTpm2HashMask[0]); Index++) {
    if (mTpm2HashMask[Index].Mask & ActivePcrBanks) {
      if (AlgoIdCount >= *Count) {
        return EFI_BUFFER_TOO_SMALL;
      }

      AlgoIds[AlgoIdCount] = mTpm2HashMask[Index].AlgoId;
      AlgoIdCount++;
    }
  }

  *Count = AlgoIdCount;

  return EFI_SUCCESS;
}

/**
  Start hash sequence.

  @param HashHandle Hash handle.

  @retval EFI_SUCCESS          Hash sequence start and HandleHandle returned.
  @retval EFI_OUT_OF_RESOURCES No enough resource to start hash.
**/
EFI_STATUS
EFIAPI
HashStart (
  OUT HASH_HANDLE  *HashHandle
  )
{
  TPMI_DH_OBJECT  SequenceHandle;
  EFI_STATUS      Status;
  UINTN           Index;
  UINTN           AlgoIdCount = HASH_COUNT;
  TPM_ALG_ID      AlgoIds[HASH_COUNT];
  HASH_HANDLE     *HashCtx;

  if (HashHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  HashCtx = AllocatePages (EFI_SIZE_TO_PAGES (sizeof (*HashCtx) * HASH_COUNT));
  ASSERT (HashCtx != NULL);

  Status = Tpm2GetAlgoFromHashMask (AlgoIds, &AlgoIdCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < AlgoIdCount; Index++) {
    Status = Tpm2HashSequenceStart (AlgoIds[Index], &SequenceHandle);
    if (!EFI_ERROR (Status)) {
      HashCtx[Index] = (HASH_HANDLE)SequenceHandle;
    }
  }

  *HashHandle = (HASH_HANDLE)HashCtx;

  return Status;
}

/**
  Update hash sequence data.

  @param HashHandle    Hash handle.
  @param DataToHash    Data to be hashed.
  @param DataToHashLen Data size.

  @retval EFI_SUCCESS     Hash sequence updated.
**/
EFI_STATUS
EFIAPI
HashUpdate (
  IN HASH_HANDLE  HashHandle,
  IN VOID         *DataToHash,
  IN UINTN        DataToHashLen
  )
{
  UINT8             *Buffer;
  UINT64            HashLen;
  TPM2B_MAX_BUFFER  HashBuffer;
  EFI_STATUS        Status;
  UINTN             Index;
  UINTN             AlgoIdCount = HASH_COUNT;
  TPM_ALG_ID        AlgoIds[HASH_COUNT];
  HASH_HANDLE       *HashCtx;

  HashCtx = (HASH_HANDLE *)HashHandle;

  Status = Tpm2GetAlgoFromHashMask (AlgoIds, &AlgoIdCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < AlgoIdCount; Index++) {
    Buffer = (UINT8 *)(UINTN)DataToHash;
    for (HashLen = DataToHashLen; HashLen > sizeof (HashBuffer.buffer); HashLen -= sizeof (HashBuffer.buffer)) {
      HashBuffer.size = sizeof (HashBuffer.buffer);
      CopyMem (HashBuffer.buffer, Buffer, sizeof (HashBuffer.buffer));
      Buffer += sizeof (HashBuffer.buffer);

      Status = Tpm2SequenceUpdate ((TPMI_DH_OBJECT)HashCtx[Index], &HashBuffer);
      if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
      }
    }

    //
    // Last one
    //
    HashBuffer.size = (UINT16)HashLen;
    CopyMem (HashBuffer.buffer, Buffer, (UINTN)HashLen);
    Status = Tpm2SequenceUpdate ((TPMI_DH_OBJECT)HashCtx[Index], &HashBuffer);
    if (EFI_ERROR (Status)) {
      return EFI_DEVICE_ERROR;
    }
  }

  return EFI_SUCCESS;
}

/**
  Hash sequence complete and return the digest list.

  @param HashHandle    Hash handle.
  @param DataToHash    Data to be hashed.
  @param DataToHashLen Data size.
  @param DigestList    Digest list.

  @retval EFI_SUCCESS     Hash sequence complete and DigestList is returned.
**/
EFI_STATUS
EFIAPI
HashComplete (
  IN HASH_HANDLE          HashHandle,
  IN VOID                 *DataToHash,
  IN UINTN                DataToHashLen,
  OUT TPML_DIGEST_VALUES  *DigestList
  )
{
  UINT8             *Buffer;
  UINT64            HashLen;
  TPM2B_MAX_BUFFER  HashBuffer;
  EFI_STATUS        Status;
  TPM2B_DIGEST      Result;
  UINTN             Index;
  UINTN             AlgoIdCount = HASH_COUNT;
  TPM_ALG_ID        AlgoIds[HASH_COUNT];
  HASH_HANDLE       *HashCtx;

  HashCtx = (HASH_HANDLE *)HashHandle;

  Status = Tpm2GetAlgoFromHashMask (AlgoIds, &AlgoIdCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (DigestList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (DigestList, sizeof (*DigestList));
  for (Index = 0; Index < AlgoIdCount; Index++) {
    Buffer = (UINT8 *)(UINTN)DataToHash;
    for (HashLen = DataToHashLen; HashLen > sizeof (HashBuffer.buffer); HashLen -= sizeof (HashBuffer.buffer)) {
      HashBuffer.size = sizeof (HashBuffer.buffer);
      CopyMem (HashBuffer.buffer, Buffer, sizeof (HashBuffer.buffer));
      Buffer += sizeof (HashBuffer.buffer);

      Status = Tpm2SequenceUpdate ((TPMI_DH_OBJECT)HashCtx[Index], &HashBuffer);
      if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
      }
    }

    //
    // Last one
    //
    HashBuffer.size = (UINT16)HashLen;
    CopyMem (HashBuffer.buffer, Buffer, (UINTN)HashLen);

    Status = Tpm2SequenceComplete (
               (TPMI_DH_OBJECT)HashCtx[Index],
               &HashBuffer,
               &Result
               );
    if (EFI_ERROR (Status)) {
      return EFI_DEVICE_ERROR;
    }

    DigestList->count                  = DigestList->count + 1;
    DigestList->digests[Index].hashAlg = AlgoIds[Index];
    CopyMem (&DigestList->digests[Index].digest, Result.buffer, Result.size);
    if (EFI_ERROR (Status)) {
      return EFI_DEVICE_ERROR;
    }
  }

  FreePages (HashCtx, EFI_SIZE_TO_PAGES (sizeof (*HashCtx) * HASH_COUNT));

  return EFI_SUCCESS;
}

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
  EFI_STATUS        Status;
  UINT8             *Buffer;
  UINT64            HashLen;
  TPMI_DH_OBJECT    SequenceHandle;
  TPM2B_MAX_BUFFER  HashBuffer;
  UINTN             Index;
  UINTN             AlgoIdCount = HASH_COUNT;
  TPM_ALG_ID        AlgoIds[HASH_COUNT];
  TPM2B_EVENT       EventData;
  TPM2B_DIGEST      Result;

  DEBUG ((DEBUG_VERBOSE, "\n %a Entry \n", __func__));

  if (DigestList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  SequenceHandle = 0xFFFFFFFF; // Know bad value

  Status = Tpm2GetAlgoFromHashMask (AlgoIds, &AlgoIdCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((AlgoIdCount == 0) && (DataToHashLen <= sizeof (EventData.buffer))) {
    return EFI_DEVICE_ERROR;
  }

  ZeroMem (DigestList, sizeof (*DigestList));
  for (Index = 0; Index < AlgoIdCount; Index++) {
    Status = Tpm2HashSequenceStart (AlgoIds[Index], &SequenceHandle);
    if (EFI_ERROR (Status)) {
      return EFI_DEVICE_ERROR;
    }

    DEBUG ((DEBUG_VERBOSE, "\n Tpm2HashSequenceStart Success \n"));

    Buffer = (UINT8 *)(UINTN)DataToHash;
    for (HashLen = DataToHashLen; HashLen > sizeof (HashBuffer.buffer); HashLen -= sizeof (HashBuffer.buffer)) {
      HashBuffer.size = sizeof (HashBuffer.buffer);
      CopyMem (HashBuffer.buffer, Buffer, sizeof (HashBuffer.buffer));
      Buffer += sizeof (HashBuffer.buffer);

      Status = Tpm2SequenceUpdate (SequenceHandle, &HashBuffer);
      if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
      }
    }

    DEBUG ((DEBUG_VERBOSE, "\n Tpm2SequenceUpdate Success \n"));

    HashBuffer.size = (UINT16)HashLen;
    CopyMem (HashBuffer.buffer, Buffer, (UINTN)HashLen);

    Status = Tpm2SequenceComplete (
               SequenceHandle,
               &HashBuffer,
               &Result
               );
    if (EFI_ERROR (Status)) {
      return EFI_DEVICE_ERROR;
    }

    DEBUG ((DEBUG_VERBOSE, "\n Tpm2SequenceComplete Success \n"));

    DigestList->count                  = DigestList->count + 1;
    DigestList->digests[Index].hashAlg = AlgoIds[Index];
    CopyMem (&DigestList->digests[Index].digest, Result.buffer, Result.size);
  }

  return EFI_SUCCESS;
}
