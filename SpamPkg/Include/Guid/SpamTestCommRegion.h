/** @file
  Data structure definition for allocated MM communication buffers.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SPAM_TEST_COMM_REGION_H_
#define SPAM_TEST_COMM_REGION_H_

#define SPAM_VAL_TEST_HANDLER_GUID \
   { 0x2f5df5d9, 0xa4c1, 0x4f6d, { 0xb5, 0x34, 0x4, 0xdd, 0x9b, 0x49, 0x59, 0x9f } }

typedef struct {
  UINT64                SupvDigestListCount;
  TPML_DIGEST_VALUES    SupvDigestList[SUPPORTED_DIGEST_COUNT];
  UINT64                MmiEntryFileSize;
  UINT64                SupervisorAuxFileSize;
  UINT8                 SupervisorAuxFileBase[];
} SPAM_TEST_COMM_INPUT_REGION;

typedef struct {
  SMM_SUPV_SECURE_POLICY_DATA_V1_0    FirmwarePolicy;
} SPAM_TEST_COMM_OUTPUT_REGION;

extern EFI_GUID  gSpamValidationTestHandlerGuid;

#endif
