/** @file -- MmPolicyMeasurementLevels.h

SCPC SMM measurement levels based on policy reports.

Copyright (C) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_POLICY_MEASUREMENT_LEVELS_H_
#define MM_POLICY_MEASUREMENT_LEVELS_H_

typedef struct {
  UINT16    IoPortNumber;
  UINT16    IoWidth;
} IO_ENTRY;

/*
Memory:
  Deny write access to TXT Private/Public Space
  Deny write access to TXT Heap/DPR region
*/
#define TXT_PRIVATE_BASE  0xFED20000
#define TXT_PRIVATE_SIZE  EFI_PAGE_SIZE
#define TXT_PUBLIC_BASE   0xFED30000
#define TXT_PUBLIC_SIZE   EFI_PAGE_SIZE

#define TXT_HEAP_BASE_REG  TXT_PUBLIC_BASE + 0x300
#define TXT_HEAP_SIZE_REG  TXT_PUBLIC_BASE + 0x308
#define TXT_DPR_REG        TXT_PUBLIC_BASE + 0x330

#define TXT_REGION_COUNT  4

#define SMM_POLICY_LEVEL_10  10
#define SMM_POLICY_LEVEL_20  20
#define SMM_POLICY_LEVEL_30  30

#define MAX_SUPPORTED_LEVEL  30

#endif // MM_POLICY_MEASUREMENT_LEVELS_H_
