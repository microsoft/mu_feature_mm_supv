/** @file
  MM Core data.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2018, ARM Limited. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __MM_SUPV_TELEMETRY_DATA_H__
#define __MM_SUPV_TELEMETRY_DATA_H__

#define MM_SUPV_TELEMETRY_SIGNATURE  SIGNATURE_32('M','S','V','T')

typedef struct {
  UINT32                    Signature;
  UINT32                    TelemetrySize;
  UINT64                    ExceptionType;
  EFI_GUID                  DriverId;
  UINT64                    ExceptionRIP;
  UINT64                    DriverLoadAddress;
  EFI_SYSTEM_CONTEXT_X64    ExceptionData;
  // UINT8*                 ExtraData
} MM_SUPV_TELEMETRY_DATA;

#endif
