/** @file
  Definitions used to publish the supervisor version.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPERVISOR_VER_H_
#define MM_SUPERVISOR_VER_H_

#define MM_SUPERVISOR_VER_VENDOR_GUID \
  { 0xD4ADFC6F, 0x2F58, 0x4BCF, { 0xA8, 0x87, 0x05, 0xEF, 0xB4, 0x7D, 0x42, 0x99 }}

#define MM_SUPERVISOR_VER_VAR_NAME  L"SmmSupervisorVersion"

#define MM_SUPERVISOR_VER_VAR_ATTRS  (EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS)

//
// Version string definition
// Version = Major.Minor
// Major: Major version is one or two digits from 0 to 99
// Minor: Minor version is four digits, the first 3 digits are the minor number, the last digit is the flag
// flag=9 represents RELEASE version, flag=8 represents DEBUG version, flag=0~7 represents test version
// MAX_VERSION_CHAR_COUNT: The maximum character count in the version string of SmmSupervisor driver,
//                         including the null terminator.
//
#define MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT  (2 + 1 + 4 + 1)

extern EFI_GUID  gMmSupervisorVerVendorGuid;

#endif
