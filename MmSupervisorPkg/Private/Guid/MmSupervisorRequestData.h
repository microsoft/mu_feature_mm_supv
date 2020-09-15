/** @file
  Data structure used to request information/functionality between DXE and
  MM supervisor.

Copyright (c), Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_REQUEST_DATA_H_
#define _MM_SUPV_REQUEST_DATA_H_

#define MM_SUPERVISOR_REQUEST_HANDLER_GUID \
  { 0x8c633b23, 0x1260, 0x4ea6, { 0x83, 0xf, 0x7d, 0xdc, 0x97, 0x38, 0x21, 0x11 } }

extern EFI_GUID  gMmSupervisorRequestHandlerGuid;

#define   MM_SUPERVISOR_REQUEST_SIG       SIGNATURE_32('M', 'S', 'U', 'P')
#define   MM_SUPERVISOR_REQUEST_REVISION  1

#pragma pack(push, 1)

typedef struct _MM_SUPERVISOR_REQUEST_HEADER {
  UINT32    Signature;
  UINT32    Revision;
  UINT32    Request;
  UINT32    Reserved;
  UINT64    Result;       // MM Communication result, cast to EFI_STATUS before usage
} MM_SUPERVISOR_REQUEST_HEADER;

/**
  This structure is used to communicate requested unblock memory information
  from DXE to MM environment. This data will be checked by MM supervisor
  to ensure the requested region does not cover critical pages.

**/
typedef struct _UNBLOCK_MEMORY_DATA_BUFFER {
  EFI_MEMORY_DESCRIPTOR    MemoryDescriptor;
  EFI_GUID                 IdentifierGuid;
} MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS;

/**
  This structure is used to communicate supervisor version number, patch level, and
  maximal communication level supported.

**/
typedef struct _VERSION_INFO_BUFFER {
  UINT32    Version;
  UINT32    PatchLevel;
  UINT64    MaxSupervisorRequestLevel;
} MM_SUPERVISOR_VERSION_INFO_BUFFER;

#pragma pack(pop)

/**
  @retval EFI_SECURITY_VIOLATION     If requested page is not page aligned
  @retval EFI_ACCESS_DENIED          If request occurs after ready to lock or policy fetching
  @retval EFI_INVALID_PARAMETER      If incoming memory ID is invalid
 **/
#define   MM_SUPERVISOR_REQUEST_UNBLOCK_MEM  0x0001

/**
  @retval EFI_SECURITY_VIOLATION     If requested page is not page aligned
  @retval EFI_ACCESS_DENIED          If request occurs after ready to lock or policy fetching
  @retval EFI_BUFFER_TOO_SMALL       If incoming communication buffer is not big enough to hold
                                     an empty policy structure
  @retval EFI_OUT_OF_RESOURCES       If incoming communication buffer is not big enough to hold
                                     the entire policy structure
 **/
#define   MM_SUPERVISOR_REQUEST_FETCH_POLICY  0x0002

/**
  @retval EFI_INVALID_PARAMETER      If communication buffer is NULL
  @retval EFI_SECURITY_VIOLATION     If communication buffer is not pointing to designated supervisor buffer
  @retval EFI_ACCESS_DENIED          If request occurs before MM foundation is setup
  @retval EFI_COMPROMISED_DATA       Supervisor image buffer does not pass minimal PeCoff check
 **/
#define   MM_SUPERVISOR_REQUEST_VERSION_INFO  0x0003

/**
  Maximal request index supported by supervisor. When supported, the value of this definition
  will be populated in the MaxSupervisorRequestLevel of VERSION_INFO_BUFFER upon a successful query
  to supervisor.

 **/
#define   MM_SUPERVISOR_REQUEST_MAX_SUPPORTED  MM_SUPERVISOR_REQUEST_VERSION_INFO

#endif // _MM_SUPV_REQUEST_DATA_H_
