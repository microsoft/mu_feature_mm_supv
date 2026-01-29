/** @file
  The internal header file includes routines supporting MM Supervisor requests.

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_USER_DATA_H_
#define MM_USER_DATA_H_

typedef enum {
  MmUserRequestTypeInit,
  MmUserRequestTypeHandlerDispatch,
  MmUserRequestTypeMax
} MM_USER_REQUEST_TYPE;

#endif // MM_USER_DATA_H_
