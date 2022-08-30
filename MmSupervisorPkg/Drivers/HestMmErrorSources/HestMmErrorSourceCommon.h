/** @file
  Define data structure for error source descriptor information.

  Copyright (c) 2020, ARM Limited. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef HEST_ERROR_SOURCE_DESCRIPTOR_H_
#define HEST_ERROR_SOURCE_DESCRIPTOR_H_

#define HEST_ERROR_SOURCE_DESC_INFO_SIZE  (OFFSET_OF (HEST_ERROR_SOURCE_DESC_INFO, ErrSourceDescList))

//
// Data Structure to communicate the error source descriptor information from
// Standalone MM.
//
typedef struct {
  //
  // Total count of error source descriptors.
  //
  UINTN    ErrSourceDescCount;
  //
  // Total size of all the error source descriptors.
  //
  UINTN    ErrSourceDescSize;
  //
  // Array of error source descriptors that is ErrSourceDescSize in size.
  //
  UINT8    ErrSourceDescList[1];
} HEST_ERROR_SOURCE_DESC_INFO;

#endif // HEST_ERROR_SOURCE_DESCRIPTOR_H_
