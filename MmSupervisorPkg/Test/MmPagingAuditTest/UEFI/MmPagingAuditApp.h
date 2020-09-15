/** @file -- DxePagingAuditCommon.h

This DXE Driver writes page table and memory map information to SFS when triggered
by an event.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_PAGING_AUDIT_APP_H_
#define MM_PAGING_AUDIT_APP_H_

#define MAX_STRING_SIZE  0x1000

/**
  This helper function writes a string entry to the memory info database buffer.
  If string would exceed current buffer allocation, it will realloc.

  NOTE: The buffer tracks its size. It does not work with NULL terminators.

  @param[in]  DatabaseString    A pointer to a CHAR8 string that should be
                                added to the database.

  @retval     EFI_SUCCESS           String was successfully added.
  @retval     EFI_OUT_OF_RESOURCES  Buffer could not be grown to accommodate string.
                                    String has not been added.

**/
EFI_STATUS
EFIAPI
AppendToMemoryInfoDatabase (
  IN CONST CHAR8  *DatabaseString
  );

/**
   Dump platform specific handler. Created handler(s) need to be compliant with
   Windows\PagingReportGenerator.py, i.e. TSEG.
**/
VOID
EFIAPI
DumpProcessorSpecificHandlers (
  VOID
  );

/**
 * @brief      Writes a buffer to file.
 *
 * @param      FileName     The name of the file being written to.
 * @param      Buffer       The buffer to write to file.
 * @param[in]  BufferSize   Size of the buffer.
 * @param[in]  WriteCount   Number to append to the end of the file.
 */
VOID
EFIAPI
WriteBufferToFile (
  IN CONST CHAR16  *FileName,
  IN       VOID    *Buffer,
  IN       UINTN   BufferSize
  );

#endif // MM_PAGING_AUDIT_APP_H_
