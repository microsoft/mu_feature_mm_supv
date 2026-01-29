/** @file
  Entry point to a Standalone MM driver.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2016 - 2018, ARM Ltd. All rights reserved.<BR>
Copyright (c) 2018, Linaro, Limited. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/StandaloneMmCoreEntryPoint.h>

#include "../../Core/Common/UserDefinitions.h"

//
// Cache copy of HobList pointer.
//
VOID  *gHobList = NULL;

VOID
EFIAPI
MmEntryPoint (
  IN CONST EFI_MM_ENTRY_CONTEXT  *MmEntryContext
  );

/**
  The entry point of PE/COFF Image for a Standalone MM Driver.

  This function is the entry point for a Standalone MM Driver.
  This function must call ProcessLibraryConstructorList() and
  ProcessModuleEntryPointList().
  If the return status from ProcessModuleEntryPointList()
  is an error status, then ProcessLibraryDestructorList() must be called.
  The return value from ProcessModuleEntryPointList() is returned.
  If _gMmRevision is not zero and SystemTable->Hdr.Revision is
  less than _gMmRevision, then return EFI_INCOMPATIBLE_VERSION.

  @param   UserOpCode    The MM User operation code.
  @param   Context       Pointer to the user context.
  @param   ContextSize   Size of the user context.

  @retval  EFI_SUCCESS               The Standalone MM Driver exited normally.
  @retval  EFI_INCOMPATIBLE_VERSION  _gMmRevision is greater than
                                     MmSystemTable->Hdr.Revision.
  @retval  Other                     Return value from
                                     ProcessModuleEntryPointList().

**/
EFI_STATUS
EFIAPI
_ModuleEntryPointWorker (
  IN MM_USER_REQUEST_TYPE  UserOpCode,
  IN VOID                  *Context  OPTIONAL,
  IN UINTN                 ContextSize
  )
{
  EFI_STATUS  Status;

  switch (UserOpCode) {
    case MmUserRequestTypeInit:
      gHobList = Context;

      //
      // Call the Standalone MM Core entry point
      //
      ProcessModuleEntryPointList (gHobList);
      Status = EFI_SUCCESS;
      break;

    case MmUserRequestTypeHandlerDispatch:
      // TODO: Patch the SmmStartupThisAp to use the syscall version.
      MmEntryPoint ((EFI_MM_ENTRY_CONTEXT *)Context);
      break;

    default:
      Status = EFI_UNSUPPORTED;
      break;
  }

  //
  // Return the cumulative return status code from all of the driver entry points
  //
  return Status;
}
