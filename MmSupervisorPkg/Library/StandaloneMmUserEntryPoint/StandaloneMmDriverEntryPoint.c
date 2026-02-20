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
  @param   Arg1          The first argument for the MM User operation.
  @param   Arg2          The second argument for the MM User operation.

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
  IN UINTN                 Arg1,
  IN UINTN                 Arg2
  )
{
  EFI_STATUS  Status;

  switch (UserOpCode) {
    case MmUserRequestTypeInit:
      gHobList = (VOID *)Arg1;

      //
      // Call the Standalone MM Core entry point
      //
      ProcessModuleEntryPointList (gHobList);
      Status = EFI_SUCCESS;
      break;

    case MmUserRequestTypeHandlerDispatch:
      MmEntryPoint ((EFI_MM_ENTRY_CONTEXT *)Arg1);
      break;

    case MmUserApProcedure:
      // For an AP procedure, the context is a pointer to the procedure argument
      // Caution: this is a MP routine, handle with care.
      DEBUG ((DEBUG_INFO, "Received AP procedure call with arg1=0x%x, arg2=0x%x\n", Arg1, Arg2));
      ((EFI_AP_PROCEDURE)Arg1)((VOID *)Arg2);
      Status = EFI_SUCCESS;
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
