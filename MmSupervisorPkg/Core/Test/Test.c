/** @file
Implementation of SMM CPU Services Protocol.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/DebugLib.h>
#include <Library/BaseLib.h>

#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MmPagingAudit.h>

#include "MmSupervisorCore.h"
#include "Test.h"

/**
  Initialize the test agents such as MM handlers to support communication with non MM test entities.

  @retval EFI_SUCCESS           The test agents are successfully initialized.
  @retval Others                Error codes returned from MmiHandlerUnRegister.
**/
EFI_STATUS
EFIAPI
InitializeMmSupervisorTestAgents (
  VOID
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;
  VOID        *Registration;

  DEBUG ((DEBUG_INFO, "%a Entry\n", __FUNCTION__));

  if (FeaturePcdGet (PcdMmSupervisorTestEnable)) {
    DEBUG ((DEBUG_INFO, "%a Test enabled, will register handlers.\n", __FUNCTION__));
    //
    // Register all test related MMI Handlers if enabled through platform configuration
    //
    Status = MmiSupvHandlerRegister (
               SmmPagingAuditHandler,
               &gMmPagingAuditMmiHandlerGuid,
               &Registration
               );
    ASSERT_EFI_ERROR (Status);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Registering handler for Mm paging audit test failed - %r!!!\n", __FUNCTION__, Status));
    }
  }

  DEBUG ((DEBUG_INFO, "%a Exit - %r\n", __FUNCTION__, Status));
  return Status;
}
