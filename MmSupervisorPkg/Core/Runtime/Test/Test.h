/** @file
Include file for MM Supervisor test only routines.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPV_TEST_H_
#define MM_SUPV_TEST_H_

/**
 * @brief      Dispatches tasks when called each (of 3) times by the app.
 *
 * @param[in]  DispatchHandle   The dispatch handle
 * @param      RegisterContext  The register context
 * @param      CommBuffer       The communications buffer
 * @param      CommBufferSize   The communications buffer size
 *
 * @return     EFI_ACCESS_DENIED if comm buffer is the wrong size, success otherwise.
 */
EFI_STATUS
EFIAPI
SmmPagingAuditHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *RegisterContext,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  );

/**
  Initialize the test agents such as MM handlers to support communication with non MM test entities.

  @retval EFI_SUCCESS           The test agents are successfully initialized.
  @retval Others                Error codes returned from MmiHandlerUnRegister.
**/
EFI_STATUS
EFIAPI
InitializeMmSupervisorTestAgents (
  VOID
  );

#endif // MM_SUPV_TEST_H_
