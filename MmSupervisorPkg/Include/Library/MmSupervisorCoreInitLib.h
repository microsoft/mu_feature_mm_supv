/** @file
  A library that provides custom initialization routines for the MM Supervisor Core.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_SUPERVISOR_CORE_INIT_LIB_H_
#define MM_SUPERVISOR_CORE_INIT_LIB_H_

/**
  Perform any custom initialization needed by the MM Supervisor Core.

  This function is called at the beginning of the MM Supervisor Core entry point,
  before any other MM Supervisor Core initialization is performed.

  This function allows any critical initialization specific to a given platform to be
  hooked at the beginning of the MM Supervisor Core initialization. This function must
  only contain code that is completely independent of any other MM Core initialization
  or services outside of the function implementation itself.

**/
VOID
EFIAPI
MmSupervisorCoreEntryInit (
  VOID
  );

#endif // MM_SUPERVISOR_CORE_INIT_LIB_H_
