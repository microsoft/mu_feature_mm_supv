/** @file

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Pi/PiMmCis.h>

#include <Protocol/MmCpu.h>
#include <Protocol/MmReadyToLock.h>
#include <Protocol/DxeMmReadyToLock.h>

#include <Guid/EventGroup.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/SysCallLib.h>

#include "MmSupervisorRing3Broker.h"
#include "MmCpu/SyscallMmCpuRing3Broker.h"
#include "Handler/MmHandlerProfileBroker.h"

//
// Table of MMI Handlers that are registered by the MM Core when it is initialized
//
MM_SHIM_MMI_HANDLERS  mMmShimMmiHandlers[] = {
  { MmReadyToLockHandler,     &gEfiDxeMmReadyToLockProtocolGuid, NULL, TRUE  },
  { MmEndOfDxeHandler,        &gEfiEndOfDxeEventGroupGuid,       NULL, FALSE },
  { MmExitBootServiceHandler, &gEfiEventExitBootServicesGuid,    NULL, FALSE },
  { MmReadyToBootHandler,     &gEfiEventReadyToBootGuid,         NULL, FALSE },
  { NULL,                     NULL,                              NULL, FALSE },
};

EFI_STATUS
EFIAPI
MmEfiNotAvailableYetArg5 (
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  Arg4,
  UINTN  Arg5
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.
  //
  return EFI_NOT_AVAILABLE_YET;
}

//
// MM Core global variable for MM System Table.  Only accessed as a physical structure in MMRAM.
//
EFI_MM_SYSTEM_TABLE  gMmShimMmst = {
  // The table header for the MMST.
  .Hdr                          = {
    .Signature  = MM_MMST_SIGNATURE,
    .Revision   = EFI_MM_SYSTEM_TABLE_REVISION,
    .HeaderSize = sizeof (gMmShimMmst.Hdr)
  },
  .MmFirmwareVendor            = NULL,
  .MmFirmwareRevision          = 0,
  .MmInstallConfigurationTable = SyscallMmInstallConfigurationTable,
  // I/O Service
  .MmIo                         = {
    {
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5,        // MmMemRead
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5         // MmMemWrite
    },
    {
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5,        // MmIoRead
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5         // MmIoWrite
    }
  },
  // Runtime memory services
  .MmAllocatePool  = MmAllocateUserPool,
  .MmFreePool      = MmFreeUserPool,
  .MmAllocatePages = SyscallMmAllocatePages,
  .MmFreePages     = SyscallMmFreePages,
  // MP service
  .MmStartupThisAp       = SyscallMmStartupThisAp,    // MmStartupThisAp
  .CurrentlyExecutingCpu = 0,                         // CurrentlyExecutingCpu
  .NumberOfCpus          = 0,                         // NumberOfCpus
  .CpuSaveStateSize      = NULL,                      // CpuSaveStateSize
  .CpuSaveState          = NULL,                      // CpuSaveState
  .NumberOfTableEntries  = 0,                         // NumberOfTableEntries
  .MmConfigurationTable  = NULL,                      // MmConfigurationTable
  // Protocol services
  .MmInstallProtocolInterface   = MmInstallUserProtocolInterface,
  .MmUninstallProtocolInterface = MmUninstallUserProtocolInterface,
  .MmHandleProtocol             = MmHandleUserProtocol,
  .MmRegisterProtocolNotify     = MmRegisterUserProtocolNotify,
  .MmLocateHandle               = MmLocateHandleUser,
  .MmLocateProtocol             = MmLocateUserProtocol,
  // MM handler services
  .MmiManage            = NULL,
  .MmiHandlerRegister   = SyscallMmiHandlerRegister,
  .MmiHandlerUnRegister = SyscallMmiHandlerUnRegister
};

/**
  Software MMI handler that is called when a ExitBoot Service event is signaled.

  @param  DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmExitBootServiceHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_HANDLE      MmHandle;
  EFI_STATUS      Status              = EFI_SUCCESS;
  STATIC BOOLEAN  mInExitBootServices = FALSE;

  if (!mInExitBootServices) {
    MmHandle = NULL;
    Status   = MmInstallUserProtocolInterface (
                 &MmHandle,
                 &gEfiEventExitBootServicesGuid,
                 EFI_NATIVE_INTERFACE,
                 NULL
                 );
  }

  mInExitBootServices = TRUE;
  return Status;
}

/**
  Software MMI handler that is called when a ExitBoot Service event is signaled.

  @param  DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmReadyToBootHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_HANDLE      MmHandle;
  EFI_STATUS      Status         = EFI_SUCCESS;
  STATIC BOOLEAN  mInReadyToBoot = FALSE;

  if (!mInReadyToBoot) {
    MmHandle = NULL;
    Status   = MmInstallUserProtocolInterface (
                 &MmHandle,
                 &gEfiEventReadyToBootGuid,
                 EFI_NATIVE_INTERFACE,
                 NULL
                 );
  }

  mInReadyToBoot = TRUE;
  return Status;
}

/**
  Software MMI handler that is called when the DxeMmReadyToLock protocol is added
  or if gEfiEventReadyToBootGuid is signaled.  This function unregisters the
  Software SMIs that are nor required after MMRAM is locked and installs the
  MM Ready To Lock Protocol so MM Drivers are informed that MMRAM is about
  to be locked.

  @param  DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmReadyToLockHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  EFI_HANDLE  MmHandle;

  DEBUG ((DEBUG_INFO, "MmReadyToLockHandler\n"));

  //
  // Unregister MMI Handlers that are no longer required after the MM driver dispatch is stopped
  //
  for (Index = 0; mMmShimMmiHandlers[Index].HandlerType != NULL; Index++) {
    if (mMmShimMmiHandlers[Index].UnRegister) {
      gMmShimMmst.MmiHandlerUnRegister (mMmShimMmiHandlers[Index].DispatchHandle);
    }
  }

  //
  // Install MM Ready to lock protocol
  //
  MmHandle = NULL;
  Status   = MmInstallUserProtocolInterface (
               &MmHandle,
               &gEfiMmReadyToLockProtocolGuid,
               EFI_NATIVE_INTERFACE,
               NULL
               );

  return Status;
}

/**
  Software MMI handler that is called when the EndOfDxe event is signaled.
  This function installs the MM EndOfDxe Protocol so MM Drivers are informed that
  platform code will invoke 3rd part code.

  @param  DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmEndOfDxeHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  MmHandle;

  DEBUG ((DEBUG_INFO, "MmEndOfDxeHandler\n"));
  //
  // Install MM EndOfDxe protocol
  //
  MmHandle = NULL;
  Status   = MmInstallUserProtocolInterface (
               &MmHandle,
               &gEfiMmEndOfDxeProtocolGuid,
               EFI_NATIVE_INTERFACE,
               NULL
               );
  return Status;
}

EFI_STATUS
EFIAPI
MmSupervisorRing3BrokerEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  mMmCpuHandle = NULL;
  EFI_HANDLE  MmHandle     = NULL;
  UINTN       Index        = 0;

  MmInitializeMemoryServices ();

  // Step 1: Register with MM Core with handler jump point
  SysCall (SMM_REG_HDL_JMP, (UINTN)CentralRing3JumpPointer, (UINTN)ApRing3JumpPointer, 0);

  // Step 2: Register ring 3 version of gMmst
  SysCall (SMM_SET_CPL3_TBL, (UINTN)&gMmShimMmst, 0, 0);

  // Step 3: Install the SMM CPU Protocol into SMM protocol database
  Status = MmInstallUserProtocolInterface (
             &mMmCpuHandle,
             &gEfiMmCpuProtocolGuid,
             EFI_NATIVE_INTERFACE,
             &mMmCpu
             );

  // Step 4: Notify the completion of this driver just in case
  Status = MmInstallUserProtocolInterface (
             &MmHandle,
             &gMmRing3HandlerReadyProtocol,
             EFI_NATIVE_INTERFACE,
             NULL
             );

  //
  // Register all handlers in the shim table
  //
  for (Index = 0; mMmShimMmiHandlers[Index].HandlerType != NULL; Index++) {
    DEBUG ((DEBUG_INFO, "MmiShimHandlerRegister - before %p\n", mMmShimMmiHandlers[Index].DispatchHandle));
    Status = gMmShimMmst.MmiHandlerRegister (
                           mMmShimMmiHandlers[Index].Handler,
                           mMmShimMmiHandlers[Index].HandlerType,
                           &mMmShimMmiHandlers[Index].DispatchHandle
                           );
    DEBUG ((DEBUG_INFO, "MmiShimHandlerRegister - GUID %g - Status %d %p\n", mMmShimMmiHandlers[Index].HandlerType, Status, mMmShimMmiHandlers[Index].DispatchHandle));
  }

  // Publish Mmi handler profile protocol for handler registration if enabled
  MmUserInitializeSmiHandlerProfile ();

  return Status;
}
