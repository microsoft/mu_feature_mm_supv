/** @file

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Protocol/MmCpu.h>
#include <Guid/SmiHandlerProfile.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/SysCallLib.h>

#include "MmSupervisorRing3Broker.h"
#include "SyscallMmCpuRing3Broker.h"

/**
  This function is called by SmmChildDispatcher module to report
  a new SMI handler is registered, to SmmCore.

  @param This            The protocol instance
  @param HandlerGuid     The GUID to identify the type of the handler.
                         For the SmmChildDispatch protocol, the HandlerGuid
                         must be the GUID of SmmChildDispatch protocol.
  @param Handler         The SMI handler.
  @param CallerAddress   The address of the module who registers the SMI handler.
  @param Context         The context of the SMI handler.
                         For the SmmChildDispatch protocol, the Context
                         must match the one defined for SmmChildDispatch protocol.
  @param ContextSize     The size of the context in bytes.
                         For the SmmChildDispatch protocol, the Context
                         must match the one defined for SmmChildDispatch protocol.

  @retval EFI_SUCCESS           The information is recorded.
  @retval EFI_OUT_OF_RESOURCES  There is no enough resource to record the information.
**/
EFI_STATUS
EFIAPI
SmiHandlerProfileRegisterHandler (
  IN SMI_HANDLER_PROFILE_PROTOCOL *This,
  IN EFI_GUID *HandlerGuid,
  IN EFI_SMM_HANDLER_ENTRY_POINT2 Handler,
  IN PHYSICAL_ADDRESS CallerAddress,
  IN VOID *Context, OPTIONAL
  IN UINTN                          ContextSize OPTIONAL
  );

/**
  This function is called by SmmChildDispatcher module to report
  an existing SMI handler is unregistered, to SmmCore.

  @param This            The protocol instance
  @param HandlerGuid     The GUID to identify the type of the handler.
                         For the SmmChildDispatch protocol, the HandlerGuid
                         must be the GUID of SmmChildDispatch protocol.
  @param Handler         The SMI handler.
  @param Context         The context of the SMI handler.
                         If it is NOT NULL, it will be used to check what is registered.
  @param ContextSize     The size of the context in bytes.
                         If Context is NOT NULL, it will be used to check what is registered.

  @retval EFI_SUCCESS           The original record is removed.
  @retval EFI_NOT_FOUND         There is no record for the HandlerGuid and handler.
**/
EFI_STATUS
EFIAPI
SmiHandlerProfileUnregisterHandler (
  IN SMI_HANDLER_PROFILE_PROTOCOL *This,
  IN EFI_GUID *HandlerGuid,
  IN EFI_SMM_HANDLER_ENTRY_POINT2 Handler,
  IN VOID *Context, OPTIONAL
  IN UINTN                          ContextSize OPTIONAL
  );

///
/// MM Handler Profile Protocol instance
///
GLOBAL_REMOVE_IF_UNREFERENCED SMI_HANDLER_PROFILE_PROTOCOL  mSmiHandlerProfile = {
  SmiHandlerProfileRegisterHandler,
  SmiHandlerProfileUnregisterHandler,
};

/**
  This function is called by SmmChildDispatcher module to report
  a new SMI handler is registered, to SmmCore.

  @param This            The protocol instance
  @param HandlerGuid     The GUID to identify the type of the handler.
                         For the SmmChildDispatch protocol, the HandlerGuid
                         must be the GUID of SmmChildDispatch protocol.
  @param Handler         The SMI handler.
  @param CallerAddress   The address of the module who registers the SMI handler.
  @param Context         The context of the SMI handler.
                         For the SmmChildDispatch protocol, the Context
                         must match the one defined for SmmChildDispatch protocol.
  @param ContextSize     The size of the context in bytes.
                         For the SmmChildDispatch protocol, the Context
                         must match the one defined for SmmChildDispatch protocol.

  @retval EFI_SUCCESS           The information is recorded.
  @retval EFI_OUT_OF_RESOURCES  There is no enough resource to record the information.
**/
EFI_STATUS
EFIAPI
SmiHandlerProfileRegisterHandler (
  IN SMI_HANDLER_PROFILE_PROTOCOL  *This,
  IN EFI_GUID                      *HandlerGuid,
  IN EFI_SMM_HANDLER_ENTRY_POINT2  Handler,
  IN PHYSICAL_ADDRESS              CallerAddress,
  IN VOID                          *Context  OPTIONAL,
  IN UINTN                         ContextSize OPTIONAL
  )
{
  SysCall (SMM_MM_HDL_REG_1, (UINTN)HandlerGuid, (UINTN)Handler, CallerAddress);
  SysCall (SMM_MM_HDL_REG_2, (UINTN)HandlerGuid, (UINTN)Context, ContextSize);
  return EFI_SUCCESS;
}

/**
  This function is called by SmmChildDispatcher module to report
  an existing SMI handler is unregistered, to SmmCore.

  @param This            The protocol instance
  @param HandlerGuid     The GUID to identify the type of the handler.
                         For the SmmChildDispatch protocol, the HandlerGuid
                         must be the GUID of SmmChildDispatch protocol.
  @param Handler         The SMI handler.
  @param Context         The context of the SMI handler.
                         If it is NOT NULL, it will be used to check what is registered.
  @param ContextSize     The size of the context in bytes.
                         If Context is NOT NULL, it will be used to check what is registered.

  @retval EFI_SUCCESS           The original record is removed.
  @retval EFI_NOT_FOUND         There is no record for the HandlerGuid and handler.
**/
EFI_STATUS
EFIAPI
SmiHandlerProfileUnregisterHandler (
  IN SMI_HANDLER_PROFILE_PROTOCOL  *This,
  IN EFI_GUID                      *HandlerGuid,
  IN EFI_SMM_HANDLER_ENTRY_POINT2  Handler,
  IN VOID                          *Context  OPTIONAL,
  IN UINTN                         ContextSize OPTIONAL
  )
{
  SysCall (SMM_MM_HDL_UNREG_1, (UINTN)HandlerGuid, (UINTN)Handler, 0);
  SysCall (SMM_MM_HDL_UNREG_2, (UINTN)HandlerGuid, (UINTN)Context, ContextSize);
  return EFI_SUCCESS;
}

/**
  Initialize SmiHandler profile feature.
**/
VOID
MmUserInitializeSmiHandlerProfile (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  if ((PcdGet8 (PcdSmiHandlerProfilePropertyMask) & 0x1) != 0) {
    Handle = NULL;
    Status = MmInstallUserProtocolInterface (
               &Handle,
               &gSmiHandlerProfileGuid,
               EFI_NATIVE_INTERFACE,
               &mSmiHandlerProfile
               );
    ASSERT_EFI_ERROR (Status);
  }
}
