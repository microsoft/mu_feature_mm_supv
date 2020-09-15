/** @file
  MMI management.

  Copyright (c) 2009 - 2013, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_HANDLER_H_
#define _MM_SUPV_HANDLER_H_

/**
  Initialize MmiHandler profile feature.
**/
VOID
MmCoreInitializeSmiHandlerProfile (
  VOID
  );

/**
  This function is called by SyscallDispatcher to process user request on registering
  a child SMI handler from user space.

  @param SyscallIndex    The protocol instance
  @param HandlerGuid     The GUID to identify the type of the handler.
                         For the SmmChildDispatch protocol, the HandlerGuid
                         must be the GUID of SmmChildDispatch protocol.
  @param Arg2            When the SyscallIndex is SMM_MM_HDL_REG_1, this argument
                         contains SMI handler. When SyscallIndex is SMM_MM_HDL_REG_2,
                         this argument is the pointer to the context of the SMI handler.
                         For the SmmChildDispatch protocol, the Context must match the
                         one defined for SmmChildDispatch protocol.
  @param Arg3            When the SyscallIndex is SMM_MM_HDL_REG_1, this is the address
                         of the module who registers the SMI handler. When SyscallIndex
                         is SMM_MM_HDL_REG_2, this represents the size of the context in
                         bytes. For the SmmChildDispatch protocol, the Context
                         must match the one defined for SmmChildDispatch protocol.

  @retval EFI_SUCCESS           The information is recorded.
  @retval EFI_UNSUPPORTED       This feature is not enabled.
  @retval EFI_INVALID_PARAMETER Unrecognized syscall index is passed in.
  @retval EFI_NOT_STARTED       User handler holder status does not meet expected state.
  @retval Others                Other errors returned from SmiHandlerProfileRegisterHandler.
**/
EFI_STATUS
ProcessUserHandlerReg (
  IN UINTN     SyscallIndex,
  IN EFI_GUID  *HandlerGuid,
  IN UINT64    Arg2,
  IN UINT64    Arg3
  );

/**
  This function is called by SyscallDispatcher to process user request on registering
  a child SMI handler from user space.

  @param SyscallIndex    The protocol instance
  @param HandlerGuid     The GUID to identify the type of the handler.
                         For the SmmChildDispatch protocol, the HandlerGuid
                         must be the GUID of SmmChildDispatch protocol.
  @param Arg2            When the SyscallIndex is SMM_MM_HDL_UNREG_1, this argument
                         contains SMI handler. When SyscallIndex is SMM_MM_HDL_UNREG_2,
                         this argument is the pointer to the context of the SMI handler.
                         For the SmmChildDispatch protocol, the Context must match the
                         one defined for SmmChildDispatch protocol.
  @param Arg3            When the SyscallIndex is SMM_MM_HDL_UNREG_1, this is the address
                         of the module who registers the SMI handler. When SyscallIndex
                         is SMM_MM_HDL_UNREG_2, this represents the size of the context in
                         bytes. For the SmmChildDispatch protocol, the Context
                         must match the one defined for SmmChildDispatch protocol.

  @retval EFI_SUCCESS           The information is recorded.
  @retval EFI_UNSUPPORTED       This feature is not enabled.
  @retval EFI_INVALID_PARAMETER Unrecognized syscall index is passed in.
  @retval EFI_NOT_STARTED       User handler holder status does not meet expected state.
  @retval Others                Other errors returned from SmiHandlerProfileUnregisterHandler.
**/
EFI_STATUS
ProcessUserHandlerUnreg (
  IN UINTN                 SyscallIndex,
  IN EFI_GUID              *HandlerGuid,
  IN EFI_PHYSICAL_ADDRESS  Arg2,
  IN EFI_PHYSICAL_ADDRESS  Arg3
  );

#endif //_MM_SUPV_HANDLER_H_
