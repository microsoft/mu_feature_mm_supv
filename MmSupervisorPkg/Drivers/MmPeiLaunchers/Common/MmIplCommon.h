/** @file
  Common internal routines shared by MM IPL in both PEI and DXE phases.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_IPL_COMMON_H_
#define MM_IPL_COMMON_H_

//
// Function prototypes from produced protocols
//

/**
  Helper function for MM Communication protocol or PPI.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication Protocol that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] TalkToSupervisor    Flag to indicate if this transaction will be
                                 interfacing supervisor or users.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into SMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SmmCommunicationCommunicateWorker (
  IN     BOOLEAN  TalkToSupervisor,
  IN OUT VOID     *CommBuffer,
  IN OUT UINTN    *CommSize OPTIONAL
  );

/**
  Helper function of event notification that is fired when a GUIDed Event Group is
  signaled.

  @param  NotifierGuid           GUID of event that triggered this notification.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The NotifierGuid was NULL.
  @retval Others                 See definition of SmmCommunicationCommunicateWorker.

**/
EFI_STATUS
EFIAPI
SmmIplGuidedEventNotifyWorker (
  IN EFI_GUID  *NotifierGuid
  );

/**
  Helper function that iterates each HOB of gMmCommonRegionHobGuid to cache
  designated communication buffer for later use.

  @param[out]  SupvCommonRegionDesc     Holder of detailed information about
                                        Supervisor communication protocol/PPI.

  @retval EFI_SUCCESS                   The entry point is executed successfully.
  @retval EFI_INVALID_PARAMETER         Input parameter is NULL.
  @retval EFI_NOT_FOUND                 One or more of the expected communication
                                        buffers are not discovered or with NULL
                                        values.

**/
EFI_STATUS
EFIAPI
InitializeCommunicationBufferFromHob (
  IN EFI_MEMORY_DESCRIPTOR  *SupvCommonRegionDesc
  );

/**
  Abstraction layer for MM Control Trigger under various environments (PEI & DXE).
  The IPL driver will implement this functionality to be used by MM Communication
  routine.

  @retval Other             See definition of EFI_MM_ACTIVATE.

 **/
EFI_STATUS
InternalMmControlTrigger (
  VOID
  );

/**
  Communicate to MmSupervisor to query version information, as defined in
  MM_SUPERVISOR_VERSION_INFO_BUFFER.

  @param[out] VersionInfo        Pointer to hold returned version information structure.

  @retval EFI_SUCCESS            The version information was successfully queried.
  @retval EFI_INVALID_PARAMETER  The VersionInfo was NULL.
  @retval EFI_SECURITY_VIOLATION The Version returned by supervisor is invalid.
  @retval Others                 Other error status returned during communication to supervisor.

**/
EFI_STATUS
QuerySupervisorVersion (
  OUT MM_SUPERVISOR_VERSION_INFO_BUFFER  *VersionInfo
  );

//
// SMM IPL global variables
//
extern UINT64                     mMmSupvCommonBufferPages;
extern UINT64                     mMmUserCommonBufferPages;
extern VOID                       *mMmSupvCommonBuffer;
extern VOID                       *mMmUserCommonBuffer;
extern VOID                       *mMmSupvCommonBufferPhysical;
extern VOID                       *mMmUserCommonBufferPhysical;
extern EFI_MM_COMMUNICATE_HEADER  *mCommunicateHeader;

extern MM_COMM_BUFFER_STATUS      *mMmCommBufferStatus;

#endif // MM_IPL_COMMON_H_
