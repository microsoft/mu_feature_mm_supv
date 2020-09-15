/** @file
  EFI MM Supervisor Communication Protocol as defined in the PI 1.5 specification.

  This protocol provides a means of communicating between drivers outside of MM and MMI
  handlers inside of MM.

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_SUPV_COMMUNICATION_H_
#define _MM_SUPV_COMMUNICATION_H_

#define MM_SUPERVISOR_COMMUNICATION_PROTOCOL_GUID \
  { \
    0x495b267c, 0xfc7f, 0x4f03, { 0xad, 0x1f, 0xd8, 0x67, 0x69, 0xe3, 0x25, 0xb5 } \
  }

#define MM_SUPERVISOR_COMM_PROTOCOL_VER  1

#define MM_SUPERVISOR_COMM_PROTOCOL_SIG  SIGNATURE_32('M', 'S', 'C', 'P')

typedef struct _MM_SUPERVISOR_COMMUNICATION_PROTOCOL MM_SUPERVISOR_COMMUNICATION_PROTOCOL;

extern EFI_GUID  gMmSupervisorCommunicationProtocolGuid;

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PROTOCOL instance.
  @param[in] CommBuffer          A pointer to the buffer to convey into MMRAM.
  @param[in] CommSize            The size of the data buffer being passed in. On exit, the size of data
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
typedef
EFI_STATUS
(EFIAPI *SUPERVISOR_MM_COMMUNICATE)(
  IN CONST MM_SUPERVISOR_COMMUNICATION_PROTOCOL   *This,
  IN OUT VOID                                      *CommBuffer,
  IN OUT UINTN                                     *CommSize OPTIONAL
  );

#pragma pack(1)

struct _MM_SUPERVISOR_COMMUNICATION_PROTOCOL {
  UINT32                       Signature;
  UINT32                       Version;
  SUPERVISOR_MM_COMMUNICATE    Communicate;
  EFI_MEMORY_DESCRIPTOR        CommunicationRegion;
};

#pragma pack()

#endif
