/** @file
  Publishes the MM Supervisor version information through optional interfaces.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/VariablePolicyHelperLib.h>

#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MmSupervisorVersion.h>
#include <Protocol/MmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>
#include <Protocol/VariablePolicy.h>
#include <Protocol/VariableWrite.h>

VOID   *mMmSupvCommonCommBufferAddress;
UINTN  mMmSupvCommonCommBufferSize;

MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *mSupvCommunicationProtocol = NULL;
EDKII_VARIABLE_POLICY_PROTOCOL        *mVariablePolicyProtocol    = NULL;

/**
  Sends the communication request to the supervisor.

  @retval     EFI_SUCCESS         Communication was successful.
  @retval     EFI_NOT_FOUND       The comm buffer or supervisor communication protocol was not found.
  @retval     Other               The status of the supervisor communication request.

**/
EFI_STATUS
MmSupvRequestDxeToMmCommunicate (
  VOID
  )
{
  EFI_STATUS                 Status;
  EFI_MM_COMMUNICATE_HEADER  *CommHeader;
  UINTN                      CommBufferSize;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer not found!\n", __func__));
    return EFI_NOT_FOUND;
  }

  CommHeader     = (EFI_MM_COMMUNICATE_HEADER *)mMmSupvCommonCommBufferAddress;
  CommBufferSize = mMmSupvCommonCommBufferSize;

  if (mSupvCommunicationProtocol == NULL) {
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&mSupvCommunicationProtocol);
    if (EFI_ERROR (Status)) {
      return EFI_NOT_FOUND;
    }
  }

  return mSupvCommunicationProtocol->Communicate (mSupvCommunicationProtocol, CommHeader, &CommBufferSize);
}

/**
  Locates a common communication buffer to use for interacting with the MM Supervisor.

  @retval     EFI_SUCCESS         A viable comm buffer was found.
  @retval     EFI_NOT_FOUND       The MM Supervisor Communication protocol was not found;

**/
EFI_STATUS
LocateMmCommonCommBuffer (
  VOID
  )
{
  EFI_STATUS  Status = EFI_SUCCESS;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    if (mSupvCommunicationProtocol == NULL) {
      Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&mSupvCommunicationProtocol);
      if (EFI_ERROR (Status)) {
        return EFI_NOT_FOUND;
      }
    }

    mMmSupvCommonCommBufferAddress = (VOID *)(UINTN)mSupvCommunicationProtocol->CommunicationRegion.VirtualStart;
    mMmSupvCommonCommBufferSize    = (UINTN)EFI_PAGES_TO_SIZE (mSupvCommunicationProtocol->CommunicationRegion.NumberOfPages);
  }

  return EFI_SUCCESS;
}

/**
  Prepares the comm buffer to be used for MM communication.

  @param[out] CommBuffer   Pointer to the CommBuffer for the test step to use.

  @retval     EFI_SUCCESS             CommBuffer is initialized and ready to use.
  @retval     EFI_NOT_FOUND           The comm buffer could not be found.
  @retval     EFI_BUFFER_TOO_SMALL    The comm buffer is too small.

**/
EFI_STATUS
MmSupvRequestGetCommBuffer (
  OUT  MM_SUPERVISOR_REQUEST_HEADER  **CommBuffer
  )
{
  EFI_STATUS                 Status;
  EFI_MM_COMMUNICATE_HEADER  *CommHeader;
  UINTN                      CommBufferSize;

  if (mMmSupvCommonCommBufferAddress == NULL) {
    Status = LocateMmCommonCommBuffer ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer not found!\n", __func__));
      return EFI_NOT_FOUND;
    }
  }

  CommHeader     = (EFI_MM_COMMUNICATE_HEADER *)mMmSupvCommonCommBufferAddress;
  CommBufferSize = sizeof (MM_SUPERVISOR_REQUEST_HEADER) + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  if (CommBufferSize > mMmSupvCommonCommBufferSize) {
    DEBUG ((DEBUG_ERROR, "[%a] - Communication buffer is too small!\n", __func__));
    return EFI_BUFFER_TOO_SMALL;
  }

  ZeroMem (CommHeader, CommBufferSize);
  CopyGuid (&CommHeader->HeaderGuid, &gMmSupervisorRequestHandlerGuid);
  CommHeader->MessageLength = sizeof (MM_SUPERVISOR_REQUEST_HEADER);

  *CommBuffer = (MM_SUPERVISOR_REQUEST_HEADER *)CommHeader->Data;

  return EFI_SUCCESS;
}

/**
  Requests MM Supervisor information by communicating with the supervisor.

  @return     MM_SUPERVISOR_VERSION_INFO_BUFFER *   A pointer to MM Supervisor version information.
  @return     NULL                                  MM Supervisor version information was not found.

**/
MM_SUPERVISOR_VERSION_INFO_BUFFER *
RequestSupervisorVersionInfo (
  VOID
  )
{
  EFI_STATUS                         Status;
  MM_SUPERVISOR_REQUEST_HEADER       *CommBuffer;
  MM_SUPERVISOR_VERSION_INFO_BUFFER  *VersionInfo;

  Status = MmSupvRequestGetCommBuffer (&CommBuffer);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return NULL;
  }

  CommBuffer->Signature = MM_SUPERVISOR_REQUEST_SIG;
  CommBuffer->Revision  = MM_SUPERVISOR_REQUEST_REVISION;
  CommBuffer->Request   = MM_SUPERVISOR_REQUEST_VERSION_INFO;
  CommBuffer->Result    = EFI_SUCCESS;

  Status = MmSupvRequestDxeToMmCommunicate ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - The MM supervisor did not successfully process the version info request. Status=%r.\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    return NULL;
  }

  if ((UINTN)CommBuffer->Result != 0) {
    Status = ENCODE_ERROR ((UINTN)CommBuffer->Result);
  }

  ASSERT_EFI_ERROR (Status);

  VersionInfo = (MM_SUPERVISOR_VERSION_INFO_BUFFER *)(CommBuffer + 1);
  ASSERT (VersionInfo->MaxSupervisorRequestLevel == MM_SUPERVISOR_REQUEST_MAX_SUPPORTED);

  DEBUG ((DEBUG_INFO, "[%a] - Supervisor version 0x%x, patch level 0x%x.\n", __func__, VersionInfo->Version, VersionInfo->PatchLevel));

  return VersionInfo;
}

/**
  Requests MM Supervisor information by communicating with the supervisor.

  @param[in]    SupervisorVersionInfoBuffer   A pointer to supervisor version information to convert to a string.
  @param[in]    SupervisorVerStrBufferSize    The size in bytes of the SupervisorVersionStr buffer.
  @param[out]   SupervisorVersionStr          A buffer of SupervisorVerStrBufferSize bytes in size to write the
                                              MM Supervisor version string to.

  @retval       EFI_SUCCESS               The buffer was successfully written with the supervisor version.
  @retval       EFI_INVALID_PARAMETER     A pointer argument provided is NULL.
  @retval       EFI_BUFFER_TOO_SMALL      SupervisorVerStrBufferSize is too small to hold the string.

**/
EFI_STATUS
ConvertSupervisorVersionInfoToDecimalString (
  IN  CONST MM_SUPERVISOR_VERSION_INFO_BUFFER  *SupervisorVersionInfoBuffer,
  IN        UINTN                              SupervisorVerStrBufferSize,
  OUT       CHAR8                              *SupervisorVersionStr
  )
{
  UINT16  MajorVersion;
  UINT16  MinorVersion;
  UINT16  Flags;

  if ((SupervisorVersionInfoBuffer == NULL) || (SupervisorVersionStr == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (SupervisorVerStrBufferSize < MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT) {
    return EFI_BUFFER_TOO_SMALL;
  }

  MajorVersion = (SupervisorVersionInfoBuffer->Version >> 16) & 0xFFFF;
  MinorVersion = (SupervisorVersionInfoBuffer->Version & 0xFFF0) >> 4;
  Flags        = (SupervisorVersionInfoBuffer->Version & 0x000F);

  DEBUG ((DEBUG_INFO, "[%a] Supervisor Published Version: %02d.%03d%1d\n", __func__, MajorVersion, MinorVersion, Flags));
  DEBUG ((DEBUG_INFO, "[%a] Major Version: %02d. Minor Version: %03d. Flags: %1d.\n", __func__, MajorVersion, MinorVersion, Flags));
  AsciiSPrint (SupervisorVersionStr, SupervisorVerStrBufferSize, "%02d.%03d%1d", MajorVersion, MinorVersion, Flags);

  return EFI_SUCCESS;
}

/**
  Publishes a UEFI variable with the MM Supervisor version.

  The UEFI variable is volatile with variable policy applied in this function.

**/
VOID
EFIAPI
PublishUefiVariable (
  VOID
  )
{
  EFI_STATUS                         Status;
  UINTN                              VarSize;
  UINT32                             VarAttributes;
  MM_SUPERVISOR_VERSION_INFO_BUFFER  *SupervisorVersionInfoBuffer;
  CHAR8                              MmSupervisorVerStr[MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT];
  CHAR8                              CurrentVarMmSupervisorVerStr[MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT];
  EDKII_VARIABLE_POLICY_PROTOCOL     *VariablePolicy;

  SupervisorVersionInfoBuffer = RequestSupervisorVersionInfo ();
  if (SupervisorVersionInfoBuffer == NULL) {
    DEBUG ((DEBUG_ERROR, "[%a] - Failed to get MM Supervisor version. Skipping version publishing.\n", __func__));
    return;
  }

  Status =  ConvertSupervisorVersionInfoToDecimalString (
              SupervisorVersionInfoBuffer,
              MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT,
              MmSupervisorVerStr
              );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "[%a] - Failed to convert MM Supervisor version (Status = %r). Skipping version publishing.\n",
      __func__,
      Status
      ));
    return;
  }

  // Check for an existing MM Supervisor version variable
  VarSize = sizeof (CurrentVarMmSupervisorVerStr);
  Status  = gRT->GetVariable (
                   MM_SUPERVISOR_VER_VAR_NAME,
                   &gMmSupervisorVerVendorGuid,
                   &VarAttributes,
                   &VarSize,
                   &CurrentVarMmSupervisorVerStr[0]
                   );
  // The version  should not have been published yet in normal circumstances.
  ASSERT (Status == EFI_NOT_FOUND);

  // Handle unexpected variable presence scenarios.
  if (EFI_ERROR (Status) ||
      (VarSize != sizeof (CurrentVarMmSupervisorVerStr)) ||
      (VarAttributes != MM_SUPERVISOR_VER_VAR_ATTRS) ||
      (AsciiStrnCmp (CurrentVarMmSupervisorVerStr, MmSupervisorVerStr, MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT) != 0))
  {
    // Variable doesn't exist or is malformed. Create a new properly formed variable.
    // If it exists already, delete it first.
    if (Status != EFI_NOT_FOUND) {
      Status = gRT->SetVariable (
                      MM_SUPERVISOR_VER_VAR_NAME,
                      &gMmSupervisorVerVendorGuid,
                      0,
                      0,
                      &CurrentVarMmSupervisorVerStr[0]
                      );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "[%a] - Failed to delete malformed MM Supervisor version variable. Status=%r.\n", __func__, Status));
        ASSERT_EFI_ERROR (Status);
        // Proceed even if we couldn't delete.
      }
    }

    VarSize       = sizeof (MmSupervisorVerStr);
    VarAttributes = MM_SUPERVISOR_VER_VAR_ATTRS;

    Status = gRT->SetVariable (
                    MM_SUPERVISOR_VER_VAR_NAME,
                    &gMmSupervisorVerVendorGuid,
                    VarAttributes,
                    VarSize,
                    &MmSupervisorVerStr[0]
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] - Failed to create MM SUpervisor version variable. Status=%r.\n", __func__, Status));
      ASSERT_EFI_ERROR (Status);
      // In failure case, go ahead and attempt to apply variable policy. Just because we can't create the variable
      // doesn't mean that someone else should be able to with invalid information.
    }
  }

  // Set up variable policies to lock the variable.
  Status = gBS->LocateProtocol (&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID **)&VariablePolicy);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[%a] - Could not locate Variable Policy protocol. Status=%r.\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
  } else {
    Status = RegisterBasicVariablePolicy (
               VariablePolicy,
               &gMmSupervisorVerVendorGuid,
               MM_SUPERVISOR_VER_VAR_NAME,
               MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT,
               MM_SUPERVISOR_VER_VAR_MAX_CHAR_COUNT,
               MM_SUPERVISOR_VER_VAR_ATTRS,
               (UINT32)(~(MM_SUPERVISOR_VER_VAR_ATTRS)),
               VARIABLE_POLICY_TYPE_LOCK_NOW
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[%a] - Failed to register MM Supervisor version variable policy. Status=%r.\n", __func__, Status));
      ASSERT_EFI_ERROR (Status);
    }
  }
}

/**
 A protocol notification function that is invoked when the MM Supervisor Communication protocol is installed.

  @param[in] Event           The signaled event.
  @param[in] Context         Not used.

**/
VOID
EFIAPI
MmSupervisorCommunicationAvailable (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;

  if (mSupvCommunicationProtocol == NULL) {
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&mSupvCommunicationProtocol);
    if (EFI_ERROR (Status)) {
      return;
    } else {
      gBS->CloseEvent (Event);
    }

    if ((mSupvCommunicationProtocol != NULL) && (mVariablePolicyProtocol != NULL)) {
      PublishUefiVariable ();
    }
  }
}

/**
 A protocol notification function that is invoked when the MM Supervisor Communication protocol is installed.

  @param[in] Event           The signaled event.
  @param[in] Context         Not used.

**/
VOID
EFIAPI
UefiVariablePolicyAvailable (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;

  if (mVariablePolicyProtocol == NULL) {
    Status = gBS->LocateProtocol (&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID **)&mVariablePolicyProtocol);
    if (EFI_ERROR (Status)) {
      return;
    } else {
      gBS->CloseEvent (Event);
    }

    if ((mSupvCommunicationProtocol != NULL) && (mVariablePolicyProtocol != NULL)) {
      PublishUefiVariable ();
    }
  }
}

/**
  Constructor that performs the steps necessary to publish MM Supervisor version information.

  @param[in]  ImageHandle  Image Handle.
  @param[in]  SystemTable  EFI System Table.

  @retval     EFI_SUCCESS  The function completed successfully. This constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
DxeMmSupervisorVersionPublicationLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_EVENT  Event;
  VOID       *Registration;

  // Note: DEPEX is not used to not impact dispatch order of the host module.
  // Note: Variable policy depends on variable write capability which accounts for the Variable Write
  //       Arch protocol and MM Supervisor Communication protocol being installed as they are required
  //       to write variables.
  Event = EfiCreateProtocolNotifyEvent (
            &gMmSupervisorCommunicationProtocolGuid,
            TPL_CALLBACK,
            MmSupervisorCommunicationAvailable,
            NULL,
            &Registration
            );
  ASSERT (Event != NULL);
  Event = EfiCreateProtocolNotifyEvent (
            &gEdkiiVariablePolicyProtocolGuid,
            TPL_CALLBACK,
            UefiVariablePolicyAvailable,
            NULL,
            &Registration
            );
  ASSERT (Event != NULL);

  return EFI_SUCCESS;
}
