/** @file -- PagingAudit.c
This is the driver portion of the MmPagingAuditApp driver.
It copies valid entries from the page tables into the communication buffer.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SpamResponder.h>
#include <SmmSecurePolicy.h>

#include <IndustryStandard/Tpm20.h>
#include <Guid/MmCoreData.h>

#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>

/**
  The main validation routine for the SPAM Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then measure
  the content into TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and measure into TPM.

  @param[in]  SpamResponderData  The pointer to the SPAM_RESPONDER_DATA structure.
  @param[out] RetDigestList      The digest list of the image.
  @param[out] NewPolicy          The new policy populated by this routine.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SpamResponderReport (
  IN  SPAM_RESPONDER_DATA *SpamResponderData,
  OUT TPML_DIGEST_VALUES  *RetDigestList,
  OUT VOID                **NewPolicy  OPTIONAL
  );

extern MM_CORE_PRIVATE_DATA             *gMmCorePrivate;
extern EFI_PHYSICAL_ADDRESS             MmSupvAuxFileBase;
extern EFI_PHYSICAL_ADDRESS             MmSupvAuxFileSize;
extern SMM_SUPV_SECURE_POLICY_DATA_V1_0 *MemPolicySnapshot;

/**
  Get the size of the SMI Handler in bytes.

  @retval The size, in bytes, of the SMI Handler.

**/
UINTN
EFIAPI
GetSmiHandlerSize (
  VOID
  );

/**
  Registers a supervisor handler to execute within MM. This handler will not be demoted when dispatched.

  @param  Handler        Handler service function pointer.
  @param  HandlerType    Points to the handler type or NULL for root MMI handlers.
  @param  DispatchHandle On return, contains a unique handle which can be used to later unregister the handler function.

  @retval EFI_SUCCESS           Handler register success.
  @retval EFI_INVALID_PARAMETER Handler or DispatchHandle is NULL.

**/
EFI_STATUS
EFIAPI
MmiSupvHandlerRegister (
  IN   EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN   CONST EFI_GUID              *HandlerType  OPTIONAL,
  OUT  EFI_HANDLE                  *DispatchHandle
  );

/**
  This function retrieves the attributes of the memory region specified by
  BaseAddress and Length. If different attributes are got from different part
  of the memory region, EFI_NO_MAPPING will be returned.

  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        Pointer to attributes returned.

  @retval EFI_SUCCESS           The attributes got for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes is NULL.
                                Length is larger than MAX_INT64. // MU_CHANGE: Avoid Length overflow for INT64
  @retval EFI_NO_MAPPING        Attributes are not consistent cross the memory
                                region.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
SmmGetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  OUT UINT64                *Attributes
  );

/**
  This function retrieves the attributes of the memory region specified by
  BaseAddress and Length. If different attributes are got from different part
  of the memory region, EFI_NO_MAPPING will be returned.

  @param  PageTableBase     The base address of the page table.
  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        Pointer to attributes returned.

  @retval EFI_SUCCESS           The attributes got for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes is NULL.
                                Length is larger than MAX_INT64. // MU_CHANGE: Avoid Length overflow for INT64
  @retval EFI_NO_MAPPING        Attributes are not consistent cross the memory
                                region.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
GetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  PageTableBase,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  OUT UINT64                *Attributes
  )
{
  return SmmGetMemoryAttributes (BaseAddress,
                                  Length,
                                Attributes
  );
}

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
SpamValidationTestHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *RegisterContext,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  EFI_STATUS          Status = EFI_SUCCESS;
  TPML_DIGEST_VALUES  DigestList[HASH_COUNT];
  VOID*               PolicyBuffer = NULL;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // If input is invalid, stop processing this SMI
  //
  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad pointers!\n", __FUNCTION__));
    return EFI_ACCESS_DENIED;
  }

  //
  // Get information about the image being loaded
  //
  SPAM_RESPONDER_DATA SpamData = {
    SPAM_RESPONDER_STRUCT_SIGNATURE,
    SPAM_REPSONDER_STRUCT_MINOR_VER,
    SPAM_REPSONDER_STRUCT_MAJOR_VER,
    sizeof (SPAM_RESPONDER_DATA),
    0,
    0,
    0,
    0,
    0,
    0
  };

  SpamData.MmEntrySize = GetSmiHandlerSize ();
  SpamData.MmSupervisorSize = gMmCorePrivate->MmCoreImageSize;
  SpamData.MmSupervisorAuxBase = MmSupvAuxFileBase;
  SpamData.MmSupervisorAuxSize = MmSupvAuxFileSize;

  Status = SpamResponderReport (&SpamData, DigestList, &PolicyBuffer);
  ASSERT_EFI_ERROR (Status);

  ASSERT (CompareMem (PolicyBuffer, MemPolicySnapshot, MemPolicySnapshot->Size) == 0);

  for (UINTN Index = 0; Index < HASH_COUNT; Index++) {
    switch (DigestList[Index].digests[0].hashAlg) {
      case TPM_ALG_SHA256:
        DUMP_HEX (DEBUG_INFO, 0, DigestList[Index].digests[0].digest.sha256, SHA256_DIGEST_SIZE, "");
        break;
      default:
        DEBUG ((DEBUG_ERROR, "Unrecognized hash alrogithm %d!!!\n", DigestList[Index].digests[0].hashAlg));
        ASSERT (FALSE);
        break;
    }
  }

  return Status;
}

/**
  Initialize the test agents such as MM handlers to support communication with non MM test entities.

  @retval EFI_SUCCESS           The test agents are successfully initialized.
  @retval Others                Error codes returned from MmiHandlerUnRegister.
**/
EFI_STATUS
EFIAPI
ResponderValidationTestLibConstructor (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
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
               SpamValidationTestHandler,
               &gSpamValidationTestHandlerGuid,
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
