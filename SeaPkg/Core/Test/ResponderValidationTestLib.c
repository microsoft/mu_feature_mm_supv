/** @file -- PagingAudit.c
This is the driver portion of the MmPagingAuditApp driver.
It copies valid entries from the page tables into the communication buffer.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SeaResponder.h>
#include <SmmSecurePolicy.h>

#include <IndustryStandard/Tpm20.h>
#include <Guid/SeaTestCommRegion.h>

#include <Library/StandaloneMmMemLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/SecurePolicyLib.h>

extern SMM_SUPV_SECURE_POLICY_DATA_V1_0  *MemPolicySnapshot;
extern SMM_SUPV_SECURE_POLICY_DATA_V1_0  *FirmwarePolicy;

/**
  The main validation routine for the SEA Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then hash
  the content using TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and hash using TPM.

  @param[in]  CpuIndex           The index of the CPU.
  @param[in]  AuxFileBase        The base address of the auxiliary file.
  @param[in]  AuxFileSize        The size of the auxiliary file.
  @param[in]  MmiEntryFileSize   The size of the MMI entry file.
  @param[in]  GoldDigestList     The digest list of the MMI entry and supervisor core.
  @param[in]  GoldDigestListCnt  The count of the digest list.
  @param[out] NewPolicy          The new policy populated by this routine.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SeaResponderReport (
  IN  UINTN                 CpuIndex,
  IN  EFI_PHYSICAL_ADDRESS  AuxFileBase,
  IN  UINT64                AuxFileSize,
  IN  UINT64                MmiEntryFileSize,
  IN  TPML_DIGEST_VALUES    *GoldDigestList,
  IN  UINTN                 GoldDigestListCnt,
  OUT VOID                  **NewPolicy  OPTIONAL
  );

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
  return SmmGetMemoryAttributes (
           BaseAddress,
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
SeaValidationTestHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *RegisterContext,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  EFI_STATUS                  Status        = EFI_SUCCESS;
  VOID                        *PolicyBuffer = NULL;
  SEA_TEST_COMM_INPUT_REGION  *CommRegion   = (SEA_TEST_COMM_INPUT_REGION *)CommBuffer;

  DEBUG ((DEBUG_INFO, "%a()\n", __func__));

  //
  // If input is invalid, stop processing this SMI
  //
  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad pointers!\n", __func__));
    Status = EFI_ACCESS_DENIED;
    goto Done;
  }

  if (MmCommBufferValid ((EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer, *CommBufferSize) == FALSE) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad pointers!\n", __func__));
    Status = EFI_ACCESS_DENIED;
    goto Done;
  }

  if ((*CommBufferSize < sizeof (SEA_TEST_COMM_INPUT_REGION)) ||
      (*CommBufferSize < sizeof (SEA_TEST_COMM_OUTPUT_REGION)))
  {
    DEBUG ((DEBUG_ERROR, "%a - Comm buffer size too small! Should be at least %d, got %d\n", __func__, MAX (sizeof (SEA_TEST_COMM_INPUT_REGION), sizeof (SEA_TEST_COMM_OUTPUT_REGION)), *CommBufferSize));
    Status = EFI_ACCESS_DENIED;
    goto Done;
  }

  Status = SeaResponderReport (
             gMmst->CurrentlyExecutingCpu,
             (EFI_PHYSICAL_ADDRESS)(UINTN)CommRegion->SupervisorAuxFileBase,
             CommRegion->SupervisorAuxFileSize,
             CommRegion->MmiEntryFileSize,
             CommRegion->SupvDigestList,
             CommRegion->SupvDigestListCount,
             &PolicyBuffer
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - SeaResponderReport failed - %r\n", __func__, Status));
    goto Done;
  }

  // Now reevaluate the communication buffer size
  if (((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)PolicyBuffer)->Size + OFFSET_OF (SEA_TEST_COMM_OUTPUT_REGION, FirmwarePolicy) > *CommBufferSize) {
    DEBUG ((DEBUG_ERROR, "%a - Policy buffer is NULL!\n", __func__));
    *CommBufferSize = ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)PolicyBuffer)->Size + OFFSET_OF (SEA_TEST_COMM_OUTPUT_REGION, FirmwarePolicy);
    Status          = EFI_BUFFER_TOO_SMALL;
    goto Done;
  }

  // Making sure the validation routine is giving us the same policy buffer output
  if (CompareMemoryPolicy (PolicyBuffer, MemPolicySnapshot) == FALSE) {
    DEBUG ((DEBUG_ERROR, "%a Memory policy changed since the snapshot!!!\n", __func__));
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  *CommBufferSize = ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)PolicyBuffer)->Size + OFFSET_OF (SEA_TEST_COMM_OUTPUT_REGION, FirmwarePolicy);
  CopyMem ((UINT8 *)CommBuffer + OFFSET_OF (SEA_TEST_COMM_OUTPUT_REGION, FirmwarePolicy), PolicyBuffer, ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)PolicyBuffer)->Size);

Done:
  if (PolicyBuffer != NULL) {
    FreePages (PolicyBuffer, EFI_SIZE_TO_PAGES (FirmwarePolicy->Size + MEM_POLICY_SNAPSHOT_SIZE));
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

  DEBUG ((DEBUG_INFO, "%a Entry\n", __func__));

  if (FeaturePcdGet (PcdMmSupervisorTestEnable)) {
    DEBUG ((DEBUG_INFO, "%a Test enabled, will register handlers.\n", __func__));
    //
    // Register all test related MMI Handlers if enabled through platform configuration
    //
    Status = MmiSupvHandlerRegister (
               SeaValidationTestHandler,
               &gSeaValidationTestHandlerGuid,
               &Registration
               );
    ASSERT_EFI_ERROR (Status);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a Registering handler for Mm paging audit test failed - %r!!!\n", __func__, Status));
    }
  }

  DEBUG ((DEBUG_INFO, "%a Exit - %r\n", __func__, Status));
  return Status;
}
