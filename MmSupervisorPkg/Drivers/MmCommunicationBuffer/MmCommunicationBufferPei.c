/** @file
A function allocates common MM communication buffer in PEI phase.

The allocation operation will be conducted after memory is discovered
and allocated buffer information will be published in HOBs for further
phases to consume.

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
Copyright (c), Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/PeiServicesLib.h>

#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>

EFI_PEI_PPI_DESCRIPTOR  MmCommunicationBuffPpi = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gMmCommunicationBufferReadyPpiGuid,
  NULL
};

/**
  Helper function to allocate reserved buffer for communication buffer based on
  given buffer type and size.

  @param[in]  Type                  Type of communication buffer reserved, currently only
                                    supervisor and user buffer are supported.
  @param[in]  PageSize              Number of pages needs to be allocated for given type.
  @param[out] BufferAddress         Buffer address allocated for given type when operation
                                    returns successfully. Otherwise it will be set to NULL.

  @retval     EFI_SUCCESS           The routine completes successfully.
  @retval     EFI_INVALID_PARAMETER The input type is not supported or page size is invalid.
  @retval     EFI_OUT_OF_RESOURCES  Insufficient resources to create communication buffer.
**/
STATIC
EFI_STATUS
ReserveSupvCommBuffer (
  IN  UINT64                PageSize,
  OUT EFI_PHYSICAL_ADDRESS  *BufferAddress  OPTIONAL
  )
{
  EFI_STATUS          Status;
  MM_COMM_REGION_HOB  *CommRegionHob;

  if (PageSize == 0) {
    DEBUG ((DEBUG_ERROR, "%a Invalid input PageSize 0x%x!\n", __FUNCTION__, PageSize));
    ASSERT (FALSE);
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (BufferAddress != NULL) {
    *BufferAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)NULL;
  }

  CommRegionHob = BuildGuidHob (&gMmCommonRegionHobGuid, sizeof (MM_COMM_REGION_HOB));
  if (CommRegionHob == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to create GUIDed HOB %g!\n", __FUNCTION__, &gMmCommonRegionHobGuid));
    ASSERT (FALSE);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  ZeroMem (CommRegionHob, sizeof (MM_COMM_REGION_HOB));
  CommRegionHob->MmCommonRegionType = MM_SUPERVISOR_BUFFER_T;

  //
  // Allocate and fill CommRegionHob
  //
  CommRegionHob->MmCommonRegionAddr = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocatePages ((UINTN)PageSize);
  if (NULL == (VOID *)(UINTN)CommRegionHob->MmCommonRegionAddr) {
    DEBUG ((DEBUG_ERROR, "%a Request of allocating common buffer of 0x%x pages failed!\n", __FUNCTION__, PageSize));
    ASSERT (FALSE);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  CommRegionHob->MmCommonRegionPages = PageSize;

  DEBUG ((DEBUG_INFO, "Reserved MM common buffer type 0x%x\n", CommRegionHob->MmCommonRegionType));
  DEBUG ((DEBUG_INFO, "  PhysicalStart   - 0x%lx\n", CommRegionHob->MmCommonRegionAddr));
  DEBUG ((DEBUG_INFO, "  NumberOfPages   - 0x%lx\n", CommRegionHob->MmCommonRegionPages));

  if (BufferAddress != NULL) {
    *BufferAddress = CommRegionHob->MmCommonRegionAddr;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  Helper function to allocate reserved buffer for communication buffer based on
  given buffer type and size.

  @param[in]  PageSize              Number of pages needs to be allocated for given type.
  @param[out] BufferAddress         Buffer address allocated for given type when operation
                                    returns successfully. Otherwise it will be set to NULL.

  @retval     EFI_SUCCESS           The routine completes successfully.
  @retval     EFI_INVALID_PARAMETER The input type is not supported or page size is invalid.
  @retval     EFI_OUT_OF_RESOURCES  Insufficient resources to create communication buffer.
**/
STATIC
EFI_STATUS
ReserveUserCommBuffer (
  IN  UINT64                PageSize,
  OUT EFI_PHYSICAL_ADDRESS  *BufferAddress  OPTIONAL
  )
{
  EFI_STATUS             Status;
  MM_COMM_BUFFER         *CommRegionHob;
  MM_COMM_BUFFER_STATUS  *CommRegionStatus;

  if (PageSize == 0) {
    DEBUG ((DEBUG_ERROR, "%a Invalid input PageSize 0x%x!\n", __FUNCTION__, PageSize));
    ASSERT (FALSE);
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (BufferAddress != NULL) {
    *BufferAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)NULL;
  }

  CommRegionHob = BuildGuidHob (&gMmCommBufferHobGuid, sizeof (MM_COMM_BUFFER));
  if (CommRegionHob == NULL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to create GUIDed HOB %g!\n", __FUNCTION__, &gMmCommBufferHobGuid));
    ASSERT (FALSE);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  ZeroMem (CommRegionHob, sizeof (MM_COMM_BUFFER));

  //
  // Allocate and fill CommRegionHob
  //
  CommRegionHob->PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocatePages ((UINTN)PageSize);
  if (NULL == (VOID *)(UINTN)CommRegionHob->PhysicalStart) {
    DEBUG ((DEBUG_ERROR, "%a Request of allocating common buffer of 0x%x pages failed!\n", __FUNCTION__, PageSize));
    ASSERT (FALSE);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  CommRegionHob->NumberOfPages = PageSize;

  CommRegionStatus = (MM_COMM_BUFFER_STATUS *)(UINTN)AllocatePages (EFI_SIZE_TO_PAGES (sizeof (MM_COMM_BUFFER_STATUS)));
  if (NULL == (VOID *)CommRegionStatus) {
    DEBUG ((DEBUG_ERROR, "%a Request of allocating common buffer status failed!\n", __FUNCTION__));
    ASSERT (FALSE);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  ZeroMem (CommRegionStatus, sizeof (MM_COMM_BUFFER_STATUS));
  CommRegionHob->Status = (EFI_PHYSICAL_ADDRESS)(UINTN)CommRegionStatus;

  DEBUG ((DEBUG_INFO, "Reserved MM common buffer for user\n"));
  DEBUG ((DEBUG_INFO, "  PhysicalStart   - 0x%lx\n", CommRegionHob->PhysicalStart));
  DEBUG ((DEBUG_INFO, "  NumberOfPages   - 0x%lx\n", CommRegionHob->NumberOfPages));

  if (BufferAddress != NULL) {
    *BufferAddress = CommRegionHob->PhysicalStart;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  Entry point of MM communication buffer initialization module in PEI phase.

  This module will allocate buffer for MM communication and create hobs with
  allocated information.

  @param[in]  FileHandle           Not used.
  @param[in]  PeiServices          General purpose services available to every PEIM.

  @retval     EFI_SUCCESS          The function completes successfully
  @retval     EFI_OUT_OF_RESOURCES Insufficient resources to create database
**/
EFI_STATUS
EFIAPI
MmCommunicationBufferPeiEntry (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  SupvBufferAddr;
  EFI_PHYSICAL_ADDRESS  UserBufferAddr;

  Status = ReserveSupvCommBuffer (PcdGet64 (PcdSupervisorCommBufferPages), &SupvBufferAddr);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to reserve communicate buffer for supervisor - %r!\n", __FUNCTION__, Status));
    goto Done;
  }

  Status = ReserveUserCommBuffer (PcdGet64 (PcdUserCommBufferPages), &UserBufferAddr);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to reserve communicate buffer for user - %r!\n", __FUNCTION__, Status));
    goto Done;
  }

  //
  // Notify others that the communication buffer is ready to go
  //
  Status = PeiServicesInstallPpi (&MmCommunicationBuffPpi);
  ASSERT_EFI_ERROR (Status);

Done:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to initialize communication buffers - %r!\n", __FUNCTION__, Status));
    if (NULL != (VOID *)(UINTN)SupvBufferAddr) {
      // Clean supervisor legacy if any
      FreePages ((VOID *)(UINTN)SupvBufferAddr, (UINTN)PcdGet64 (PcdSupervisorCommBufferPages));
    }

    if (NULL != (VOID *)(UINTN)UserBufferAddr) {
      // Clean user legacy if any
      FreePages ((VOID *)(UINTN)UserBufferAddr, (UINTN)PcdGet64 (PcdUserCommBufferPages));
    }
  }

  return Status;
}
