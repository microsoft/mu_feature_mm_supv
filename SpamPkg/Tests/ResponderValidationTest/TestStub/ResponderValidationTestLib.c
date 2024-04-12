/** @file -- PagingAudit.c
This is the driver portion of the MmPagingAuditApp driver.
It copies valid entries from the page tables into the communication buffer.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CpuLib.h>

#include <Protocol/SmmCommunication.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MmPagingAudit.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"
#include "Mem/HeapGuard.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"

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
SmmPagingAuditHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *RegisterContext,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  // EFI_STATUS                          Status = EFI_SUCCESS;
  // SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER  *AuditCommBuffer;
  // UINTN                               StartIndex;
  // UINTN                               Index;
  // UINTN                               CopyCount;

  // DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  // //
  // // If input is invalid, stop processing this SMI
  // //
  // if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
  //   DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad pointers!\n", __FUNCTION__));
  //   return EFI_ACCESS_DENIED;
  // }

  // //
  // // Make sure that the buffer size makes sense for any of the possible calls.
  // //
  // if (*CommBufferSize < sizeof (SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER)) {
  //   DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad size!\n", __FUNCTION__));
  //   return EFI_ACCESS_DENIED;
  // }

  // AuditCommBuffer = CommBuffer;

  // //
  // // Make sure that user-supplied values don't cause math errors.
  // //
  // // This upper limit is somewhat arbitrary, currently capped at MAX_SMI_CALL_COUNT,
  // // in order to prevent overflow on x86 or x64 systems during related multiplications
  // if (AuditCommBuffer->Header.RequestIndex > MAX_SMI_CALL_COUNT) {
  //   DEBUG ((DEBUG_ERROR, "%a - RequestIndex %d > MAX_SMI_CALL_COUNT!\n", __FUNCTION__, AuditCommBuffer->Header.RequestIndex));
  //   return EFI_INVALID_PARAMETER;
  // }

  // DEBUG ((DEBUG_INFO, "%a - RequestIndex %d !\n", __FUNCTION__, AuditCommBuffer->Header.RequestIndex));
  // //
  // // If this call will need cached data, load that now.
  // //
  // if ((AuditCommBuffer->Header.RequestType == SMM_PAGE_AUDIT_TABLE_REQUEST) ||
  //     (AuditCommBuffer->Header.RequestType == SMM_PAGE_AUDIT_PDE_REQUEST))
  // {
  //   if (!mPageTableDataLoaded) {
  //     mPageTableDataLoaded = LoadFlatPageTableData (
  //                              &mPte1GCount,
  //                              &mPte2MCount,
  //                              &mPte4KCount,
  //                              &mPdeCount,
  //                              &mGuardCount,
  //                              &mPte1GEntries,
  //                              &mPte2MEntries,
  //                              &mPte4KEntries,
  //                              &mPdeEntries,
  //                              &mGuardEntries
  //                              );
  //   }

  //   if (!mPageTableDataLoaded) {
  //     DEBUG ((DEBUG_ERROR, "%a - Failed to load page table data!\n", __FUNCTION__));
  //     return EFI_ABORTED;
  //   }
  // }

  // //
  // // Handle requests as they come.
  // //
  // switch (AuditCommBuffer->Header.RequestType) {
  //   case SMM_PAGE_AUDIT_TABLE_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Getting page tables.\n", __FUNCTION__));
  //     // Init defaults.
  //     ZeroMem (&AuditCommBuffer->Data.TableEntry, sizeof (AuditCommBuffer->Data.TableEntry));
  //     // Copy 1G Table Entries.
  //     StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_1G;
  //     if (StartIndex < mPte1GCount) {
  //       CopyCount = MIN ((mPte1GCount - StartIndex), BUFFER_COUNT_1G);
  //       CopyMem (&AuditCommBuffer->Data.TableEntry.Pte1G, &mPte1GEntries[StartIndex], CopyCount * sizeof (PAGE_TABLE_1G_ENTRY));
  //       AuditCommBuffer->Data.TableEntry.Pte1GCount = CopyCount;
  //       // Check for more room.
  //       StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_1G);
  //       if (StartIndex < mPte1GCount) {
  //         AuditCommBuffer->Data.TableEntry.HasMore = TRUE;
  //       }
  //     }

  //     // Copy 2M Table Entries.
  //     StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_2M;
  //     if (StartIndex < mPte2MCount) {
  //       CopyCount = MIN ((mPte2MCount - StartIndex), BUFFER_COUNT_2M);
  //       CopyMem (&AuditCommBuffer->Data.TableEntry.Pte2M, &mPte2MEntries[StartIndex], CopyCount * sizeof (PAGE_TABLE_ENTRY));
  //       AuditCommBuffer->Data.TableEntry.Pte2MCount = CopyCount;
  //       // Check for more room.
  //       StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_2M);
  //       if (StartIndex < mPte2MCount) {
  //         AuditCommBuffer->Data.TableEntry.HasMore = TRUE;
  //       }
  //     }

  //     // Copy 4K Table Entries.
  //     StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_4K;
  //     if (StartIndex < mPte4KCount) {
  //       CopyCount = MIN ((mPte4KCount - StartIndex), BUFFER_COUNT_4K);
  //       CopyMem (&AuditCommBuffer->Data.TableEntry.Pte4K, &mPte4KEntries[StartIndex], CopyCount * sizeof (PAGE_TABLE_4K_ENTRY));
  //       AuditCommBuffer->Data.TableEntry.Pte4KCount = CopyCount;
  //       // Check for more room.
  //       StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_4K);
  //       if (StartIndex < mPte4KCount) {
  //         AuditCommBuffer->Data.TableEntry.HasMore = TRUE;
  //       }
  //     }

  //     break;

  //   case SMM_PAGE_AUDIT_GUARD_PAGE_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Getting guard page entries.\n", __FUNCTION__));
  //     // Init defaults.
  //     ZeroMem (&AuditCommBuffer->Data.GuardPages, sizeof (AuditCommBuffer->Data.GuardPages));
  //     // Copy Guard Page Entries.
  //     StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_GUARD;
  //     if (StartIndex < mGuardCount) {
  //       CopyCount = MIN ((mGuardCount - StartIndex), BUFFER_COUNT_GUARD);
  //       CopyMem (&AuditCommBuffer->Data.GuardPages.GuardPage, &mGuardEntries[StartIndex], CopyCount * sizeof (UINT64));
  //       AuditCommBuffer->Data.GuardPages.GuardPageCount = CopyCount;
  //       // Check for more room.
  //       StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_GUARD);
  //       if (StartIndex < mGuardCount) {
  //         AuditCommBuffer->Data.GuardPages.HasMore = TRUE;
  //       }
  //     }

  //     break;

  //   case SMM_PAGE_AUDIT_PDE_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Getting page directories.\n", __FUNCTION__));
  //     // Init defaults.
  //     ZeroMem (&AuditCommBuffer->Data.PdeEntry, sizeof (AuditCommBuffer->Data.PdeEntry));
  //     // Copy PDE Entries.
  //     StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_PDE;
  //     if (StartIndex < mPdeCount) {
  //       CopyCount = MIN ((mPdeCount - StartIndex), BUFFER_COUNT_PDE);
  //       CopyMem (&AuditCommBuffer->Data.PdeEntry.Pde, &mPdeEntries[StartIndex], CopyCount * sizeof (UINT64));
  //       AuditCommBuffer->Data.PdeEntry.PdeCount = CopyCount;
  //       // Check for more room.
  //       StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_PDE);
  //       if (StartIndex < mPdeCount) {
  //         AuditCommBuffer->Data.PdeEntry.HasMore = TRUE;
  //       }
  //     }

  //     break;

  //   case SMM_PAGE_AUDIT_MISC_DATA_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Getting misc info run #%d\n", __FUNCTION__, AuditCommBuffer->Header.RequestIndex));
  //     BitwidthDumpHandler (&AuditCommBuffer->Data.MiscData);
  //     IdtDumpHandler (&AuditCommBuffer->Data.MiscData);
  //     SmmLoadedImageTableDump (AuditCommBuffer->Header.RequestIndex, &AuditCommBuffer->Data.MiscData);
  //     StackDumpHandler (&AuditCommBuffer->Data.MiscData);
  //     CommBufferDumpHandler (&AuditCommBuffer->Data.MiscData);
  //     break;

  //   case SMM_PAGE_AUDIT_CLEAR_DATA_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Clearing cached data.\n", __FUNCTION__));
  //     // Reset all of the cached data.
  //     FreePool (mPte1GEntries);
  //     mPte1GEntries = NULL;
  //     FreePool (mPte2MEntries);
  //     mPte2MEntries = NULL;
  //     FreePool (mPte4KEntries);
  //     mPte4KEntries = NULL;
  //     FreePool (mPdeEntries);
  //     mPdeEntries = NULL;
  //     FreePool (mGuardEntries);
  //     mGuardEntries        = NULL;
  //     mPte1GCount          = 0;
  //     mPte2MCount          = 0;
  //     mPte4KCount          = 0;
  //     mPdeCount            = 0;
  //     mGuardCount          = 0;
  //     mPageTableDataLoaded = FALSE;
  //     break;

  //   case SMM_PAGE_AUDIT_SMI_ENTRY_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Getting SMI entry information.\n", __FUNCTION__));
  //     // Init defaults.
  //     ZeroMem (&AuditCommBuffer->Data.SmiEntry, sizeof (AuditCommBuffer->Data.SmiEntry));
  //     // Populate the tile size before dispatching per core routine
  //     AuditCommBuffer->Data.SmiEntry.SmiEntrySize     = GetSmiHandlerSize ();
  //     AuditCommBuffer->Data.SmiEntry.SmiEntrySize     = ALIGN_VALUE (AuditCommBuffer->Data.SmiEntry.SmiEntrySize, SIZE_4KB);
  //     AuditCommBuffer->Data.SmiEntry.SmiSaveStateSize =
  //       (SMRAM_SAVE_STATE_MAP_OFFSET - SMM_PSD_OFFSET) + sizeof (SMRAM_SAVE_STATE_MAP);
  //     AuditCommBuffer->Data.SmiEntry.SmiSaveStateSize = ALIGN_VALUE (AuditCommBuffer->Data.SmiEntry.SmiSaveStateSize, SIZE_4KB);
  //     // Copy SMI entry, save state and GDT base addresses.
  //     StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_CORES;
  //     for (Index = 0; Index < BUFFER_COUNT_CORES && Index + StartIndex < mNumberOfCpus; Index++) {
  //       if (Index + StartIndex == gMmCoreMmst.CurrentlyExecutingCpu) {
  //         SmiEntryDumpHandler (&AuditCommBuffer->Data.SmiEntry);
  //       } else {
  //         Status = SmmBlockingStartupThisAp (SmiEntryDumpHandler, Index + StartIndex, &AuditCommBuffer->Data.SmiEntry);
  //         ASSERT_EFI_ERROR (Status);
  //       }
  //     }

  //     AuditCommBuffer->Data.SmiEntry.SmiEntryCount = Index;
  //     if (Index + StartIndex < mNumberOfCpus) {
  //       // We are not done yet.
  //       AuditCommBuffer->Data.SmiEntry.HasMore = TRUE;
  //     }

  //     break;

  //   case SMM_PAGE_AUDIT_UNBLOCKED_REQUEST:
  //     DEBUG ((DEBUG_INFO, "%a - Getting unblocked entries.\n", __FUNCTION__));
  //     // Init defaults.
  //     ZeroMem (&AuditCommBuffer->Data.UnblockedRegion, sizeof (AuditCommBuffer->Data.UnblockedRegion));
  //     // Copy PDE Entries.
  //     StartIndex                                                 = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_UNBLOCK;
  //     CopyCount                                                  = BUFFER_COUNT_UNBLOCK;
  //     Status                                                     = CollectUnblockedRegionsFromNthNode (StartIndex, AuditCommBuffer->Data.UnblockedRegion.UnblockedRegions, &CopyCount);
  //     AuditCommBuffer->Data.UnblockedRegion.UnblockedRegionCount = CopyCount;
  //     if (CopyCount == BUFFER_COUNT_UNBLOCK) {
  //       // It might be due to buffer is full
  //       AuditCommBuffer->Data.UnblockedRegion.HasMore = TRUE;
  //     }

  //     break;

  //   default:
  //     DEBUG ((DEBUG_ERROR, "%a - Unknown request type! 0x%02X\n", __FUNCTION__, AuditCommBuffer->Header.RequestType));
  //     Status = EFI_ACCESS_DENIED;
  //     break;
  // }

  return Status;
}

/**
  Initialize the test agents such as MM handlers to support communication with non MM test entities.

  @retval EFI_SUCCESS           The test agents are successfully initialized.
  @retval Others                Error codes returned from MmiHandlerUnRegister.
**/
EFI_STATUS
EFIAPI
ResponderValidationTestConstructor (
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
               SmmPagingAuditHandler,
               &gMmPagingAuditMmiHandlerGuid,
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
