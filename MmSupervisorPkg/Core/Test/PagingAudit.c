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
#include <Library/UefiCpuLib.h>

#include <Protocol/SmmCommunication.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/MmSupervisorRequestData.h>
#include <Guid/MmPagingAudit.h>

#include "MmSupervisorCore.h"
#include "Mem/Mem.h"
#include "Mem/HeapGuard.h"
#include "Relocate/Relocate.h"
#include "Services/MpService/MpService.h"

#define IndexToAddress(a, b, c, d)  ((UINT64) (a << 39) + (b << 30) + (c <<  21) + (d << 12))

#define MAX_SMI_CALL_COUNT  1000

// Data that should persist from call to call.
// This data has to be broken up so that it can fit within the
// shared Comm Buffer.
GLOBAL_REMOVE_IF_UNREFERENCED STATIC BOOLEAN              mPageTableDataLoaded = FALSE;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINTN                mPte1GCount          = 0;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINTN                mPte2MCount          = 0;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINTN                mPte4KCount          = 0;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINTN                mPdeCount            = 0;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINTN                mGuardCount          = 0;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC PAGE_TABLE_1G_ENTRY  *mPte1GEntries       = NULL;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC PAGE_TABLE_ENTRY     *mPte2MEntries       = NULL;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC PAGE_TABLE_4K_ENTRY  *mPte4KEntries       = NULL;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINT64               *mPdeEntries         = NULL;
GLOBAL_REMOVE_IF_UNREFERENCED STATIC UINT64               *mGuardEntries       = NULL;

EFI_STATUS
EFIAPI
CollectUnblockedRegionsFromNthNode (
  IN      UINTN                                StartIndex,
  OUT     MM_SUPERVISOR_UNBLOCK_MEMORY_PARAMS  *Buffer,
  IN OUT  UINTN                                *BufferCount
  );

/**
 * @brief      Locates loaded image table and copies the image information into the comm buffer.
 *
 * @param      RequestIndex The index of current MM request. The stepping of each request is
 *                          defined by BUFFER_COUNT_IMAGES.
 * @param      CommBuffer   Images will be copied here for use in the app.
 *
 * @return     EFI_SUCCESS or error from SmmLocateHandle
 */
EFI_STATUS
EFIAPI
SmmLoadedImageTableDump (
  IN  UINTN                                 RequestIndex,
  OUT SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *CommBuffer
  )
{
  EFI_STATUS                 Status;
  UINTN                      HandleBufferSize;
  UINTN                      HandleBufferCount;
  EFI_HANDLE                 *HandleBuffer;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  UINTN                      SourceIndex;
  UINTN                      DestinationIndex;
  CHAR8                      *ImageName;

  //
  // First, need to get a buffer of all the handles for loaded images.
  //
  HandleBufferSize = 0;
  HandleBuffer     = NULL;
  Status           = gMmst->MmLocateHandle (
                              ByProtocol,
                              &gEfiLoadedImageProtocolGuid,
                              NULL,
                              &HandleBufferSize,
                              HandleBuffer
                              );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_ABORTED;
  }

  // Now that we have the size, allocate memory.
  HandleBuffer = AllocateZeroPool (HandleBufferSize);
  if (HandleBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufferSize,
                    HandleBuffer
                    );
  if (EFI_ERROR (Status)) {
    FreePool (HandleBuffer);
    return Status;
  }

  //
  // Initialize return values.
  //
  CommBuffer->SmmImageCount = 0;
  CommBuffer->HasMore       = FALSE;
  ZeroMem (&CommBuffer->SmmImage, sizeof (CommBuffer->SmmImage));

  //
  // Based on the number of handles returned, determine whether we need to fetch anything else.
  //
  HandleBufferCount = HandleBufferSize / sizeof (EFI_HANDLE);

  // RequestIndex is capped at MAX_SMI_CALL_COUNT in the root handler,
  // Multiplication overflow should not occur on x86 or x64 systems
  SourceIndex = RequestIndex * BUFFER_COUNT_IMAGES;
  if (SourceIndex < HandleBufferCount) {
    for (DestinationIndex = 0;
         SourceIndex < HandleBufferCount && DestinationIndex < BUFFER_COUNT_IMAGES;
         SourceIndex++, DestinationIndex++)
    {
      Status = gMmst->MmHandleProtocol (
                        HandleBuffer[SourceIndex],
                        &gEfiLoadedImageProtocolGuid,
                        (VOID **)&LoadedImage
                        );
      // If this failed, keep trying to copy things.
      if (EFI_ERROR (Status)) {
        continue;
      }

      CommBuffer->SmmImage[DestinationIndex].ImageBase = (UINT64)LoadedImage->ImageBase;
      CommBuffer->SmmImage[DestinationIndex].ImageSize = (UINT64)LoadedImage->ImageSize;

      ImageName = PeCoffLoaderGetPdbPointer (LoadedImage->ImageBase);
      AsciiStrnCpyS (
        &CommBuffer->SmmImage[DestinationIndex].ImageName[0],
        MAX_IMAGE_NAME_SIZE,
        ImageName,
        MAX_IMAGE_NAME_SIZE-1
        );
      Status = FindFileNameFromDiscoveredList (
                 (EFI_PHYSICAL_ADDRESS)(UINTN)LoadedImage->ImageBase,
                 &CommBuffer->SmmImage[DestinationIndex].ImageGuid
                 );
      // Only handle error with ASSERT here as this code should only be built with ASSERT turned on.
      ASSERT_EFI_ERROR (Status);
    }

    // Update the return count and HasMore.
    CommBuffer->SmmImageCount = DestinationIndex;
    CommBuffer->HasMore       = (SourceIndex < HandleBufferCount);
  }

  // Always put away your toys.
  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }

  return EFI_SUCCESS;
}

/**
 * @brief      Copies IDTR into the comm buffer.
 *
 * @param      CommBuffer  The communications buffer.
 */
VOID
EFIAPI
IdtDumpHandler (
  OUT SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *CommBuffer
  )
{
  IA32_DESCRIPTOR  Idtr;

  AsmReadIdtr (&Idtr);

  CommBuffer->Idtr = Idtr;
}

/**
 * @brief      Copies IDTR into the comm buffer.
 *
 * @param      CommBuffer  The communications buffer.
 */
VOID
EFIAPI
BitwidthDumpHandler (
  OUT SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *CommBuffer
  )
{
  CommBuffer->MaxAddessBitwidth = mPhysicalAddressBits;
}

/**
 * @brief      Copies stack pointers into the comm buffer
 *
 * @param      CommBuffer  The communications buffer
 */
VOID
StackDumpHandler (
  OUT SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *CommBuffer
  )
{
  CommBuffer->SupvStackBaseAddr = mSmmStackArrayBase;
  CommBuffer->SupvStackSize     = mSmmStackArrayEnd - mSmmStackArrayBase + 1;
  CommBuffer->UserStackBaseAddr = mSmmCpl3StackArrayBase;
  CommBuffer->UserStackSize     = mSmmCpl3StackArrayEnd - mSmmCpl3StackArrayBase + 1;
}

/**
 * @brief      Copies communication buffer region into the comm buffer
 *
 * @param      CommBuffer  The communications buffer
 */
VOID
CommBufferDumpHandler (
  OUT SMM_PAGE_AUDIT_MISC_DATA_COMM_BUFFER  *CommBuffer
  )
{
  CommBuffer->SupvCommBufferBase = mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].PhysicalStart;
  CommBuffer->SupvCommBufferSize = EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].NumberOfPages);
  CommBuffer->UserCommBufferBase = mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].PhysicalStart;
  CommBuffer->UserCommBufferSize = EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages);
}

/**
 * @brief      Copies communication buffer region into the comm buffer
 *
 * @param      CommBuffer  The communications buffer
 */
VOID
EFIAPI
SmiEntryDumpHandler (
  IN OUT VOID  *ProcedureArgument
  )
{
  UINTN                                 CpuIndex;
  UINTN                                 DataIndex;
  EFI_STATUS                            Status;
  SMM_PAGE_AUDIT_SMI_ENTRY_COMM_BUFFER  *CommBuffer = ProcedureArgument;

  // Get current CPU index
  Status = SmmWhoAmI (NULL, &CpuIndex);
  ASSERT_EFI_ERROR (Status);

  DataIndex = CpuIndex % BUFFER_COUNT_CORES;

  // Populate the index here
  if (StandardSignatureIsAuthenticAMD ()) {
    CommBuffer->SmiEntryBase[DataIndex] = AsmReadMsr64 (AMD_64_SMM_BASE) + SMM_HANDLER_OFFSET;
  } else {
    CommBuffer->SmiEntryBase[DataIndex] = AsmReadMsr64 (MSR_IA32_SMBASE) + SMM_HANDLER_OFFSET;
  }

  CommBuffer->SmiSaveStateBase[DataIndex] = CommBuffer->SmiEntryBase[DataIndex] + CommBuffer->SmiEntrySize;

  AsmReadGdtr (&CommBuffer->Gdtr[DataIndex]);
}

/**
  This helper function walks the page tables to retrieve:
  - a count of each entry
  - a count of each directory entry
  - [optional] a flat list of each entry
  - [optional] a flat list of each directory entry

  @param[in, out]   Pte1GCount, Pte2MCount, Pte4KCount, PdeCount
      On input, the number of entries that can fit in the corresponding buffer (if provided).
      It is expected that this will be zero if the corresponding buffer is NULL.
      On output, the number of entries that were encountered in the page table.
  @param[out]       Pte1GEntries, Pte2MEntries, Pte4KEntries, PdeEntries
      A buffer which will be filled with the entries that are encountered in the tables.

  @retval     EFI_SUCCESS             All requested data has been returned.
  @retval     EFI_INVALID_PARAMETER   One or more of the count parameter pointers is NULL.
  @retval     EFI_INVALID_PARAMETER   Presence of buffer counts and pointers is incongruent.
  @retval     EFI_BUFFER_TOO_SMALL    One or more of the buffers was insufficient to hold
                                      all of the entries in the page tables. The counts
                                      have been updated with the total number of entries
                                      encountered.

**/
STATIC
EFI_STATUS
GetFlatPageTableData (
  IN OUT UINTN             *Pte1GCount,
  IN OUT UINTN             *Pte2MCount,
  IN OUT UINTN             *Pte4KCount,
  IN OUT UINTN             *PdeCount,
  IN OUT UINTN             *GuardCount,
  OUT PAGE_TABLE_1G_ENTRY  *Pte1GEntries,
  OUT PAGE_TABLE_ENTRY     *Pte2MEntries,
  OUT PAGE_TABLE_4K_ENTRY  *Pte4KEntries,
  OUT UINT64               *PdeEntries,
  OUT UINT64               *GuardEntries
  )
{
  EFI_STATUS                      Status = EFI_SUCCESS;
  PAGE_MAP_AND_DIRECTORY_POINTER  *Work;
  PAGE_MAP_AND_DIRECTORY_POINTER  *Pml4;
  PAGE_TABLE_1G_ENTRY             *Pte1G;
  PAGE_TABLE_ENTRY                *Pte2M;
  PAGE_TABLE_4K_ENTRY             *Pte4K;
  UINTN                           Index1;
  UINTN                           Index2;
  UINTN                           Index3;
  UINTN                           Index4;
  UINTN                           MyGuardCount        = 0;
  UINTN                           MyPdeCount          = 0;
  UINTN                           My4KCount           = 0;
  UINTN                           My2MCount           = 0;
  UINTN                           My1GCount           = 0;
  UINTN                           NumPage4KNotPresent = 0;
  UINTN                           NumPage2MNotPresent = 0;
  UINTN                           NumPage1GNotPresent = 0;
  UINT64                          Address;

  //
  // First, fail fast if some of the parameters don't look right.
  //
  // ALL count parameters should be provided.
  if ((Pte1GCount == NULL) || (Pte2MCount == NULL) || (Pte4KCount == NULL) || (PdeCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // If a count is greater than 0, the corresponding buffer pointer MUST be provided.
  // It will be assumed that all buffers have space for any corresponding count.
  if (((*Pte1GCount > 0) && (Pte1GEntries == NULL)) || ((*Pte2MCount > 0) && (Pte2MEntries == NULL)) ||
      ((*Pte4KCount > 0) && (Pte4KEntries == NULL)) || ((*PdeCount > 0) && (PdeEntries == NULL)))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Alright, let's get to work.
  //
  Pml4 = (PAGE_MAP_AND_DIRECTORY_POINTER *)AsmReadCr3 ();
  // Increase the count.
  // If we have room for more PDE Entries, add one.
  MyPdeCount++;
  if (MyPdeCount <= *PdeCount) {
    PdeEntries[MyPdeCount-1] = (UINT64)Pml4;
  }

  for (Index4 = 0x0; Index4 < 0x200; Index4++) {
    if (!Pml4[Index4].Bits.Present) {
      continue;
    }

    Pte1G = (PAGE_TABLE_1G_ENTRY *)(UINTN)(Pml4[Index4].Bits.PageTableBaseAddress << 12);
    // Increase the count.
    // If we have room for more PDE Entries, add one.
    MyPdeCount++;
    if (MyPdeCount <= *PdeCount) {
      PdeEntries[MyPdeCount-1] = (UINT64)Pte1G;
    }

    for (Index3 = 0x0; Index3 < 0x200; Index3++ ) {
      if (!Pte1G[Index3].Bits.Present) {
        NumPage1GNotPresent++;
        continue;
      }

      //
      // MustBe1 is the bit that indicates whether the pointer is a directory
      // pointer or a page table entry.
      //
      if (!(Pte1G[Index3].Bits.MustBe1)) {
        //
        // We have to cast 1G and 2M directories to this to
        // get all of their address bits.
        //
        Work  = (PAGE_MAP_AND_DIRECTORY_POINTER *)Pte1G;
        Pte2M = (PAGE_TABLE_ENTRY *)(UINTN)(Work[Index3].Bits.PageTableBaseAddress << 12);
        // Increase the count.
        // If we have room for more PDE Entries, add one.
        MyPdeCount++;
        if (MyPdeCount <= *PdeCount) {
          PdeEntries[MyPdeCount-1] = (UINT64)Pte2M;
        }

        for (Index2 = 0x0; Index2 < 0x200; Index2++ ) {
          if (!Pte2M[Index2].Bits.Present) {
            NumPage2MNotPresent++;
            continue;
          }

          if (!(Pte2M[Index2].Bits.MustBe1)) {
            Work  = (PAGE_MAP_AND_DIRECTORY_POINTER *)Pte2M;
            Pte4K = (PAGE_TABLE_4K_ENTRY *)(UINTN)(Work[Index2].Bits.PageTableBaseAddress << 12);
            // Increase the count.
            // If we have room for more PDE Entries, add one.
            MyPdeCount++;
            if (MyPdeCount <= *PdeCount) {
              PdeEntries[MyPdeCount-1] = (UINT64)Pte4K;
            }

            for (Index1 = 0x0; Index1 < 0x200; Index1++ ) {
              if (!Pte4K[Index1].Bits.Present) {
                NumPage4KNotPresent++;
                Address = IndexToAddress (Index4, Index3, Index2, Index1);
                if (IsGuardPage (Address)) {
                  MyGuardCount++;
                  if (MyGuardCount <= *GuardCount) {
                    GuardEntries[MyGuardCount - 1] = Address;
                  }
                }

                continue;
              }

              // Increase the count.
              // If we have room for more Page Table entries, add one.
              My4KCount++;
              if (My4KCount <= *Pte4KCount) {
                Pte4KEntries[My4KCount-1] = Pte4K[Index1];
              }
            }
          } else {
            // Increase the count.
            // If we have room for more Page Table entries, add one.
            My2MCount++;
            if (My2MCount <= *Pte2MCount) {
              Pte2MEntries[My2MCount-1] = Pte2M[Index2];
            }
          }
        }
      } else {
        // Increase the count.
        // If we have room for more Page Table entries, add one.
        My1GCount++;
        if (My1GCount <= *Pte1GCount) {
          Pte1GEntries[My1GCount-1] = Pte1G[Index3];
        }
      }
    }
  }

  DEBUG ((DEBUG_INFO, "Pages used for Page Tables   = %d\n", MyPdeCount));
  DEBUG ((DEBUG_INFO, "Number of   4K Pages active  = %d - NotPresent = %d\n", My4KCount, NumPage4KNotPresent));
  DEBUG ((DEBUG_INFO, "Number of   2M Pages active  = %d - NotPresent = %d\n", My2MCount, NumPage2MNotPresent));
  DEBUG ((DEBUG_INFO, "Number of   1G Pages active  = %d - NotPresent = %d\n", My1GCount, NumPage1GNotPresent));
  DEBUG ((DEBUG_INFO, "Number of   Guard Pages active  = %d\n", MyGuardCount));

  //
  // determine whether any of the buffers were too small.
  // Only matters if a given buffer was provided.
  //
  if (((Pte1GEntries != NULL) && (*Pte1GCount < My1GCount)) || ((Pte2MEntries != NULL) && (*Pte2MCount < My2MCount)) ||
      ((Pte4KEntries != NULL) && (*Pte4KCount < My4KCount)) || ((PdeEntries != NULL) && (*PdeCount < MyPdeCount)) ||
      ((GuardEntries != NULL) && (*GuardCount < MyGuardCount)))
  {
    Status = EFI_BUFFER_TOO_SMALL;
  }

  //
  // Update all the return pointers.
  //
  *Pte1GCount = My1GCount;
  *Pte2MCount = My2MCount;
  *Pte4KCount = My4KCount;
  *PdeCount   = MyPdeCount;
  *GuardCount = MyGuardCount;

  return Status;
} // GetFlatPageTableData()

/**
  This is a helper function that wraps GetFlatPageTableData(),
  and abstracts the call->allocate->call pattern.

  @params are virtually identical to GetFlatPageTableData() except:
    - all params are OUTs
    - Entries are pointer-pointers to handle buffer allocation

  @retval   TRUE    Data is loaded.
  @retval   FALSE   Data could not be loaded, all buffers are deallocated.

**/
STATIC
BOOLEAN
LoadFlatPageTableData (
  OUT UINTN                *Pte1GCount,
  OUT UINTN                *Pte2MCount,
  OUT UINTN                *Pte4KCount,
  OUT UINTN                *PdeCount,
  OUT UINTN                *GuardCount,
  OUT PAGE_TABLE_1G_ENTRY  **Pte1GEntries,
  OUT PAGE_TABLE_ENTRY     **Pte2MEntries,
  OUT PAGE_TABLE_4K_ENTRY  **Pte4KEntries,
  OUT UINT64               **PdeEntries,
  OUT UINT64               **GuardEntries
  )
{
  EFI_STATUS  Status;

  // Run once to get counts.
  DEBUG ((DEBUG_INFO, "%a - First call to determine required buffer sizes.\n", __FUNCTION__));
  *Pte1GCount = 0;
  *Pte2MCount = 0;
  *Pte4KCount = 0;
  *PdeCount   = 0;
  Status      = GetFlatPageTableData (Pte1GCount, Pte2MCount, Pte4KCount, PdeCount, GuardCount, NULL, NULL, NULL, NULL, NULL);

  // In the case of the allocation code blow could alter page tables, preemptively added some entries to
  // account for potential broken up 2M pages
  *Pte4KCount = *Pte4KCount + 0x200;
  *PdeCount   = *PdeCount + 1;
  // Also compensate for guard page from allocations below
  *GuardCount = *GuardCount + 0x10;

  // Allocate buffers if successful.
  if (!EFI_ERROR (Status)) {
    *Pte1GEntries = AllocateZeroPool (*Pte1GCount * sizeof (PAGE_TABLE_1G_ENTRY));
    *Pte2MEntries = AllocateZeroPool (*Pte2MCount * sizeof (PAGE_TABLE_ENTRY));
    *Pte4KEntries = AllocateZeroPool (*Pte4KCount * sizeof (PAGE_TABLE_4K_ENTRY));
    *PdeEntries   = AllocateZeroPool (*PdeCount * sizeof (UINT64));
    *GuardEntries = AllocateZeroPool (*GuardCount * sizeof (UINT64));

    // Check for errors.
    if ((*Pte1GEntries == NULL) || (*Pte2MEntries == NULL) || (*Pte4KEntries == NULL) || (*PdeEntries == NULL) || (*GuardEntries == NULL)) {
      DEBUG ((DEBUG_ERROR, "%a - Ran out of resource during allocation.\n", __FUNCTION__));
      Status = EFI_OUT_OF_RESOURCES;
    }
  } else {
    DEBUG ((DEBUG_ERROR, "%a - Get page table data failed - %r.\n", __FUNCTION__, Status));
  }

  // If still good, grab the data.
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a - Second call to grab the data.\n", __FUNCTION__));
    Status = GetFlatPageTableData (
               Pte1GCount,
               Pte2MCount,
               Pte4KCount,
               PdeCount,
               GuardCount,
               *Pte1GEntries,
               *Pte2MEntries,
               *Pte4KEntries,
               *PdeEntries,
               *GuardEntries
               );
  }

  // If an error occurred, bail and free.
  if (EFI_ERROR (Status)) {
    if (*Pte1GEntries != NULL) {
      FreePool (*Pte1GEntries);
      *Pte1GEntries = NULL;
    }

    if (*Pte2MEntries != NULL) {
      FreePool (*Pte2MEntries);
      *Pte2MEntries = NULL;
    }

    if (*Pte4KEntries != NULL) {
      FreePool (*Pte4KEntries);
      *Pte4KEntries = NULL;
    }

    if (*PdeEntries != NULL) {
      FreePool (*PdeEntries);
      *PdeEntries = NULL;
    }

    if (*GuardEntries != NULL) {
      FreePool (*GuardEntries);
      *GuardEntries = NULL;
    }

    *Pte1GCount = 0;
    *Pte2MCount = 0;
    *Pte4KCount = 0;
    *PdeCount   = 0;
    *GuardCount = 0;
  }

  return !EFI_ERROR (Status);
} // LoadFlatPageTableData()

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
  EFI_STATUS                          Status = EFI_SUCCESS;
  SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER  *AuditCommBuffer;
  UINTN                               StartIndex;
  UINTN                               Index;
  UINTN                               CopyCount;

  DEBUG ((DEBUG_INFO, "%a()\n", __FUNCTION__));

  //
  // If input is invalid, stop processing this SMI
  //
  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad pointers!\n", __FUNCTION__));
    return EFI_ACCESS_DENIED;
  }

  //
  // Make sure that the buffer size makes sense for any of the possible calls.
  //
  if (*CommBufferSize < sizeof (SMM_PAGE_AUDIT_UNIFIED_COMM_BUFFER)) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid comm buffer! Bad size!\n", __FUNCTION__));
    return EFI_ACCESS_DENIED;
  }

  AuditCommBuffer = CommBuffer;

  //
  // Make sure that user-supplied values don't cause math errors.
  //
  // This upper limit is somewhat arbitrary, currently capped at MAX_SMI_CALL_COUNT,
  // in order to prevent overflow on x86 or x64 systems during related multiplications
  if (AuditCommBuffer->Header.RequestIndex > MAX_SMI_CALL_COUNT) {
    DEBUG ((DEBUG_ERROR, "%a - RequestIndex %d > MAX_SMI_CALL_COUNT!\n", __FUNCTION__, AuditCommBuffer->Header.RequestIndex));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_INFO, "%a - RequestIndex %d !\n", __FUNCTION__, AuditCommBuffer->Header.RequestIndex));
  //
  // If this call will need cached data, load that now.
  //
  if ((AuditCommBuffer->Header.RequestType == SMM_PAGE_AUDIT_TABLE_REQUEST) ||
      (AuditCommBuffer->Header.RequestType == SMM_PAGE_AUDIT_PDE_REQUEST))
  {
    if (!mPageTableDataLoaded) {
      mPageTableDataLoaded = LoadFlatPageTableData (
                               &mPte1GCount,
                               &mPte2MCount,
                               &mPte4KCount,
                               &mPdeCount,
                               &mGuardCount,
                               &mPte1GEntries,
                               &mPte2MEntries,
                               &mPte4KEntries,
                               &mPdeEntries,
                               &mGuardEntries
                               );
    }

    if (!mPageTableDataLoaded) {
      DEBUG ((DEBUG_ERROR, "%a - Failed to load page table data!\n", __FUNCTION__));
      return EFI_ABORTED;
    }
  }

  //
  // Handle requests as they come.
  //
  switch (AuditCommBuffer->Header.RequestType) {
    case SMM_PAGE_AUDIT_TABLE_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Getting page tables.\n", __FUNCTION__));
      // Init defaults.
      ZeroMem (&AuditCommBuffer->Data.TableEntry, sizeof (AuditCommBuffer->Data.TableEntry));
      // Copy 1G Table Entries.
      StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_1G;
      if (StartIndex < mPte1GCount) {
        CopyCount = MIN ((mPte1GCount - StartIndex), BUFFER_COUNT_1G);
        CopyMem (&AuditCommBuffer->Data.TableEntry.Pte1G, &mPte1GEntries[StartIndex], CopyCount * sizeof (PAGE_TABLE_1G_ENTRY));
        AuditCommBuffer->Data.TableEntry.Pte1GCount = CopyCount;
        // Check for more room.
        StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_1G);
        if (StartIndex < mPte1GCount) {
          AuditCommBuffer->Data.TableEntry.HasMore = TRUE;
        }
      }

      // Copy 2M Table Entries.
      StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_2M;
      if (StartIndex < mPte2MCount) {
        CopyCount = MIN ((mPte2MCount - StartIndex), BUFFER_COUNT_2M);
        CopyMem (&AuditCommBuffer->Data.TableEntry.Pte2M, &mPte2MEntries[StartIndex], CopyCount * sizeof (PAGE_TABLE_ENTRY));
        AuditCommBuffer->Data.TableEntry.Pte2MCount = CopyCount;
        // Check for more room.
        StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_2M);
        if (StartIndex < mPte2MCount) {
          AuditCommBuffer->Data.TableEntry.HasMore = TRUE;
        }
      }

      // Copy 4K Table Entries.
      StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_4K;
      if (StartIndex < mPte4KCount) {
        CopyCount = MIN ((mPte4KCount - StartIndex), BUFFER_COUNT_4K);
        CopyMem (&AuditCommBuffer->Data.TableEntry.Pte4K, &mPte4KEntries[StartIndex], CopyCount * sizeof (PAGE_TABLE_4K_ENTRY));
        AuditCommBuffer->Data.TableEntry.Pte4KCount = CopyCount;
        // Check for more room.
        StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_4K);
        if (StartIndex < mPte4KCount) {
          AuditCommBuffer->Data.TableEntry.HasMore = TRUE;
        }
      }

      break;

    case SMM_PAGE_AUDIT_GUARD_PAGE_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Getting guard page entries.\n", __FUNCTION__));
      // Init defaults.
      ZeroMem (&AuditCommBuffer->Data.GuardPages, sizeof (AuditCommBuffer->Data.GuardPages));
      // Copy Guard Page Entries.
      StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_GUARD;
      if (StartIndex < mGuardCount) {
        CopyCount = MIN ((mGuardCount - StartIndex), BUFFER_COUNT_GUARD);
        CopyMem (&AuditCommBuffer->Data.GuardPages.GuardPage, &mGuardEntries[StartIndex], CopyCount * sizeof (UINT64));
        AuditCommBuffer->Data.GuardPages.GuardPageCount = CopyCount;
        // Check for more room.
        StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_GUARD);
        if (StartIndex < mGuardCount) {
          AuditCommBuffer->Data.GuardPages.HasMore = TRUE;
        }
      }

      break;

    case SMM_PAGE_AUDIT_PDE_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Getting page directories.\n", __FUNCTION__));
      // Init defaults.
      ZeroMem (&AuditCommBuffer->Data.PdeEntry, sizeof (AuditCommBuffer->Data.PdeEntry));
      // Copy PDE Entries.
      StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_PDE;
      if (StartIndex < mPdeCount) {
        CopyCount = MIN ((mPdeCount - StartIndex), BUFFER_COUNT_PDE);
        CopyMem (&AuditCommBuffer->Data.PdeEntry.Pde, &mPdeEntries[StartIndex], CopyCount * sizeof (UINT64));
        AuditCommBuffer->Data.PdeEntry.PdeCount = CopyCount;
        // Check for more room.
        StartIndex = ((AuditCommBuffer->Header.RequestIndex + 1) * BUFFER_COUNT_PDE);
        if (StartIndex < mPdeCount) {
          AuditCommBuffer->Data.PdeEntry.HasMore = TRUE;
        }
      }

      break;

    case SMM_PAGE_AUDIT_MISC_DATA_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Getting misc info run #%d\n", __FUNCTION__, AuditCommBuffer->Header.RequestIndex));
      BitwidthDumpHandler (&AuditCommBuffer->Data.MiscData);
      IdtDumpHandler (&AuditCommBuffer->Data.MiscData);
      SmmLoadedImageTableDump (AuditCommBuffer->Header.RequestIndex, &AuditCommBuffer->Data.MiscData);
      StackDumpHandler (&AuditCommBuffer->Data.MiscData);
      CommBufferDumpHandler (&AuditCommBuffer->Data.MiscData);
      break;

    case SMM_PAGE_AUDIT_CLEAR_DATA_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Clearing cached data.\n", __FUNCTION__));
      // Reset all of the cached data.
      FreePool (mPte1GEntries);
      mPte1GEntries = NULL;
      FreePool (mPte2MEntries);
      mPte2MEntries = NULL;
      FreePool (mPte4KEntries);
      mPte4KEntries = NULL;
      FreePool (mPdeEntries);
      mPdeEntries = NULL;
      FreePool (mGuardEntries);
      mGuardEntries        = NULL;
      mPte1GCount          = 0;
      mPte2MCount          = 0;
      mPte4KCount          = 0;
      mPdeCount            = 0;
      mGuardCount          = 0;
      mPageTableDataLoaded = FALSE;
      break;

    case SMM_PAGE_AUDIT_SMI_ENTRY_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Getting SMI entry information.\n", __FUNCTION__));
      // Init defaults.
      ZeroMem (&AuditCommBuffer->Data.SmiEntry, sizeof (AuditCommBuffer->Data.SmiEntry));
      // Populate the tile size before dispatching per core routine
      AuditCommBuffer->Data.SmiEntry.SmiEntrySize     = GetSmiHandlerSize ();
      AuditCommBuffer->Data.SmiEntry.SmiEntrySize     = ALIGN_VALUE (AuditCommBuffer->Data.SmiEntry.SmiEntrySize, SIZE_4KB);
      AuditCommBuffer->Data.SmiEntry.SmiSaveStateSize =
        (SMRAM_SAVE_STATE_MAP_OFFSET - SMM_PSD_OFFSET) + sizeof (SMRAM_SAVE_STATE_MAP);
      AuditCommBuffer->Data.SmiEntry.SmiSaveStateSize = ALIGN_VALUE (AuditCommBuffer->Data.SmiEntry.SmiSaveStateSize, SIZE_4KB);
      // Copy SMI entry, save state and GDT base addresses.
      StartIndex = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_CORES;
      for (Index = 0; Index < BUFFER_COUNT_CORES && Index + StartIndex < mNumberOfCpus; Index++) {
        if (Index + StartIndex == gMmCoreMmst.CurrentlyExecutingCpu) {
          SmiEntryDumpHandler (&AuditCommBuffer->Data.SmiEntry);
        } else {
          Status = SmmStartupThisAp (SmiEntryDumpHandler, Index + StartIndex, &AuditCommBuffer->Data.SmiEntry);
          ASSERT_EFI_ERROR (Status);
        }
      }

      AuditCommBuffer->Data.SmiEntry.SmiEntryCount = Index;
      if (Index + StartIndex < mNumberOfCpus) {
        // We are not done yet.
        AuditCommBuffer->Data.SmiEntry.HasMore = TRUE;
      }

      break;

    case SMM_PAGE_AUDIT_UNBLOCKED_REQUEST:
      DEBUG ((DEBUG_INFO, "%a - Getting unblocked entries.\n", __FUNCTION__));
      // Init defaults.
      ZeroMem (&AuditCommBuffer->Data.UnblockedRegion, sizeof (AuditCommBuffer->Data.UnblockedRegion));
      // Copy PDE Entries.
      StartIndex                                                 = AuditCommBuffer->Header.RequestIndex * BUFFER_COUNT_UNBLOCK;
      CopyCount                                                  = BUFFER_COUNT_UNBLOCK;
      Status                                                     = CollectUnblockedRegionsFromNthNode (StartIndex, AuditCommBuffer->Data.UnblockedRegion.UnblockedRegions, &CopyCount);
      AuditCommBuffer->Data.UnblockedRegion.UnblockedRegionCount = CopyCount;
      if (CopyCount == BUFFER_COUNT_UNBLOCK) {
        // It might be due to buffer is full
        AuditCommBuffer->Data.UnblockedRegion.HasMore = TRUE;
      }

      break;

    default:
      DEBUG ((DEBUG_ERROR, "%a - Unknown request type! 0x%02X\n", __FUNCTION__, AuditCommBuffer->Header.RequestType));
      Status = EFI_ACCESS_DENIED;
      break;
  }

  return Status;
}
