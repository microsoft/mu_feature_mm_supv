/**@file

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MmSupervisorCore.h"
#include <Library/FvLib.h>
#include <Library/ExtractGuidedSectionLib.h>

#include "Mem/Mem.h"

//
// MM FFS driver cache list node signature
//
#define FFS_DRIVER_CACHE_SIGNATURE  SIGNATURE_32('F','F','D','C')

typedef struct {
  UINTN                    Signature;
  LIST_ENTRY               Link;
  EFI_MEMORY_DESCRIPTOR    DriverCacheDesc;
} FFS_DRIVER_CACHE_LIST;

//
// List of file types supported by dispatcher
//
EFI_FV_FILETYPE  mMmFileTypes[] = {
  // Traditional modules are restricted to load under MU's standalone MM environment
  // EFI_FV_FILETYPE_MM,
  EFI_FV_FILETYPE_MM_STANDALONE,
  //
  // Note: DXE core will process the FV image file, so skip it in MM core
  // EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE
  //
};

//
// List of firmware volume headers whose containing firmware volumes have been
// parsed and added to the mFwDriverList.
//
LIST_ENTRY  mFfsDriverCacheList = INITIALIZE_LIST_HEAD_VARIABLE (mFfsDriverCacheList);

EFI_STATUS
MmAddToDriverList (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader,
  IN VOID                        *Pe32Data,
  IN UINTN                       Pe32DataSize,
  IN VOID                        *Depex,
  IN UINTN                       DepexSize,
  IN EFI_GUID                    *DriverName
  );

BOOLEAN
FvHasBeenProcessed (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  );

KNOWN_FWVOL *
FvIsBeingProcessed (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  );

EFI_STATUS
MmCoreFfsFindMmDriver (
  IN  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  )

/*++

Routine Description:
  Given the pointer to the Firmware Volume Header find the
  MM driver and return its PE32 image.

Arguments:
  FwVolHeader - Pointer to memory mapped FV

Returns:
  other       - Failure

--*/
{
  EFI_STATUS                  Status;
  EFI_STATUS                  DepexStatus;
  EFI_FFS_FILE_HEADER         *FileHeader;
  EFI_FFS_FILE_HEADER         *InnerFileHeader;
  EFI_FV_FILETYPE             FileType;
  VOID                        *Pe32Data;
  UINTN                       Pe32DataSize;
  VOID                        *Depex;
  UINTN                       DepexSize;
  UINTN                       Index;
  EFI_FIRMWARE_VOLUME_HEADER  *InnerFvHeader;
  KNOWN_FWVOL                 *KnownFwVol;
  UINTN                       TotalSize;
  UINTN                       BufferIndex;
  UINTN                       FileSize;
  FFS_DRIVER_CACHE_LIST       *CurrentCacheNode;

  DEBUG ((DEBUG_INFO, "MmCoreFfsFindMmDriver - 0x%x\n", FwVolHeader));

  if (FvHasBeenProcessed (FwVolHeader)) {
    return EFI_SUCCESS;
  }

  KnownFwVol = FvIsBeingProcessed (FwVolHeader);
  if (KnownFwVol == NULL) {
    //
    // The FV with the same FV name guid has already been processed.
    // So lets skip it!
    //
    return EFI_SUCCESS;
  }

  for (Index = 0; Index < sizeof (mMmFileTypes) / sizeof (mMmFileTypes[0]); Index++) {
    DEBUG ((DEBUG_INFO, "Check MmFileTypes - 0x%x\n", mMmFileTypes[Index]));
    FileType   = mMmFileTypes[Index];
    FileHeader = NULL;
    TotalSize  = 0;
    do {
      Status = FfsFindNextFile (FileType, FwVolHeader, &FileHeader);
      if (!EFI_ERROR (Status)) {
        FileSize = 0;
        CopyMem (&FileSize, FileHeader->Size, sizeof (FileHeader->Size));
        TotalSize = TotalSize + FileSize;
      }
    } while (!EFI_ERROR (Status));

    // If by the time we get here this FV is outside of MMRAM, copy it MMRAM
    // It will be marked as CPL3 RO XP before entering MMI
    Status = MmAllocatePages (
               AllocateAnyPages,
               EfiRuntimeServicesCode,
               EFI_SIZE_TO_PAGES (TotalSize),
               (EFI_PHYSICAL_ADDRESS *)&InnerFvHeader
               );
    DEBUG ((DEBUG_INFO, "%a Allocating for discovered ffs address: 0x%p, pages: 0x%x\n", __FUNCTION__, InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize)));
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Allocating for FwVol out of resources - %r!\n", Status));
      goto Done;
    }

    FileHeader  = NULL;
    BufferIndex = 0;
    do {
      Status = FfsFindNextFile (FileType, FwVolHeader, &FileHeader);
      if (!EFI_ERROR (Status)) {
        FileSize = 0;
        CopyMem (&FileSize, FileHeader->Size, sizeof (FileHeader->Size));
        Status = MmCopyMemToMmram ((UINT8 *)InnerFvHeader + BufferIndex, FileHeader, FileSize);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "Copying FFS from FV failed - %r!\n", Status));
          FreePages (InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize));
          goto Done;
        }

        InnerFileHeader = (EFI_FFS_FILE_HEADER *)((UINT8 *)InnerFvHeader + BufferIndex);
        BufferIndex     = BufferIndex + FileSize;
        Status          = FfsFindSectionData (EFI_SECTION_PE32, InnerFileHeader, &Pe32Data, &Pe32DataSize);
        DEBUG ((DEBUG_INFO, "Find PE data - 0x%x\n", Pe32Data));
        DepexStatus = FfsFindSectionData (EFI_SECTION_MM_DEPEX, InnerFileHeader, &Depex, &DepexSize);
        if (!EFI_ERROR (DepexStatus)) {
          // Set the FV header to be NULL here since the original header will not be available anyway.
          MmAddToDriverList (NULL, Pe32Data, Pe32DataSize, Depex, DepexSize, &InnerFileHeader->Name);
        }
      }
    } while (!EFI_ERROR (Status));
  }

  // Group all temporarily allocated buffer into a linked list, they will be frees at ready to lock event
  CurrentCacheNode = AllocateZeroPool (sizeof (FFS_DRIVER_CACHE_LIST));
  ASSERT (CurrentCacheNode != NULL);

  CurrentCacheNode->Signature                     = FFS_DRIVER_CACHE_SIGNATURE;
  CurrentCacheNode->DriverCacheDesc.NumberOfPages = EFI_SIZE_TO_PAGES (TotalSize);
  CurrentCacheNode->DriverCacheDesc.PhysicalStart = (EFI_PHYSICAL_ADDRESS)(UINTN)InnerFvHeader;
  CurrentCacheNode->DriverCacheDesc.Type          = EfiRuntimeServicesData;
  InsertTailList (&mFfsDriverCacheList, &CurrentCacheNode->Link);

  Status = EFI_SUCCESS;

Done:
  return Status;
}

/**
  Helper function to protect temporarily allocated buffer for ffs. They should not be changed before ready to lock.

  @retval EFI_SUCCESS       All previously allocated buffer for ffs are protected properly.
  @retval Error             Some issue occurred during garbage collection.

**/
EFI_STATUS
LockFfsBuffer (
  VOID
  )
{
  EFI_STATUS             Status;
  LIST_ENTRY             *Link;
  FFS_DRIVER_CACHE_LIST  *CurrentCacheNode;

  // Patch FFS buffer to be CPL3, RO and XP
  if (IsListEmpty (&mFfsDriverCacheList)) {
    ASSERT (FALSE);
  }

  //
  // Iterate through each node in the list and free all the referenced memory block referenced and the node itself.
  //
  Link = mFfsDriverCacheList.ForwardLink;
  while (Link != &mFfsDriverCacheList) {
    CurrentCacheNode = CR (Link, FFS_DRIVER_CACHE_LIST, Link, FFS_DRIVER_CACHE_SIGNATURE);
    Link             = Link->ForwardLink;

    if ((CurrentCacheNode->DriverCacheDesc.PhysicalStart != 0) &&
        (CurrentCacheNode->DriverCacheDesc.NumberOfPages != 0))
    {
      Status = SmmSetMemoryAttributes (
                 CurrentCacheNode->DriverCacheDesc.PhysicalStart,
                 EFI_PAGES_TO_SIZE (CurrentCacheNode->DriverCacheDesc.NumberOfPages),
                 (EFI_MEMORY_RO | EFI_MEMORY_XP)
                 );
      if (EFI_ERROR (Status)) {
        ASSERT_EFI_ERROR (Status);
        goto Exit;
      }
    }
  }

Exit:
  return Status;
}

/**
  Helper function to recycle temporarily allocated buffer for ffs. They should not be needed anymore.

  @retval EFI_SUCCESS       All previously allocated buffer for ffs are recycled properly.
  @retval Error             Some issue occurred during garbage collection.

**/
EFI_STATUS
RecycleFfsBuffer (
  VOID
  )
{
  EFI_STATUS             Status;
  LIST_ENTRY             *Link;
  FFS_DRIVER_CACHE_LIST  *CurrentCacheNode;

  if (IsListEmpty (&mFfsDriverCacheList)) {
    Status = EFI_NOT_FOUND;
    goto Exit;
  }

  //
  // Iterate through each node in the list and free all the referenced memory block referenced and the node itself.
  //
  Link = mFfsDriverCacheList.ForwardLink;
  while (Link != &mFfsDriverCacheList) {
    CurrentCacheNode = CR (Link, FFS_DRIVER_CACHE_LIST, Link, FFS_DRIVER_CACHE_SIGNATURE);
    if ((CurrentCacheNode->DriverCacheDesc.PhysicalStart != 0) &&
        (CurrentCacheNode->DriverCacheDesc.NumberOfPages != 0))
    {
      // Remove read only lock here, since they were marked as RO
      Status = SmmClearMemoryAttributes (
                 CurrentCacheNode->DriverCacheDesc.PhysicalStart,
                 EFI_PAGES_TO_SIZE (CurrentCacheNode->DriverCacheDesc.NumberOfPages),
                 EFI_MEMORY_RO
                 );
      if (EFI_ERROR (Status)) {
        goto Exit;
      }

      MmFreePages (CurrentCacheNode->DriverCacheDesc.PhysicalStart, CurrentCacheNode->DriverCacheDesc.NumberOfPages);
    }

    Link = RemoveEntryList (Link);
    // Moved iterator, good to free the node itself
    MmFreeSupervisorPool (CurrentCacheNode);
  }

  Status = EFI_SUCCESS;

Exit:
  return Status;
}
