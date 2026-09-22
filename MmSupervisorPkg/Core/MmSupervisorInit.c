/** @file
  MM Core Main Entry Point

  Copyright (c) 2009 - 2025, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MmSupervisorCore.h"
#include "Relocate/Relocate.h"
#include "Mem/Mem.h"
#include "Mem/HeapGuard.h"
#include "Hob/SupvInitHobs.h"

#include <Protocol/MmBase.h>
#include <Protocol/PiPcd.h>

#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>
#include <Library/MmSupervisorCoreInitLib.h>
#include <Library/FvLib.h>
#include <Library/SecurePolicyLib.h>

PE_COFF_LOADER_IMAGE_CONTEXT      RuntimeSupvImageContext;
VOID                              *SmiRendezvous;
SMM_SUPV_SECURE_POLICY_DATA_V1_0  *MemPolicySnapshot = NULL;

EFI_STATUS
MmCoreFfsFindMmDriver (
  IN  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  );

/**
  This is the main Dispatcher for MM and it exits when there are no more
  drivers to run. Drain the mScheduledQueue and load and start a PE
  image for each driver. Search the mDiscoveredList to see if any driver can
  be placed on the mScheduledQueue. If no drivers are placed on the
  mScheduledQueue exit the function.

  @retval EFI_SUCCESS           All of the MM Drivers that could be dispatched
                                have been run and the MM Entry Point has been
                                registered.
  @retval EFI_NOT_READY         The MM Driver that registered the MM Entry Point
                                was just dispatched.
  @retval EFI_NOT_FOUND         There are no MM Drivers available to be dispatched.
  @retval EFI_ALREADY_STARTED   The MM Dispatcher is already running

**/
EFI_STATUS
MmLoadButNotDispatch (
  VOID
  );

// TODO: This should not be here.
#include "Services/MpService/MpService.h"
extern SMM_DISPATCHER_MP_SYNC_DATA  *mSmmMpSyncData;
extern SMM_CPU_PRIVATE_DATA         *gSmmCpuPrivate;
extern UINTN                        mSmmMpSyncDataSize;
extern LIST_ENTRY                   mDiscoveredList;

EFI_STATUS
EFIAPI
MmLoadImage (
  IN OUT EFI_MM_DRIVER_ENTRY           *DriverEntry,
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  );

//
// Physical pointer to MM_COMM_BUFFER structure shared between MM IPL and the MM Core
//
MM_COMM_BUFFER_STATUS  *mMmCommSupvMailboxBufferStatus;
MM_COMM_BUFFER_STATUS  *mMmCommUserMailboxBufferStatus;

//
// Ring 3 Hob pointer
//
VOID   *mMmHobStart;
UINTN  mMmHobSize;

//
// MM Core global variable for MM System Table.  Only accessed as a physical structure in MMRAM.
//
EFI_MM_SYSTEM_TABLE  gMmCoreMmst = {
  // The table header for the MMST.
  {
    MM_MMST_SIGNATURE,
    EFI_MM_SYSTEM_TABLE_REVISION,
    sizeof (gMmCoreMmst.Hdr)
  },
  // MmFirmwareVendor
  NULL,
  // MmFirmwareRevision
  0,
  // MmInstallConfigurationTable
  NULL,
  // I/O Service
  { },
  // Runtime memory services
  MmAllocateSupervisorPool,
  MmFreeSupervisorPool,
  MmAllocateSupervisorPages,
  MmFreePages,
};

EFI_MEMORY_DESCRIPTOR  mMmSupervisorAccessBuffer[MM_OPEN_BUFFER_CNT];

EFI_SYSTEM_TABLE                  *mEfiSystemTable;
UINTN                             mMmramRangeCount;
EFI_MMRAM_DESCRIPTOR              *mMmramRanges;
EFI_MM_DRIVER_ENTRY               *mMmCoreDriverEntry;
EFI_MM_DRIVER_ENTRY               *mMmUserDriverEntry;
BOOLEAN                           mMmReadyToLockDone          = FALSE;
BOOLEAN                           mCoreInitializationComplete = FALSE;
VOID                              *mInternalCommBufferCopy[MM_OPEN_BUFFER_CNT];
SMM_SUPV_SECURE_POLICY_DATA_V1_0  *FirmwarePolicy = NULL;

/**
  Place holder function until all the MM System Table Service are available.

  Note: This function is only used by MMRAM invocation.  It is never used by DXE invocation.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined
  @param  Arg5                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
MmEfiNotAvailableYetArg5 (
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  Arg4,
  UINTN  Arg5
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.
  //
  return EFI_NOT_AVAILABLE_YET;
}

/**
Function to extract common buffers to be used for both user handlers and supervisor handlers.

Note: In SCPC implementation, any attempt in triggering MMI handler without using the pre-
allocated buffer will be treated as a potential security violation.
**/
EFI_STATUS
EFIAPI
PrepareCommonBuffers (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS  GuidHob;
  MM_COMM_REGION_HOB    *CommRegionHob;
  MM_COMM_BUFFER        *UserCommRegionHob;
  EFI_STATUS            Status;
  UINTN                 Index;

  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    ZeroMem (&mMmSupervisorAccessBuffer[Index], sizeof (EFI_MEMORY_DESCRIPTOR));
  }

  GuidHob.Guid  = GetFirstGuidHob (&gMmCommonRegionHobGuid);
  CommRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);
  if (CommRegionHob->MmCommonRegionType == MM_SUPERVISOR_BUFFER_T) {
    if (mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart != 0) {
      DEBUG ((DEBUG_ERROR, "%a - Duplicated hobs for type %x!!\n", __func__, CommRegionHob->MmCommonRegionType));
      Status = EFI_ALREADY_STARTED;
      goto Exit;
    }

    if (!MmIsBufferOutsideMmValid (
           mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart,
           EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].NumberOfPages)
           ))
    {
      DEBUG ((
        DEBUG_ERROR,
        "%a - Buffer (%p) invalid for type %x!!\n",
        __func__,
        mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart,
        CommRegionHob->MmCommonRegionType
        ));
      Status = EFI_BAD_BUFFER_SIZE;
      ASSERT (FALSE);
      goto Exit;
    }

    mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart = CommRegionHob->MmCommonRegionAddr;
    mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].NumberOfPages = CommRegionHob->MmCommonRegionPages;

    mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].Type      = EfiRuntimeServicesData;
    mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].Attribute = EFI_MEMORY_XP | EFI_MEMORY_SP;
    if (CommRegionHob->MmCommonRegionType == MM_SUPERVISOR_BUFFER_T) {
      Status = MmAllocateSupervisorPages (
                 AllocateAnyPages,
                 EfiRuntimeServicesData,
                 CommRegionHob->MmCommonRegionPages,
                 (EFI_PHYSICAL_ADDRESS *)&mInternalCommBufferCopy[CommRegionHob->MmCommonRegionType]
                 );
    } else {
      Status = MmAllocatePages (
                 AllocateAnyPages,
                 EfiRuntimeServicesData,
                 CommRegionHob->MmCommonRegionPages,
                 (EFI_PHYSICAL_ADDRESS *)&mInternalCommBufferCopy[CommRegionHob->MmCommonRegionType]
                 );
    }

    ASSERT_EFI_ERROR (Status);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - Failed to allocate internal buffer copy, please consider adjust TSEG size... - %r\n", __func__, Status));
      goto Exit;
    }

    mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].VirtualStart = 0;
    DEBUG ((
      DEBUG_INFO,
      "%a - Populating MM Access Buffer Type %d to 0x%p with 0x%x pages\n",
      __func__,
      CommRegionHob->MmCommonRegionType,
      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart,
      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].NumberOfPages
      ));

    mMmCommSupvMailboxBufferStatus = (MM_COMM_BUFFER_STATUS *)(UINTN)CommRegionHob->MmStatusRegionAddr;
    if (mMmCommSupvMailboxBufferStatus == NULL) {
      DEBUG ((DEBUG_ERROR, "%a - Invalid Supervisor MM Communication Buffer Status pointer!\n", __func__));
      Status = EFI_INVALID_PARAMETER;
      goto Exit;
    }

    if (FALSE == MmIsBufferOutsideMmValid ((EFI_PHYSICAL_ADDRESS)(VOID *)mMmCommSupvMailboxBufferStatus, sizeof (*mMmCommSupvMailboxBufferStatus))) {
      DEBUG ((DEBUG_ERROR, "%a - Supervisor Mm Comm region overlaps into SMM\n", __func__));
      mMmCommSupvMailboxBufferStatus = NULL;
      Status                         = EFI_SECURITY_VIOLATION;
      goto Exit;
    }

    DEBUG ((DEBUG_INFO, "%a - Supervisor communication buffer status is at 0x%p\n", __func__, mMmCommSupvMailboxBufferStatus));
  } else {
    DEBUG ((
      DEBUG_ERROR,
      "%a - Invalid common buffer type %x."
      "Please make sure the user buffer is published through gMmCommBufferHobGuid!!\n",
      __func__,
      CommRegionHob->MmCommonRegionType
      ));
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

  // Cover the user level buffer, through the EDK2 way...
  GuidHob.Guid = GetFirstGuidHob (&gMmCommBufferHobGuid);
  if (GuidHob.Guid == NULL) {
    DEBUG ((DEBUG_ERROR, "Failed to find MM Communication Buffer HOB\n"));
    DEBUG ((DEBUG_ERROR, "Only Root MMI Handlers will be supported!\n"));
    Status = EFI_NOT_FOUND;
    goto Exit;
  }

  UserCommRegionHob = (MM_COMM_BUFFER *)GET_GUID_HOB_DATA (GuidHob);
  DEBUG ((
    DEBUG_INFO,
    "MM Communication Buffer is at %x, number of pages is %x\n",
    UserCommRegionHob->PhysicalStart,
    UserCommRegionHob->NumberOfPages
    ));

  if ((UserCommRegionHob->PhysicalStart == 0) || (UserCommRegionHob->NumberOfPages == 0)) {
    ASSERT (UserCommRegionHob->PhysicalStart != 0 && UserCommRegionHob->NumberOfPages != 0);
    Status = EFI_NOT_FOUND;
    goto Exit;
  }

  if (!MmIsBufferOutsideMmValid (
         UserCommRegionHob->PhysicalStart,
         EFI_PAGES_TO_SIZE (UserCommRegionHob->NumberOfPages)
         ))
  {
    UserCommRegionHob = NULL;
    DEBUG ((DEBUG_ERROR, "MM Communication Buffer is invalid!\n"));
    Status = EFI_BAD_BUFFER_SIZE;
    ASSERT (FALSE);
    goto Exit;
  }

  mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].PhysicalStart = UserCommRegionHob->PhysicalStart;
  mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages = UserCommRegionHob->NumberOfPages;
  mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].Type          = EfiRuntimeServicesData;
  mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].Attribute     = EFI_MEMORY_XP | EFI_MEMORY_SP;
  Status                                                    = MmAllocatePages (
                                                                AllocateAnyPages,
                                                                EfiRuntimeServicesData,
                                                                UserCommRegionHob->NumberOfPages,
                                                                (EFI_PHYSICAL_ADDRESS *)&mInternalCommBufferCopy[MM_USER_BUFFER_T]
                                                                );

  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to allocate internal buffer copy, please consider adjust TSEG size... - %r\n", __func__, Status));
    goto Exit;
  }

  mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].VirtualStart = 0;
  DEBUG ((
    DEBUG_INFO,
    "%a - Populating MM Access Buffer Type %d to 0x%p with 0x%x pages\n",
    __func__,
    MM_USER_BUFFER_T,
    mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].PhysicalStart,
    mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages
    ));

  mMmCommUserMailboxBufferStatus = (MM_COMM_BUFFER_STATUS *)(UINTN)UserCommRegionHob->Status;
  if (mMmCommUserMailboxBufferStatus == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid MM Communication Buffer Status pointer!\n", __func__));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  if (FALSE == MmIsBufferOutsideMmValid ((EFI_PHYSICAL_ADDRESS)(VOID *)mMmCommUserMailboxBufferStatus, sizeof (*mMmCommUserMailboxBufferStatus))) {
    DEBUG ((DEBUG_ERROR, "%a User Mm Comm region overlaps into SMM\n", __func__));
    mMmCommUserMailboxBufferStatus = NULL;
    Status                         = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a - User communication buffer status is at 0x%p\n", __func__, mMmCommUserMailboxBufferStatus));

  Status = EFI_SUCCESS;

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to prepare communicate buffer for Standalone MM environment... - %r\n", __func__, Status));
    ZeroMem (mMmSupervisorAccessBuffer, sizeof (mMmSupervisorAccessBuffer));
  }

  return Status;
}

/**
  Determine if two buffers overlap in memory.

  @param[in] Buff1  Pointer to first buffer
  @param[in] Size1  Size of Buff1
  @param[in] Buff2  Pointer to second buffer
  @param[in] Size2  Size of Buff2

  @retval TRUE      Buffers overlap in memory.
  @retval TRUE      Math error.
  @retval FALSE     Buffer doesn't overlap.

**/
BOOLEAN
InternalIsBufferOverlapped (
  IN UINT8  *Buff1,
  IN UINTN  Size1,
  IN UINT8  *Buff2,
  IN UINTN  Size2
  )
{
  UINTN    End1;
  UINTN    End2;
  BOOLEAN  IsOverUnderflow1;
  BOOLEAN  IsOverUnderflow2;

  // Check for over or underflow
  IsOverUnderflow1 = EFI_ERROR (SafeUintnAdd ((UINTN)Buff1, Size1, &End1));
  IsOverUnderflow2 = EFI_ERROR (SafeUintnAdd ((UINTN)Buff2, Size2, &End2));

  if (IsOverUnderflow1 || IsOverUnderflow2) {
    return TRUE;
  }

  if ((End1 <= (UINTN)Buff2) || ((UINTN)Buff1 >= End2)) {
    return FALSE;
  }

  return TRUE;
}

/**
  Helper function to copy and load a standalone MM core image.

  @param[in]  FwVolHeader   The firmware volume containing the image.
  @param[in]  FileHeader    The FFS file containing the image.
  @param[out] DriverEntry   The driver entry for the loaded image.
  @param[out] ImageContext  The PE/COFF context for the loaded image.

  @retval EFI_SUCCESS           The image was loaded successfully.
  @retval EFI_INVALID_PARAMETER A parameter was invalid.
  @retval Others                An error occurred while copying or loading the image.

**/
STATIC
EFI_STATUS
LoadStandaloneMmCoreImage (
  IN  EFI_FIRMWARE_VOLUME_HEADER    *FwVolHeader,
  IN  EFI_FFS_FILE_HEADER           *FileHeader,
  OUT EFI_MM_DRIVER_ENTRY           **DriverEntry,
  OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  EFI_STATUS  Status;
  UINT64      TotalSize;
  VOID        *InnerFvHeader;
  VOID        *Pe32Data;
  UINTN       Pe32DataSize;

  if ((FwVolHeader == NULL) || (FileHeader == NULL) || (DriverEntry == NULL) || (ImageContext == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((
    DEBUG_INFO,
    "[%a]   Discovered Standalone MM core [%g] in FV at 0x%x.\n",
    __func__,
    &FileHeader->Name,
    (UINTN)FileHeader
    ));

  TotalSize     = 0;
  InnerFvHeader = NULL;
  *DriverEntry  = NULL;
  CopyMem (&TotalSize, FileHeader->Size, sizeof (FileHeader->Size));

  if (CompareGuid (&FileHeader->Name, &gMmSupervisorCoreGuid)) {
    Status = MmAllocateSupervisorPages (
               AllocateAnyPages,
               EfiRuntimeServicesCode,
               EFI_SIZE_TO_PAGES (TotalSize),
               (EFI_PHYSICAL_ADDRESS *)&InnerFvHeader
               );
  } else {
    Status = MmAllocatePages (
               AllocateAnyPages,
               EfiRuntimeServicesCode,
               EFI_SIZE_TO_PAGES (TotalSize),
               (EFI_PHYSICAL_ADDRESS *)&InnerFvHeader
               );
  }

  DEBUG ((DEBUG_INFO, "%a Allocating for discovered FFS address: %p, pages: 0x%x\n", __func__, InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize)));
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a failed to allocate pages for the FFS file - %r!\n", __func__, Status));
    return Status;
  }

  CopyMem (InnerFvHeader, FileHeader, TotalSize);

  Status = FfsFindSectionData (EFI_SECTION_PE32, InnerFvHeader, &Pe32Data, &Pe32DataSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a failed to find PE32 section data - %r!\n", __func__, Status));
    MmFreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "%a found PE data at %p\n", __func__, Pe32Data));

  Status = MmAllocateSupervisorPool (
             EfiRuntimeServicesData,
             sizeof (EFI_MM_DRIVER_ENTRY),
             (VOID **)DriverEntry
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a failed to allocate the MM driver entry - %r!\n", __func__, Status));
    MmFreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize));
    return Status;
  }

  ZeroMem (*DriverEntry, sizeof (EFI_MM_DRIVER_ENTRY));

  (*DriverEntry)->Signature = EFI_MM_DRIVER_ENTRY_SIGNATURE;
  CopyGuid (&(*DriverEntry)->FileName, &FileHeader->Name);
  (*DriverEntry)->FwVolHeader  = FwVolHeader;
  (*DriverEntry)->Pe32Data     = Pe32Data;
  (*DriverEntry)->Pe32DataSize = Pe32DataSize;
  (*DriverEntry)->DepexSize    = 0;
  (*DriverEntry)->Depex        = NULL;

  ZeroMem (ImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));

  Status = MmLoadImage (*DriverEntry, ImageContext);
  if (EFI_ERROR (Status)) {
    MmFreeSupervisorPool (*DriverEntry);
    *DriverEntry = NULL;
    MmFreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize));
  }

  return Status;
}

/**
  Discovers Standalone MM drivers in FV HOBs and adds those drivers to the Standalone MM
  dispatch list.

  This function will also set the Standalone MM BFV address to the FV that contains this
  Standalone MM core driver.

  @retval   EFI_SUCCESS           An error was not encountered discovering Standalone MM drivers.
  @retval   EFI_NOT_FOUND         The HOB list could not be found.

**/
EFI_STATUS
DiscoverStandaloneMmDriversInFvHobs (
  IN EFI_PHYSICAL_ADDRESS  *StandaloneBfvAddress
  )
{
  UINT16                          ExtHeaderOffset;
  EFI_FIRMWARE_VOLUME_HEADER      *FwVolHeader;
  EFI_FIRMWARE_VOLUME_EXT_HEADER  *ExtHeader;
  EFI_FFS_FILE_HEADER             *FileHeader;
  EFI_PEI_HOB_POINTERS            Hob;
  EFI_STATUS                      Status;

  Hob.Raw = GetHobList ();
  if (Hob.Raw == NULL) {
    return EFI_NOT_FOUND;
  }

  do {
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, Hob.Raw);
    if (Hob.Raw != NULL) {
      FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)(Hob.FirmwareVolume->BaseAddress);

      DEBUG ((
        DEBUG_INFO,
        "[%a] Found FV HOB referencing FV at 0x%x. Size is 0x%x.\n",
        __func__,
        (UINTN)FwVolHeader,
        FwVolHeader->FvLength
        ));

      ExtHeaderOffset = ReadUnaligned16 (&FwVolHeader->ExtHeaderOffset);
      if (ExtHeaderOffset != 0) {
        ExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)((UINT8 *)FwVolHeader + ExtHeaderOffset);
        DEBUG ((DEBUG_INFO, "[%a]   FV GUID = {%g}.\n", __func__, &ExtHeader->FvName));
      }

      //
      // If a MM_STANDALONE or MM_CORE_STANDALONE driver is in the FV. Add the drivers
      // to the dispatch list. Mark the FV with this driver as the Standalone BFV.
      //
      FileHeader = NULL;
      do {
        Status =  FfsFindNextFile (
                    EFI_FV_FILETYPE_FREEFORM,
                    FwVolHeader,
                    &FileHeader
                    );
        if (!EFI_ERROR (Status)) {
          if (CompareGuid (&FileHeader->Name, &gMmSupervisorCoreGuid)) {
            *StandaloneBfvAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)FwVolHeader;

            Status = LoadStandaloneMmCoreImage (
                       FwVolHeader,
                       FileHeader,
                       &mMmCoreDriverEntry,
                       &RuntimeSupvImageContext
                       );
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "%a loading mm image returned %r\n", __func__, Status));
              PANIC ("Unable to load supervisor, FIMD!!!\n");
            }

            SmiRendezvous = (VOID *)RuntimeSupvImageContext.EntryPoint;
          } else if (CompareGuid (&FileHeader->Name, &gMmSupervisorUserGuid)) {
            Status = LoadStandaloneMmCoreImage (
                       FwVolHeader,
                       FileHeader,
                       &mMmUserDriverEntry,
                       &RuntimeSupvImageContext
                       );
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "%a MmAddStandaloneMmDriver failed - %r!\n", __func__, Status));
              break;
            }
          }
        } else {
          break;
        }
      } while (TRUE);

      // if (!EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_INFO,
        "[%a]   Adding Standalone MM drivers in FV at 0x%x to the dispatch list.\n",
        __func__,
        (UINTN)FwVolHeader
        ));
      Status = MmCoreFfsFindMmDriver (FwVolHeader);
      ASSERT_EFI_ERROR (Status);
      // }

      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);

  return EFI_SUCCESS;
}

INTN
EFIAPI
CompareMmramRangeCpuStart (
  IN CONST VOID  *MmramDescriptor1,
  IN CONST VOID  *MmramDescriptor2
  )
{
  CONST EFI_MMRAM_DESCRIPTOR  *Desc1 = (CONST EFI_MMRAM_DESCRIPTOR *)MmramDescriptor1;
  CONST EFI_MMRAM_DESCRIPTOR  *Desc2 = (CONST EFI_MMRAM_DESCRIPTOR *)MmramDescriptor2;

  if (Desc1->CpuStart < Desc2->CpuStart) {
    return -1;
  } else if (Desc1->CpuStart > Desc2->CpuStart) {
    return 1;
  } else {
    // Well, we better not have two same CpuStart entries
    ASSERT (FALSE);
    return 0;
  }
}

/**
  Routine for initializing policy data provided by firmware.

  @param  StandaloneBfvAddress  The base address of the FV that contains the policy file.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval Errors                The supervisor is unable to locate or protect the policy from firmware.

**/
EFI_STATUS
InitializePolicy (
  IN EFI_PHYSICAL_ADDRESS  StandaloneBfvAddress
  )
{
  EFI_STATUS           Status;
  EFI_FFS_FILE_HEADER  *FileHeader;
  VOID                 *SectionData;
  UINTN                SectionDataSize;
  UINTN                PolicySize;

  FirmwarePolicy = NULL;

  //
  // First try to find the policy file based on the GUID specified.
  //
  FileHeader = NULL;
  do {
    Status =  FfsFindNextFile (
                EFI_FV_FILETYPE_FREEFORM,
                (EFI_FIRMWARE_VOLUME_HEADER *)StandaloneBfvAddress,
                &FileHeader
                );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Failed to locate firmware policy file from given FV - %r\n",
        __func__,
        Status
        ));
      break;
    }

    if (!CompareGuid (&FileHeader->Name, &gMmSupervisorPolicyFileGuid)) {
      continue;
    }

    DEBUG ((
      DEBUG_INFO,
      "[%a] Discovered policy file in FV at 0x%p.\n",
      __func__,
      FileHeader
      ));

    Status = FfsFindSectionData (
               EFI_SECTION_RAW,
               FileHeader,
               &SectionData,
               &SectionDataSize
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Failed to find raw section from discovered policy file - %r\n",
        __func__,
        Status
        ));
      break;
    }

    PolicySize = ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)SectionData)->Size;
    if (PolicySize > SectionDataSize) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Policy data size 0x%x > blob size 0x%x.\n",
        __func__,
        PolicySize,
        SectionDataSize
        ));
      Status = EFI_BAD_BUFFER_SIZE;
      break;
    }

    FirmwarePolicy = AllocateAlignedPages (EFI_SIZE_TO_PAGES (PolicySize), EFI_PAGE_SIZE);
    if (FirmwarePolicy == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Cannot allocate page for firmware provided policy - %r\n",
        __func__,
        Status
        ));
      break;
    }

    CopyMem (FirmwarePolicy, SectionData, PolicySize);

    DEBUG_CODE_BEGIN ();
    DumpSmmPolicyData (FirmwarePolicy);
    DEBUG_CODE_END ();

    // We found one valid firmware policy, do not need to proceed further on this FV.
    break;
  } while (TRUE);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Unable to locate a valid firmware policy from given FV, bail here - %r\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  Status = SecurityPolicyCheck (FirmwarePolicy);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Policy check failed on policy blob from firmware - %r\n", __func__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

Done:
  return Status;
}

/**
  Publish the MMRAM ranges described by the inbound HOB list and bring up the
  core memory services on top of them.

  Leaves mMmramRanges holding a private, CpuStart-sorted copy of the ranges.

  @param[in]  HobStart  Start of the inbound HOB list.

  @retval EFI_SUCCESS           Memory services are up and mMmramRanges is populated.
  @retval EFI_UNSUPPORTED       No MMRAM descriptor HOB was found.
  @retval EFI_NOT_FOUND         The MMRAM descriptor HOB was malformed.
  @retval EFI_OUT_OF_RESOURCES  Failed to allocate the private copy of the ranges.
**/
STATIC
EFI_STATUS
InitializeMmramRanges (
  IN VOID  *HobStart
  )
{
  EFI_HOB_GUID_TYPE               *MmramRangesHob;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *MmramRangesHobData;
  EFI_MMRAM_DESCRIPTOR            *MmramRanges;
  EFI_MMRAM_DESCRIPTOR            MmDescDummy;
  UINTN                           MmramRangeCount;
  UINTN                           Index;

  //
  // Extract the MMRAM ranges from the MMRAM descriptor HOB
  //
  MmramRangesHob = GetNextGuidHob (&gEfiMmPeiMmramMemoryReserveGuid, HobStart);
  if (MmramRangesHob == NULL) {
    MmramRangesHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
    if (MmramRangesHob == NULL) {
      return EFI_UNSUPPORTED;
    }
  }

  MmramRangesHobData = GET_GUID_HOB_DATA (MmramRangesHob);
  if (MmramRangesHobData == NULL) {
    ASSERT (MmramRangesHobData != NULL);
    return EFI_NOT_FOUND;
  }

  MmramRanges     = MmramRangesHobData->Descriptor;
  MmramRangeCount = (UINTN)MmramRangesHobData->NumberOfMmReservedRegions;
  if ((MmramRanges == NULL) || (MmramRangeCount == 0)) {
    ASSERT (MmramRanges);
    ASSERT (MmramRangeCount);
    return EFI_NOT_FOUND;
  }

  //
  // Print the MMRAM ranges passed by the caller
  //
  DEBUG ((DEBUG_INFO, "MmramRangeCount - 0x%x\n", MmramRangeCount));
  for (Index = 0; Index < MmramRangeCount; Index++) {
    DEBUG ((
      DEBUG_INFO,
      "MmramRanges[%d]: 0x%016lx - 0x%lx\n",
      Index,
      MmramRanges[Index].CpuStart,
      MmramRanges[Index].PhysicalSize
      ));
  }

  //
  // Initialize memory service using free MMRAM
  //
  DEBUG ((DEBUG_INFO, "MmInitializeMemoryServices\n"));
  MmInitializeMemoryServices (MmramRangeCount, MmramRanges);
  mMemoryAllocationMmst = &gMmCoreMmst;

  //
  // Copy the MMRAM ranges into private MMRAM
  //
  mMmramRangeCount = MmramRangeCount;
  DEBUG ((DEBUG_INFO, "mMmramRangeCount - 0x%x\n", mMmramRangeCount));
  mMmramRanges = AllocatePool (mMmramRangeCount * sizeof (EFI_MMRAM_DESCRIPTOR));
  DEBUG ((DEBUG_INFO, "mMmramRanges - 0x%x\n", mMmramRanges));
  if (mMmramRanges == NULL) {
    ASSERT (mMmramRanges != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (mMmramRanges, (VOID *)(UINTN)MmramRanges, mMmramRangeCount * sizeof (EFI_MMRAM_DESCRIPTOR));

  // Sort the Mmram ranges by CpuStart address
  QuickSort (
    mMmramRanges,
    mMmramRangeCount,
    sizeof (EFI_MMRAM_DESCRIPTOR),
    CompareMmramRangeCpuStart,
    &MmDescDummy
    );

  return EFI_SUCCESS;
}

/**
  The Entry Point for MM Core

  Install DXE Protocols and reload MM Core into MMRAM and register MM Core
  EntryPoint on the MMI vector.

  Note: This function is called for both DXE invocation and MMRAM invocation.

  @param  HobStart       A pointer to the start of the HOB list.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmSupervisorMain (
  IN VOID  *HobStart
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  StandaloneBfvAddress;
  MM_SUPV_INIT_HOB_BUILDER   HobBuilder;

  MmSupervisorCoreEntryInit ();

  DEBUG ((DEBUG_INFO, "MmMain - 0x%x\n", HobStart));

  Status = InitializeMmramRanges (HobStart);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  ProcessLibraryConstructorList (HobStart, &gMmCoreMmst);

  //
  // Discover Standalone MM drivers for dispatch
  //
  Status = DiscoverStandaloneMmDriversInFvHobs (&StandaloneBfvAddress);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    goto Exit;
  }

  //
  // Stand up the supervisor HOB list. The steps below append to it as the data
  // they describe becomes available, so it is terminated last.
  //
  SupvInitHobsInit (&HobBuilder);

  Status = SetupSmiEntryExit ();
  if (EFI_ERROR (Status)) {
    // Should not happen
    DEBUG ((DEBUG_ERROR, "Configuring SMI entry and exit failed - %r\n", Status));
    ASSERT (FALSE);
    goto Exit;
  }

  MmLoadButNotDispatch ();

  // Describes the core, the user module and every driver loaded above
  Status = SupvInitHobsAddModuleAllocations (&HobBuilder);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to add module allocations - Status %d\n", __func__, Status));
    ASSERT (FALSE);
    goto Exit;
  }

  Status = PrepareCommonBuffers ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to prepare comm buffer - Status %d\n", __func__, Status));
    ASSERT (FALSE);
    goto Exit;
  }

  InitializePolicy (StandaloneBfvAddress);

  // Describes what the supervisor set up for the runtime to pick up
  Status = SupvInitHobsAddPassDown (&HobBuilder);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to add pass down HOB - Status %d\n", __func__, Status));
    ASSERT (FALSE);
    goto Exit;
  }

  LockMmCoreBeforeExit ();

  // The lock step is the last thing to allocate, so the memory map is now final
  SupvInitHobsAddMmramDescriptors (&HobBuilder);
  SupvInitHobsFinalize (&HobBuilder);

  mCoreInitializationComplete = TRUE;

  DEBUG ((DEBUG_INFO, "Jumping to MM Supervisor runtime!!!\n"));

  PostRelocationRun ();

  DEBUG ((DEBUG_INFO, "MmMain Done!\n"));

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Standalone MM foundation not properly set, system may not boot - %r!\n", __func__, Status));
  }

  return Status;
}
