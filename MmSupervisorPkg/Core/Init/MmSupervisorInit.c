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
// #include "PrivilegeMgmt/PrivilegeMgmt.h"
// #include "Telemetry/Telemetry.h"
#include <Guid/PassDown.h>
#include <Guid/DepexStruc.h>

#include <Protocol/MmBase.h>
#include <Protocol/PiPcd.h>

#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>
#include <Library/MmSupervisorCoreInitLib.h>
#include <Library/FvLib.h>
#include <Library/SecurePolicyLib.h>

PE_COFF_LOADER_IMAGE_CONTEXT  RuntimeSupvImageContext;
VOID *SmiRendezvous;
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
#include "../Common/MpService.h"
extern SMM_DISPATCHER_MP_SYNC_DATA  *mSmmMpSyncData;
extern SMM_CPU_PRIVATE_DATA  *gSmmCpuPrivate;
extern UINTN mSmmMpSyncDataSize;
extern LIST_ENTRY  mDiscoveredList;
extern UINTN mMmiEntrySize;

EFI_STATUS
EFIAPI
MmLoadImage (
  IN OUT EFI_MM_DRIVER_ENTRY           *DriverEntry,
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  );

// //
// // Globals used to initialize the protocol
// //
// EFI_HANDLE  mMmCpuHandle = NULL;

//
// Physical pointer to MM_COMM_BUFFER structure shared between MM IPL and the MM Core
//
MM_COMM_BUFFER_STATUS  mMmCommunicationBufferStatus;
MM_COMM_BUFFER_STATUS  *mMmCommMailboxBufferStatus = NULL;

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
  { 0 },
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
// MM_SUPV_USER_COMMON_BUFFER        *SupervisorToUserDataBuffer = NULL;
// BOOLEAN                           mMmReadyToLockDone          = FALSE;
BOOLEAN                           mCoreInitializationComplete = FALSE;
// VOID                              *mInternalCommBufferCopy[MM_OPEN_BUFFER_CNT];
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
    // if (CommRegionHob->MmCommonRegionType == MM_SUPERVISOR_BUFFER_T) {
    //   Status = MmAllocateSupervisorPages (
    //              AllocateAnyPages,
    //              EfiRuntimeServicesData,
    //              CommRegionHob->MmCommonRegionPages,
    //              (EFI_PHYSICAL_ADDRESS *)&mInternalCommBufferCopy[CommRegionHob->MmCommonRegionType]
    //              );
    // } else {
    //   Status = MmAllocatePages (
    //              AllocateAnyPages,
    //              EfiRuntimeServicesData,
    //              CommRegionHob->MmCommonRegionPages,
    //              (EFI_PHYSICAL_ADDRESS *)&mInternalCommBufferCopy[CommRegionHob->MmCommonRegionType]
    //              );
    // }

    // ASSERT_EFI_ERROR (Status);
    // if (EFI_ERROR (Status)) {
    //   DEBUG ((DEBUG_ERROR, "%a - Failed to allocate internal buffer copy, please consider adjust TSEG size... - %r\n", __func__, Status));
    //   goto Exit;
    // }

    mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].VirtualStart = 0;
    DEBUG ((
      DEBUG_INFO,
      "%a - Populating MM Access Buffer Type %d to 0x%p with 0x%x pages\n",
      __func__,
      CommRegionHob->MmCommonRegionType,
      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart,
      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].NumberOfPages
      ));
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
  // Status                                                    = MmAllocatePages (
  //                                                               AllocateAnyPages,
  //                                                               EfiRuntimeServicesData,
  //                                                               UserCommRegionHob->NumberOfPages,
  //                                                               (EFI_PHYSICAL_ADDRESS *)&mInternalCommBufferCopy[MM_USER_BUFFER_T]
  //                                                               );

  // ASSERT_EFI_ERROR (Status);
  // if (EFI_ERROR (Status)) {
  //   DEBUG ((DEBUG_ERROR, "%a - Failed to allocate internal buffer copy, please consider adjust TSEG size... - %r\n", __func__, Status));
  //   goto Exit;
  // }

  mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].VirtualStart = 0;
  DEBUG ((
    DEBUG_INFO,
    "%a - Populating MM Access Buffer Type %d to 0x%p with 0x%x pages\n",
    __func__,
    MM_USER_BUFFER_T,
    mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].PhysicalStart,
    mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages
    ));

  mMmCommMailboxBufferStatus = (MM_COMM_BUFFER_STATUS *)(UINTN)UserCommRegionHob->Status;
  if (mMmCommMailboxBufferStatus == NULL) {
    DEBUG ((DEBUG_ERROR, "%a - Invalid MM Communication Buffer Status pointer!\n", __func__));
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  if (FALSE == MmIsBufferOutsideMmValid ((EFI_PHYSICAL_ADDRESS)(VOID *)mMmCommMailboxBufferStatus, sizeof (*mMmCommMailboxBufferStatus))) {
    DEBUG ((DEBUG_ERROR, "%a User Mm Comm region overlaps into SMM\n", __func__));
    Status = EFI_SECURITY_VIOLATION;
    goto Exit;
  }

  // Status = MmAllocatePages (
  //            AllocateAnyPages,
  //            EfiRuntimeServicesData,
  //            DEFAULT_SUPV_TO_USER_BUFFER_PAGE,
  //            (EFI_PHYSICAL_ADDRESS *)&SupervisorToUserDataBuffer
  //            );
  // ASSERT_EFI_ERROR (Status);
  // if (EFI_ERROR (Status)) {
  //   DEBUG ((DEBUG_ERROR, "%a - Failed to allocate supervisor to user buffer, cannot continue...\n", __func__));
  //   goto Exit;
  // }
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

UINTN
GetHobListSize (
  IN VOID  *HobStart
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  ASSERT (HobStart != NULL);

  Hob.Raw = (UINT8 *)HobStart;
  while (!END_OF_HOB_LIST (Hob)) {
    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  //
  // Need plus END_OF_HOB_LIST
  //
  return (UINTN)Hob.Raw - (UINTN)HobStart + sizeof (EFI_HOB_GENERIC_HEADER);
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
  UINT64                          TotalSize;
  VOID                            *InnerFvHeader;
  VOID                        *Pe32Data;
  UINTN                       Pe32DataSize;

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
        Status     =  FfsFindNextFile (
                        EFI_FV_FILETYPE_MM_CORE_STANDALONE,
                        FwVolHeader,
                        &FileHeader
                        );
        if (!EFI_ERROR (Status)) {
          if (CompareGuid (&FileHeader->Name, &gMmSupervisorCoreGuid)) {
            DEBUG ((
              DEBUG_INFO,
              "[%a]   Discovered Standalone MM runtime core [%g] in FV at 0x%x.\n",
              __func__,
              &FileHeader->Name,
              (UINTN)FileHeader
              ));

            *StandaloneBfvAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)FwVolHeader;

            TotalSize = 0;
            CopyMem (&TotalSize, FileHeader->Size, sizeof (FileHeader->Size));

            Status = MmAllocateSupervisorPages (
                      AllocateAnyPages,
                      EfiRuntimeServicesCode,
                      EFI_SIZE_TO_PAGES (TotalSize),
                      (EFI_PHYSICAL_ADDRESS *)&InnerFvHeader
                      );
            DEBUG ((DEBUG_INFO, "%a Allocating for discovered ffs address: 0x%p, pages: 0x%x\n", __func__, InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize)));
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "Allocating for FwVol out of resources - %r!\n", Status));
              break;
            }

            CopyMem ((UINT8 *)InnerFvHeader, FileHeader, TotalSize);
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "Copying FFS from FV failed - %r!\n", Status));
              MmFreePages ((EFI_PHYSICAL_ADDRESS)InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize));
              break;
            }

            Status  = FfsFindSectionData (EFI_SECTION_PE32, InnerFvHeader, &Pe32Data, &Pe32DataSize);
            DEBUG ((DEBUG_INFO, "Find PE data - 0x%x\n", Pe32Data));

            //
            // Allocate a Loaded Image Protocol in MM
            //
            Status = MmAllocateSupervisorPool (EfiRuntimeServicesData, sizeof (EFI_MM_DRIVER_ENTRY), (VOID **)&mMmCoreDriverEntry);
            ASSERT_EFI_ERROR (Status);

            ZeroMem (mMmCoreDriverEntry, sizeof (EFI_MM_DRIVER_ENTRY));

            //
            // Fill in the remaining fields of the Loaded Image Protocol instance.
            //
            mMmCoreDriverEntry->Signature                 = EFI_MM_DRIVER_ENTRY_SIGNATURE;
            CopyGuid (&mMmCoreDriverEntry->FileName, &FileHeader->Name);
            mMmCoreDriverEntry->FwVolHeader  = FwVolHeader;
            mMmCoreDriverEntry->Pe32Data     = Pe32Data;
            mMmCoreDriverEntry->Pe32DataSize = Pe32DataSize;
            mMmCoreDriverEntry->DepexSize    = 0;
            mMmCoreDriverEntry->Depex        = NULL;

            ZeroMem (&RuntimeSupvImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));

            Status = MmLoadImage (mMmCoreDriverEntry, &RuntimeSupvImageContext);
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "%a loading mm image returned %r\n", __func__, Status));
              PANIC ("Unable to load supervisor, FIMD!!!\n");
            }

            SmiRendezvous = (VOID*)RuntimeSupvImageContext.EntryPoint;
          } else if (CompareGuid (&FileHeader->Name, &gMmSupervisorUserGuid)) {
            DEBUG ((
              DEBUG_INFO,
              "[%a]   Discovered Standalone MM user module [%g] in FV at 0x%x.\n",
              __func__,
              &FileHeader->Name,
              (UINTN)FileHeader
              ));

            TotalSize = 0;
            CopyMem (&TotalSize, FileHeader->Size, sizeof (FileHeader->Size));

            Status = MmAllocatePages (
                      AllocateAnyPages,
                      EfiRuntimeServicesCode,
                      EFI_SIZE_TO_PAGES (TotalSize),
                      (EFI_PHYSICAL_ADDRESS *)&InnerFvHeader
                      );
            DEBUG ((DEBUG_INFO, "%a Allocating for discovered ffs address: 0x%p, pages: 0x%x\n", __func__, InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize)));
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "Allocating for FwVol out of resources - %r!\n", Status));
              break;
            }

            CopyMem ((UINT8 *)InnerFvHeader, FileHeader, TotalSize);
            if (EFI_ERROR (Status)) {
              DEBUG ((DEBUG_ERROR, "Copying FFS from FV failed - %r!\n", Status));
              MmFreePages ((EFI_PHYSICAL_ADDRESS)InnerFvHeader, EFI_SIZE_TO_PAGES (TotalSize));
              break;
            }

            Status  = FfsFindSectionData (EFI_SECTION_PE32, InnerFvHeader, &Pe32Data, &Pe32DataSize);
            DEBUG ((DEBUG_INFO, "Find PE data - 0x%x\n", Pe32Data));

            //
            // Allocate a Loaded Image Protocol in MM
            //
            Status = MmAllocateSupervisorPool (EfiRuntimeServicesData, sizeof (EFI_MM_DRIVER_ENTRY), (VOID **)&mMmUserDriverEntry);
            ASSERT_EFI_ERROR (Status);

            ZeroMem (mMmUserDriverEntry, sizeof (EFI_MM_DRIVER_ENTRY));

            //
            // Fill in the remaining fields of the Loaded Image Protocol instance.
            //
            mMmUserDriverEntry->Signature                 = EFI_MM_DRIVER_ENTRY_SIGNATURE;
            CopyGuid (&mMmUserDriverEntry->FileName, &FileHeader->Name);
            mMmUserDriverEntry->FwVolHeader  = FwVolHeader;
            mMmUserDriverEntry->Pe32Data     = Pe32Data;
            mMmUserDriverEntry->Pe32DataSize = Pe32DataSize;
            mMmUserDriverEntry->DepexSize    = 0;
            mMmUserDriverEntry->Depex        = NULL;

            ZeroMem (&RuntimeSupvImageContext, sizeof (PE_COFF_LOADER_IMAGE_CONTEXT));

            Status = MmLoadImage (mMmUserDriverEntry, &RuntimeSupvImageContext);
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

EFI_STATUS
EFIAPI
PrepareMmSupervisorHobs (
  IN  EFI_PHYSICAL_ADDRESS  MmHobStart,
  OUT UINT64                *MmHobSize
);

EFI_STATUS
CreateMemoryAllocationModuleHob (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN OUT UINT64            *Length
  )
{
  UINTN                             NewLength;
  EFI_HOB_MEMORY_ALLOCATION_MODULE  *MmCoreModuleHob;
  LIST_ENTRY                    *Link;
  EFI_MM_DRIVER_ENTRY           *DriverEntry;

  EFI_HOB_GUID_TYPE           *DepexHob;
  MM_SUPV_DEPEX_HOB_DATA  *DepexHobData;
  EFI_PHYSICAL_ADDRESS OriginalBase = BaseAddress;

  if (BaseAddress == 0 || Length == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_INFO, "%a\n", __func__));

  NewLength = ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8) * 2; // For MM Core and MM User
  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);
    NewLength += ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);
    NewLength += ALIGN_VALUE (sizeof (EFI_HOB_GUID_TYPE) + sizeof (MM_SUPV_DEPEX_HOB_DATA) + DriverEntry->DepexSize, 8);
  }

  if (*Length < NewLength) {
    *Length = NewLength;
    return EFI_BUFFER_TOO_SMALL;
  }

  OriginalBase = BaseAddress;

  // First Module Hob for MM Core
  MmCoreModuleHob = (EFI_HOB_MEMORY_ALLOCATION_MODULE *)(UINTN)BaseAddress;
  CopyGuid (&MmCoreModuleHob->MemoryAllocationHeader.Name, &gMmSupervisorHobMemoryAllocModuleGuid);
  MmCoreModuleHob->MemoryAllocationHeader.MemoryBaseAddress = (EFI_PHYSICAL_ADDRESS)(mMmCoreDriverEntry->ImageBuffer);
  MmCoreModuleHob->MemoryAllocationHeader.MemoryLength      = EFI_PAGES_TO_SIZE(mMmCoreDriverEntry->NumberOfPage);
  MmCoreModuleHob->MemoryAllocationHeader.MemoryType        = EfiReservedMemoryType;
  ZeroMem (MmCoreModuleHob->MemoryAllocationHeader.Reserved, sizeof (MmCoreModuleHob->MemoryAllocationHeader.Reserved));

  CopyGuid (&MmCoreModuleHob->ModuleName, &gMmSupervisorCoreGuid);
  MmCoreModuleHob->EntryPoint = mMmCoreDriverEntry->ImageEntryPoint;

  MmCoreModuleHob->Header.HobType    = EFI_HOB_TYPE_MEMORY_ALLOCATION;
  MmCoreModuleHob->Header.HobLength  = ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);
  MmCoreModuleHob->Header.Reserved   = 0;

  // Move to next HOB location
  BaseAddress += ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);

  // Second Module Hob for MM User
  MmCoreModuleHob = (EFI_HOB_MEMORY_ALLOCATION_MODULE *)(UINTN)BaseAddress;
  CopyGuid (&MmCoreModuleHob->MemoryAllocationHeader.Name, &gMmSupervisorHobMemoryAllocModuleGuid);
  MmCoreModuleHob->MemoryAllocationHeader.MemoryBaseAddress = (EFI_PHYSICAL_ADDRESS)(mMmUserDriverEntry->ImageBuffer);
  MmCoreModuleHob->MemoryAllocationHeader.MemoryLength      = EFI_PAGES_TO_SIZE(mMmUserDriverEntry->NumberOfPage);
  MmCoreModuleHob->MemoryAllocationHeader.MemoryType        = EfiReservedMemoryType;
  ZeroMem (MmCoreModuleHob->MemoryAllocationHeader.Reserved, sizeof (MmCoreModuleHob->MemoryAllocationHeader.Reserved));

  CopyGuid (&MmCoreModuleHob->ModuleName, &gMmSupervisorUserGuid);
  MmCoreModuleHob->EntryPoint = mMmUserDriverEntry->ImageEntryPoint;

  MmCoreModuleHob->Header.HobType    = EFI_HOB_TYPE_MEMORY_ALLOCATION;
  MmCoreModuleHob->Header.HobLength  = ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);
  MmCoreModuleHob->Header.Reserved   = 0;

  // Move to next HOB location
  BaseAddress += ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);

  // Other Module Hobs for Discovered Drivers
  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_MM_DRIVER_ENTRY, Link, EFI_MM_DRIVER_ENTRY_SIGNATURE);

    MmCoreModuleHob = (EFI_HOB_MEMORY_ALLOCATION_MODULE *)(UINTN)BaseAddress;
    CopyGuid (&MmCoreModuleHob->MemoryAllocationHeader.Name, &gMmSupervisorHobMemoryAllocModuleGuid);
    MmCoreModuleHob->MemoryAllocationHeader.MemoryBaseAddress = (EFI_PHYSICAL_ADDRESS)(DriverEntry->ImageBuffer);
    MmCoreModuleHob->MemoryAllocationHeader.MemoryLength      = EFI_PAGES_TO_SIZE(DriverEntry->NumberOfPage);
    MmCoreModuleHob->MemoryAllocationHeader.MemoryType        = EfiReservedMemoryType;
    ZeroMem (MmCoreModuleHob->MemoryAllocationHeader.Reserved, sizeof (MmCoreModuleHob->MemoryAllocationHeader.Reserved));

    CopyGuid (&MmCoreModuleHob->ModuleName, &DriverEntry->FileName);
    MmCoreModuleHob->EntryPoint = DriverEntry->ImageEntryPoint;

    MmCoreModuleHob->Header.HobType    = EFI_HOB_TYPE_MEMORY_ALLOCATION;
    MmCoreModuleHob->Header.HobLength  = ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);
    MmCoreModuleHob->Header.Reserved   = 0;

    // Move to next HOB location
    BaseAddress += ALIGN_VALUE (sizeof (EFI_HOB_MEMORY_ALLOCATION_MODULE), 8);

    // Create DEPEX HOB for Discovered Driver
    DepexHob = (EFI_HOB_GUID_TYPE *)(UINTN)BaseAddress;
    CopyGuid (&DepexHob->Name, &gMmSupervisorDepexHobGuid);
    DepexHob->Header.HobType  = EFI_HOB_TYPE_GUID_EXTENSION;
    DepexHob->Header.HobLength = (UINT16)ALIGN_VALUE (sizeof (EFI_HOB_GUID_TYPE) + sizeof (MM_SUPV_DEPEX_HOB_DATA) + DriverEntry->DepexSize, 8);
    DepexHob->Header.Reserved = 0;

    DepexHobData = (MM_SUPV_DEPEX_HOB_DATA *)(DepexHob + 1);
    CopyGuid (&DepexHobData->Name, &DriverEntry->FileName);
    DepexHobData->Length = DriverEntry->DepexSize;
    if (DriverEntry->DepexSize != 0) {
      CopyMem (DepexHobData->Data, DriverEntry->Depex, DriverEntry->DepexSize);
    }

    // Move to next HOB location
    BaseAddress += ALIGN_VALUE (sizeof (EFI_HOB_GUID_TYPE) + sizeof (MM_SUPV_DEPEX_HOB_DATA) + DriverEntry->DepexSize, 8);
  }

  ASSERT ((UINTN)(BaseAddress - OriginalBase) == NewLength);

  *Length      = *Length - NewLength;

  return EFI_SUCCESS;
}

EFI_STATUS
CreateArbitraryHob (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN OUT UINT64            *Length
  )
{
  UINTN                             NewLength;
  EFI_HOB_GUID_TYPE                 *GuidedHob;
  MM_SUPV_PASS_DOWN_HOB_DATA  *PassDownData;

  if (BaseAddress == 0 || Length == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  NewLength = ALIGN_VALUE (sizeof (EFI_HOB_GUID_TYPE) + sizeof (MM_SUPV_PASS_DOWN_HOB_DATA), 8);

  if (*Length < NewLength) {
    *Length = NewLength;
    return EFI_BUFFER_TOO_SMALL;
  }

  // First Module Hob for MM Core
  GuidedHob = (EFI_HOB_GUID_TYPE *)(UINTN)BaseAddress;
  CopyGuid (&GuidedHob->Name, &gMmSupervisorPassDownHobGuid);
  GuidedHob->Header.HobLength = ALIGN_VALUE (sizeof (EFI_HOB_GUID_TYPE) + sizeof (MM_SUPV_PASS_DOWN_HOB_DATA), 8);
  GuidedHob->Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  GuidedHob->Header.Reserved  = 0;

  PassDownData = (MM_SUPV_PASS_DOWN_HOB_DATA *)(GuidedHob + 1);
  PassDownData->Revision = MM_SUPV_PASS_DOWN_HOB_REVISION;
  PassDownData->Reserved = 0;
  PassDownData->MmSupvCpuPrivate = (EFI_PHYSICAL_ADDRESS)AllocateCopyPool (sizeof (*gSmmCpuPrivate), (VOID *)gSmmCpuPrivate);
  PassDownData->MmSupvCpuPrivateSize = sizeof (*gSmmCpuPrivate);

  // PassDownData->MmSupvCommBuffer = (EFI_PHYSICAL_ADDRESS)mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].PhysicalStart;
  // PassDownData->MmSupvCommBufferInternal = (EFI_PHYSICAL_ADDRESS)mInternalCommBufferCopy[MM_SUPERVISOR_BUFFER_T];
  // PassDownData->MmSupvCommBufferSize = mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].NumberOfPages * EFI_PAGE_SIZE;

  // PassDownData->MmUserCommBuffer = (EFI_PHYSICAL_ADDRESS)mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].PhysicalStart;
  // PassDownData->MmUserCommBufferInternal = (EFI_PHYSICAL_ADDRESS)mInternalCommBufferCopy[MM_USER_BUFFER_T];
  // PassDownData->MmUserCommBufferSize = mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages * EFI_PAGE_SIZE;

  // PassDownData->MmSupvStatusBuffer = (EFI_PHYSICAL_ADDRESS)mMmCommMailboxBufferStatus;

  // PassDownData->MmSupvToUserBuffer = (EFI_PHYSICAL_ADDRESS)SupervisorToUserDataBuffer;
  // PassDownData->MmSupvToUserBufferSize = EFI_PAGES_TO_SIZE (DEFAULT_SUPV_TO_USER_BUFFER_PAGE);

  PassDownData->MmInitializedBuffer = (EFI_PHYSICAL_ADDRESS)mSmmInitialized;

  PassDownData->MmSupervisorCpl3StackBase = (EFI_PHYSICAL_ADDRESS)mSmmCpl3StackArrayBase;
  PassDownData->MmSupervisorCpl3PerCoreStackSize = mSmmStackSize;

  PassDownData->MmSupvFirmwarePolicyBuffer = (EFI_PHYSICAL_ADDRESS)FirmwarePolicy;
  PassDownData->MmSupvFirmwarePolicyBufferSize = FirmwarePolicy->Size;

  PassDownData->BspMmBaseAddress = (EFI_PHYSICAL_ADDRESS)mCpuHotPlugData.SmBase[0];
  PassDownData->MmiEntrypointSize = mMmiEntrySize;

  *Length      = *Length - NewLength;

  return EFI_SUCCESS;
}

INTN
EFIAPI
CompareMmramRangeCpuStart (
  IN CONST VOID                 *MmramDescriptor1,
  IN CONST VOID                 *MmramDescriptor2
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

  // // Prepare the buffer for Mem policy snapshot, it will be compared against when non-MM entity requested
  // Status = AllocateMemForPolicySnapshot (&MemPolicySnapshot);
  // if (EFI_ERROR (Status)) {
  //   DEBUG ((DEBUG_ERROR, "%a Failed to allocate buffer for memory policy snapshot - %r\n", __func__, Status));
  //   ASSERT_EFI_ERROR (Status);
  //   goto Done;
  // }

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
  EFI_STATUS                      Status;
  UINTN                           Index;
  // VOID                            *Registration;
  EFI_HOB_GUID_TYPE               *MmramRangesHob;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *MmramRangesHobData;
  EFI_MMRAM_DESCRIPTOR            *MmramRanges;
  EFI_MMRAM_DESCRIPTOR            MmDescDummy;
  UINTN                           MmramRangeCount;
  UINT64                          StartTicker;
  UINT64                          EndTicker;
  EFI_PHYSICAL_ADDRESS            StandaloneBfvAddress;

  MmSupervisorCoreEntryInit ();

  DEBUG ((DEBUG_INFO, "MmMain - 0x%x\n", HobStart));

  //
  // Extract the MMRAM ranges from the MMRAM descriptor HOB
  //
  MmramRangesHob = GetNextGuidHob (&gEfiMmPeiMmramMemoryReserveGuid, HobStart);
  if (MmramRangesHob == NULL) {
    MmramRangesHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
    if (MmramRangesHob == NULL) {
      Status =  EFI_UNSUPPORTED;
      goto Exit;
    }
  }

  MmramRangesHobData = GET_GUID_HOB_DATA (MmramRangesHob);
  if (MmramRangesHobData == NULL) {
    ASSERT (MmramRangesHobData != NULL);
    Status =  EFI_NOT_FOUND;
    goto Exit;
  }

  MmramRanges     = MmramRangesHobData->Descriptor;
  MmramRangeCount = (UINTN)MmramRangesHobData->NumberOfMmReservedRegions;
  if ((MmramRanges == NULL) || (MmramRangeCount == 0)) {
    ASSERT (MmramRanges);
    ASSERT (MmramRangeCount);
    Status =  EFI_NOT_FOUND;
    goto Exit;
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
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  CopyMem (mMmramRanges, (VOID *)(UINTN)MmramRanges, mMmramRangeCount * sizeof (EFI_MMRAM_DESCRIPTOR));

  // Sort the Mmram ranges by CpuStart address
  QuickSort (
    MmramRanges,
    MmramRangeCount,
    sizeof (EFI_MMRAM_DESCRIPTOR),
    CompareMmramRangeCpuStart,
    &MmDescDummy
    );

  ProcessLibraryConstructorList (HobStart, &gMmCoreMmst);

  //
  // Discover Standalone MM drivers for dispatch
  //
  StartTicker = GetPerformanceCounter ();
  Status      = DiscoverStandaloneMmDriversInFvHobs (&StandaloneBfvAddress);
  EndTicker   = GetPerformanceCounter ();
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    goto Exit;
  }

  EFI_PHYSICAL_ADDRESS  MmSupervisorHobStart;
  UINTN                 MmSupervisorHobSize;
  UINTN                 InitialMmHobSize;
  UINTN                 RemainingSize;

  //
  // Install HobList
  //
  DEBUG ((DEBUG_INFO, "gHobList - 0x%p\n", gHobList));
  InitialMmHobSize = GetHobListSize (gHobList);
  DEBUG ((DEBUG_INFO, "HobSize - 0x%x\n", InitialMmHobSize));

  MmSupervisorHobSize = 0;
  Status = PrepareMmSupervisorHobs (0, &MmSupervisorHobSize);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_ERROR, "%a Failed to get MM Supervisor allocation hob size - Status %d\n", __func__, Status));
    ASSERT (FALSE);
    PANIC ("Failed to prepare MM Supervisor hobs");
  }

  mMmHobSize = InitialMmHobSize + MmSupervisorHobSize;

  // Note: Allocate an extra page to avoid Hob overlapping with other memory
  // This page is supposed to cover all the subsequent allocations during hob creation, page table setup, allocation module hob, etc.
  mMmHobSize = ALIGN_VALUE (mMmHobSize, EFI_PAGE_SIZE);
  mMmHobSize += EFI_PAGE_SIZE;

  Status = (EFI_PHYSICAL_ADDRESS)(UINTN)MmAllocateSupervisorPages (AllocateAnyPages, EfiRuntimeServicesData, EFI_SIZE_TO_PAGES (mMmHobSize), &MmSupervisorHobStart);
  if (EFI_ERROR (Status)) {
    PANIC ("Failed to allocate MM Supervisor hob memory");
  } else {
    DEBUG ((DEBUG_INFO, "%a Allocated MM Supervisor Hob at 0x%p with size 0x%x\n", __func__, (VOID *)(UINTN)MmSupervisorHobStart, mMmHobSize));
  }

  // Copy existing hob list to MM Supervisor hob
  mMmHobStart = (VOID *)(UINTN)MmSupervisorHobStart;

  ZeroMem ((VOID *)(UINTN)MmSupervisorHobStart, (UINTN)mMmHobSize);
  RemainingSize = mMmHobSize;

  // Copy existing hob list
  EFI_PEI_HOB_POINTERS  Hob;

  InitialMmHobSize = 0;
  Hob.Raw = (UINT8 *)gHobList;
  while (!END_OF_HOB_LIST (Hob)) {
    UINTN  HobSize;
    HobSize = GET_HOB_LENGTH (Hob);
    if (InitialMmHobSize + ALIGN_VALUE (HobSize, 8) > mMmHobSize) {
      DEBUG ((DEBUG_ERROR, "%a MM Supervisor Hob size 0x%x is not enough to copy existing hob list, need at least 0x%x\n", __func__, mMmHobSize, InitialMmHobSize + ALIGN_VALUE (HobSize, 8)));
      ASSERT (FALSE);
      PANIC ("MM Supervisor Hob size insufficient");
    }

    // Filter out the MmRam Hob as we will recreate it later
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_GUID_EXTENSION) {
      EFI_GUID  *HobGuid;
      HobGuid = &((EFI_HOB_GUID_TYPE *)Hob.Raw)->Name;
      if (CompareGuid (HobGuid, &gEfiMmPeiMmramMemoryReserveGuid) ||
          CompareGuid (HobGuid, &gEfiSmmSmramMemoryGuid)) {
        DEBUG ((DEBUG_INFO, "%a Skip Copying MmRam Hob Type 0x%x Size 0x%x\n", __func__, GET_HOB_TYPE (Hob), HobSize));
        Hob.Raw = GET_NEXT_HOB (Hob);
        continue;
      }
    }

    DEBUG ((DEBUG_INFO, "%a Copy Hob Type 0x%x Size 0x%x into offset 0x%x\n", __func__, GET_HOB_TYPE (Hob), HobSize, InitialMmHobSize));
    CopyMem ((VOID *)((UINTN)MmSupervisorHobStart + InitialMmHobSize), (VOID *)Hob.Raw, HobSize);
    InitialMmHobSize += ALIGN_VALUE (HobSize, 8);
    Hob.Raw = GET_NEXT_HOB (Hob);
  }
  RemainingSize -= ALIGN_VALUE (InitialMmHobSize, 8);

  Status = SetupSmiEntryExit ();
  if (EFI_ERROR (Status)) {
    // Should not happen
    DEBUG ((DEBUG_ERROR, "Configuring SMI entry and exit failed - %r\n", Status));
    ASSERT (FALSE);
    goto Exit;
  }

  MmLoadButNotDispatch ();

  // Add memory allocation module hob for core and user modules
  CreateMemoryAllocationModuleHob ((EFI_PHYSICAL_ADDRESS)(MmSupervisorHobStart + ALIGN_VALUE (InitialMmHobSize, 8)), &RemainingSize);

  Status = PrepareCommonBuffers ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to prepare comm buffer - Status %d\n", __func__, Status));
    ASSERT (FALSE);
    goto Exit;
  }

  InitializePolicy (StandaloneBfvAddress);

  CreateArbitraryHob ((EFI_PHYSICAL_ADDRESS)(MmSupervisorHobStart + ALIGN_VALUE (mMmHobSize - RemainingSize, 8)), &RemainingSize);

  LockMmCoreBeforeExit (MmSupervisorHobStart + mMmHobSize - RemainingSize, &RemainingSize);

  // Adding the end of HOB list
  VOID* EndHob = (VOID *)(MmSupervisorHobStart + mMmHobSize - RemainingSize);

  if (RemainingSize < ALIGN_VALUE (sizeof (EFI_HOB_GENERIC_HEADER), 8)) {
    DEBUG ((DEBUG_ERROR, "%a MM Supervisor Hob size 0x%x is not enough to add end of hob list, need at least 0x%x\n", __func__, mMmHobSize, ALIGN_VALUE (sizeof (EFI_HOB_GENERIC_HEADER), 8)));
    ASSERT (FALSE);
    PANIC ("MM Supervisor Hob size insufficient for end hob");
  }

  ((EFI_HOB_GENERIC_HEADER *)EndHob)->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  ((EFI_HOB_GENERIC_HEADER *)EndHob)->HobLength = (UINT16)ALIGN_VALUE (sizeof (EFI_HOB_GENERIC_HEADER), 8);
  ((EFI_HOB_GENERIC_HEADER *)EndHob)->Reserved  = 0;

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
