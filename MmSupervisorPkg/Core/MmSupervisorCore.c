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
#include "Handler/Handler.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"
#include "Telemetry/Telemetry.h"
#include "Test/Test.h"

#include <Protocol/MmBase.h>
#include <Protocol/PiPcd.h>

#include <Guid/MmCommonRegion.h>
#include <Library/SecurePolicyLib.h>

EFI_STATUS
MmCoreFfsFindMmDriver (
  IN  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader
  );

EFI_STATUS
MmDispatcher (
  VOID
  );

//
// Globals used to initialize the protocol
//
EFI_HANDLE  mMmCpuHandle = NULL;

//
// Physical pointer to private structure shared between MM IPL and the MM Core
//
MM_CORE_PRIVATE_DATA  gMmCorePrivate;
MM_CORE_PRIVATE_DATA  *gMmCoreMailbox = NULL;

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
  MmInstallConfigurationTable,
  // I/O Service
  {
    {
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5,        // MmMemRead
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5         // MmMemWrite
    },
    {
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5,        // MmIoRead
      (EFI_MM_CPU_IO)MmEfiNotAvailableYetArg5         // MmIoWrite
    }
  },
  // Runtime memory services
  MmAllocateSupervisorPool,
  MmFreeSupervisorPool,
  MmAllocateSupervisorPages,
  MmFreePages,
  // MP service
  NULL,                          // MmStartupThisAp
  0,                             // CurrentlyExecutingCpu
  0,                             // NumberOfCpus
  NULL,                          // CpuSaveStateSize
  NULL,                          // CpuSaveState
  0,                             // NumberOfTableEntries
  NULL,                          // MmConfigurationTable
  MmInstallProtocolInterface,
  MmUninstallProtocolInterface,
  MmHandleProtocol,
  MmRegisterProtocolNotify,
  MmLocateHandle,
  MmLocateProtocol,
  MmiManage,
  MmiSupvHandlerRegister,
  MmiHandlerSupvUnRegister
};

EFI_MEMORY_DESCRIPTOR  mMmSupervisorAccessBuffer[MM_OPEN_BUFFER_CNT];

//
// Table of MMI Handlers that are registered by the MM Core when it is initialized
//
MM_CORE_MMI_HANDLERS  mMmCoreMmiHandlers[] = {
  { MmDriverDispatchHandler, &gMmSupervisorDriverDispatchGuid,  NULL, TRUE  },
  { MmReadyToLockHandler,    &gEfiDxeMmReadyToLockProtocolGuid, NULL, TRUE  },
  { MmSupvRequestHandler,    &gMmSupervisorRequestHandlerGuid,  NULL, FALSE },
  { NULL,                    NULL,                              NULL, FALSE },
};

EFI_SYSTEM_TABLE                  *mEfiSystemTable;
UINTN                             mMmramRangeCount;
EFI_MMRAM_DESCRIPTOR              *mMmramRanges;
EFI_MM_DRIVER_ENTRY               *mMmCoreDriverEntry;
MM_SUPV_USER_COMMON_BUFFER        *SupervisorToUserDataBuffer = NULL;
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

/*
Function to extract common buffers to be used for both user handlers and supervisor handlers.

Note: In SCPC implementation, any attempt in triggering MMI handler without using the pre-
allocated buffer will be treated as a potential security violation.

*/
EFI_STATUS
EFIAPI
PrepareCommonBuffers (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS   GuidHob;
  MM_COMM_REGION_HOB     *CommRegionHob;
  EFI_STATUS             Status;
  UINTN                  Index;
  VOID                   *HobData;
  MM_CORE_DATA_HOB_DATA  *DataInHob;

  for (Index = 0; Index < MM_OPEN_BUFFER_CNT; Index++) {
    ZeroMem (&mMmSupervisorAccessBuffer[Index], sizeof (EFI_MEMORY_DESCRIPTOR));
  }

  GuidHob.Guid = GetFirstGuidHob (&gMmCommonRegionHobGuid);
  while (GuidHob.Guid != NULL) {
    CommRegionHob = GET_GUID_HOB_DATA (GuidHob.Guid);
    if (CommRegionHob->MmCommonRegionType < MM_OPEN_BUFFER_CNT) {
      if (mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart != 0) {
        DEBUG ((DEBUG_ERROR, "%a - Duplicated hobs for type %x!!\n", __FUNCTION__, CommRegionHob->MmCommonRegionType));
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
          __FUNCTION__,
          mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart,
          CommRegionHob->MmCommonRegionType
          ));
        Status = EFI_BAD_BUFFER_SIZE;
        ASSERT (FALSE);
        goto Exit;
      }

      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart = CommRegionHob->MmCommonRegionAddr;
      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].NumberOfPages = CommRegionHob->MmCommonRegionPages;
      // But the memory itself is allocated under reserved..
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
        DEBUG ((DEBUG_ERROR, "%a - Failed to allocate internal buffer copy, please consider adjust TSEG size... - %r\n", __FUNCTION__, Status));
        goto Exit;
      }

      mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].VirtualStart = 0;
      DEBUG ((
        DEBUG_INFO,
        "%a - Populating MM Access Buffer Type %d to 0x%p with 0x%x pages\n",
        __FUNCTION__,
        CommRegionHob->MmCommonRegionType,
        mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].PhysicalStart,
        mMmSupervisorAccessBuffer[CommRegionHob->MmCommonRegionType].NumberOfPages
        ));
    }

    GuidHob.Guid = GET_NEXT_HOB (GuidHob);
    GuidHob.Guid = GetNextGuidHob (&gMmCommonRegionHobGuid, GuidHob.Guid);
  }

  Status = MmAllocatePages (
             AllocateAnyPages,
             EfiRuntimeServicesData,
             DEFAULT_SUPV_TO_USER_BUFFER_PAGE,
             (EFI_PHYSICAL_ADDRESS *)&SupervisorToUserDataBuffer
             );
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to allocate supervisor to user buffer, cannot continue...\n", __FUNCTION__));
    goto Exit;
  }

  // Here we disclose some fundamental information to ring 3 world, such as MmRanges
  ZeroMem (SupervisorToUserDataBuffer, sizeof (MM_SUPV_USER_COMMON_BUFFER));
  SupervisorToUserDataBuffer->gMmCorePrivateDummy.MmramRangeCount = gMmCorePrivate.MmramRangeCount;
  Status                                                          = MmAllocatePages (
                                                                      AllocateAnyPages,
                                                                      EfiRuntimeServicesData,
                                                                      EFI_SIZE_TO_PAGES (gMmCorePrivate.MmramRangeCount * sizeof (EFI_MMRAM_DESCRIPTOR)),
                                                                      &(SupervisorToUserDataBuffer->gMmCorePrivateDummy.MmramRanges)
                                                                      );
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to allocate supervisor to user buffer, cannot continue...\n", __FUNCTION__));
    goto Exit;
  }

  CopyMem (
    (VOID *)SupervisorToUserDataBuffer->gMmCorePrivateDummy.MmramRanges,
    (VOID *)gMmCorePrivate.MmramRanges,
    gMmCorePrivate.MmramRangeCount * sizeof (EFI_MMRAM_DESCRIPTOR)
    );
  HobData = GetNextGuidHob (&gMmCoreDataHobGuid, mMmHobStart);
  if (HobData != NULL) {
    // Only relink the dummy private data if needed
    DataInHob          = GET_GUID_HOB_DATA (HobData);
    DataInHob->Address = (EFI_PHYSICAL_ADDRESS)(UINTN)SupervisorToUserDataBuffer;
  }

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to prepare communicate buffer for Standalone MM environment... - %r\n", __FUNCTION__, Status));
  }

  return Status;
}

/**
  Software MMI handler that should be triggered from non-MM environment upon DxeMmReadyToLock
  event. This function unregisters the SUPERVISOR MMIs that are not required after Ready To Lock
  event. Certain features, such as unblock memory regions, will not be available after this point.

  Note: User ready to lock event will be notified prior to this supervisor ready to lock event.
  This order is controlled in the corresponding DXE agent (IPL and/or DxeSupport driver).

  @param  DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-MM environment into an MM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
MmReadyToLockHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINTN       Index;

  PERF_CALLBACK_BEGIN (&gEfiDxeMmReadyToLockProtocolGuid);

  DEBUG ((DEBUG_INFO, "MmReadyToLockHandler\n"));

  //
  // Unregister MMI Handlers that are no longer required after the MM driver dispatch is stopped
  //
  for (Index = 0; mMmCoreMmiHandlers[Index].HandlerType != NULL; Index++) {
    if (mMmCoreMmiHandlers[Index].UnRegister) {
      Status = MmiHandlerSupvUnRegister (mMmCoreMmiHandlers[Index].DispatchHandle);
      if (EFI_ERROR (Status)) {
        DEBUG ((
          DEBUG_ERROR,
          "Failed to unregister supervisor handler No. %d %g - %r\n",
          Index,
          mMmCoreMmiHandlers[Index].HandlerType,
          Status
          ));
      }
    }
  }

  // All drivers has been dispatched, recycle all the buffers allocated for ffs driver caching
  Status = RecycleFfsBuffer ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to recycle ffs buffer at ready to lock - %r\n", Status));
    ASSERT_EFI_ERROR (Status);
  }

  // If MMI handler profile is supported, traverse them after unregistering
  // Since this is after the CPL3 ready to lock event completely, thus whatever
  // remains will be the one impacting runtime.
  if ((PcdGet8 (PcdSmiHandlerProfilePropertyMask) & 0x1) != 0) {
    SmmReadyToLockInSmiHandlerProfile (NULL, NULL, NULL);
  }

  Status = PrepareMemPolicySnapshot (MemPolicySnapshot);

  mMmReadyToLockDone = TRUE;

  PERF_CALLBACK_END (&gEfiDxeMmReadyToLockProtocolGuid);

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
  The main entry point to MM Foundation.

  Note: This function is only used by MMRAM invocation.  It is never used by DXE invocation.

  @param  MmEntryContext           Processor information and functionality
                                    needed by MM Foundation.

**/
VOID
EFIAPI
MmEntryPoint (
  IN CONST EFI_MM_ENTRY_CONTEXT  *MmEntryContext
  )
{
  EFI_STATUS                 Status;
  EFI_MM_COMMUNICATE_HEADER  *CommunicateHeader;
  EFI_PHYSICAL_ADDRESS       CommunicationBuffer;
  UINT64                     BufferSize;

  PERF_FUNCTION_BEGIN ();

  DEBUG ((DEBUG_VERBOSE, "MmEntryPoint ...\n"));

  //
  // Update MMST using the context
  //
  CopyMem (&gMmCoreMmst.MmStartupThisAp, MmEntryContext, sizeof (EFI_MM_ENTRY_CONTEXT));
  SyncMmEntryContextToCpl3 ();

  //
  // Mark the InMm flag as TRUE
  //
  if (gMmCoreMailbox != NULL) {
    gMmCoreMailbox->InMm = TRUE;
    CopyMem (&gMmCorePrivate, gMmCoreMailbox, sizeof (MM_CORE_PRIVATE_DATA));
  }

  gMmCorePrivate.InMm = TRUE;

  //
  // Check to see if this is a Synchronous MMI sent through the MM Communication
  // Protocol or an Asynchronous MMI
  //
  CommunicationBuffer = (EFI_PHYSICAL_ADDRESS)(UINTN)gMmCorePrivate.CommunicationBuffer;
  BufferSize          = gMmCorePrivate.BufferSize;
  if ((VOID *)CommunicationBuffer != NULL) {
    //
    // Synchronous MMI for MM Core or request from Communicate protocol
    //
    if ((CommunicationBuffer == mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].PhysicalStart) &&
        (BufferSize <= EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages)))
    {
      //
      // This should be user communicate channel, follow normal user channel iterations, but use ring 3 buffer to hold BufferSize changes
      //
      ZeroMem (mInternalCommBufferCopy[MM_USER_BUFFER_T], EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages));
      CopyMem (mInternalCommBufferCopy[MM_USER_BUFFER_T], (VOID *)(UINTN)CommunicationBuffer, BufferSize);
      CommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *)(UINTN)mInternalCommBufferCopy[MM_USER_BUFFER_T];

      Status = SafeUint64Sub (BufferSize, OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data), &BufferSize);
      if (EFI_ERROR (Status)) {
        gMmCorePrivate.CommunicationBuffer = 0;
        gMmCorePrivate.ReturnStatus        = EFI_ACCESS_DENIED;
        // Note: this will cause another difference compared to PiSmmCore,
        // as the normal one will handle asynchronous MMI sources.
        goto Cleanup;
      }

      SupervisorToUserDataBuffer->gMmCorePrivateDummy.BufferSize = BufferSize;
      Status                                                     = MmiManage (
                                                                     &CommunicateHeader->HeaderGuid,
                                                                     NULL,
                                                                     CommunicateHeader->Data,
                                                                     (UINTN *)&(SupervisorToUserDataBuffer->gMmCorePrivateDummy.BufferSize)
                                                                     );
      //
      // Update CommunicationBuffer, BufferSize and ReturnStatus
      // Communicate service finished, reset the pointer to CommBuffer to NULL
      //
      BufferSize = SupervisorToUserDataBuffer->gMmCorePrivateDummy.BufferSize +
                   OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
      if (BufferSize <= EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_USER_BUFFER_T].NumberOfPages)) {
        CopyMem ((VOID *)(UINTN)CommunicationBuffer, CommunicateHeader, BufferSize);
      } else {
        // The returned buffer size indicating the return buffer is larger than input buffer, need to panic here.
        DEBUG ((DEBUG_ERROR, "%a Returned buffer size is larger than maximal allowed size indicated in input, something is off...\n", __FUNCTION__));
        ASSERT (FALSE);
      }

      gMmCorePrivate.BufferSize          = BufferSize;
      gMmCorePrivate.CommunicationBuffer = 0;
      gMmCorePrivate.ReturnStatus        = (Status == EFI_SUCCESS) ? EFI_SUCCESS : EFI_NOT_FOUND;
    } else if ((CommunicationBuffer == mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].PhysicalStart) &&
               (BufferSize <= EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].NumberOfPages)))
    {
      //
      // This should be supervisor communicate channel, everything can be ring 0 buffer fine
      //
      ZeroMem (mInternalCommBufferCopy[MM_SUPERVISOR_BUFFER_T], EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].NumberOfPages));
      CopyMem (mInternalCommBufferCopy[MM_SUPERVISOR_BUFFER_T], (VOID *)(UINTN)CommunicationBuffer, BufferSize);
      CommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *)(UINTN)mInternalCommBufferCopy[MM_SUPERVISOR_BUFFER_T];

      Status = SafeUint64Sub (BufferSize, OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data), &BufferSize);
      if (EFI_ERROR (Status)) {
        gMmCorePrivate.CommunicationBuffer = 0;
        gMmCorePrivate.ReturnStatus        = EFI_ACCESS_DENIED;
        goto Cleanup;
      }

      Status = MmiManage (
                 &CommunicateHeader->HeaderGuid,
                 NULL,
                 CommunicateHeader->Data,
                 (UINTN *)&BufferSize
                 );
      //
      // Update CommunicationBuffer, BufferSize and ReturnStatus
      // Communicate service finished, reset the pointer to CommBuffer to NULL
      //
      BufferSize = BufferSize + OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
      if (BufferSize <= EFI_PAGES_TO_SIZE (mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].NumberOfPages)) {
        CopyMem ((VOID *)(UINTN)mMmSupervisorAccessBuffer[MM_SUPERVISOR_BUFFER_T].PhysicalStart, CommunicateHeader, BufferSize);
      } else {
        // The returned buffer size indicating the return buffer is larger than input buffer, need to panic here.
        DEBUG ((DEBUG_ERROR, "%a Returned buffer size is larger than maximal allowed size indicated in input, something is off...\n", __FUNCTION__));
        ASSERT (FALSE);
      }

      gMmCorePrivate.BufferSize          = BufferSize;
      gMmCorePrivate.CommunicationBuffer = 0;
      gMmCorePrivate.ReturnStatus        = (Status == EFI_SUCCESS) ? EFI_SUCCESS : EFI_NOT_FOUND;
      //
      // Do not handle asynchronous MMI sources. This cannot be it...
      //
      goto Cleanup;
    } else {
      //
      // If CommunicationBuffer is not in valid address scope, return EFI_ACCESS_DENIED
      //
      gMmCorePrivate.CommunicationBuffer = 0;
      gMmCorePrivate.ReturnStatus        = EFI_ACCESS_DENIED;
    }
  }

  //
  // Process Asynchronous MMI sources
  //
  MmiManage (NULL, NULL, NULL, NULL);

  //
  // TBD: Do not use private data structure ?
  //

Cleanup:
  //
  // Clear the InMm flag as we are going to leave MM
  //
  gMmCorePrivate.InMm = FALSE;
  if (gMmCoreMailbox != NULL) {
    CopyMem (gMmCoreMailbox, &gMmCorePrivate, sizeof (MM_CORE_PRIVATE_DATA));
    gMmCoreMailbox->InMm = FALSE;
  }

  DEBUG ((DEBUG_VERBOSE, "MmEntryPoint Done\n"));

  PERF_FUNCTION_END ();
}

EFI_STATUS
EFIAPI
MmConfigurationMmNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EFI_STATUS                     Status;
  EFI_MM_CONFIGURATION_PROTOCOL  *MmConfiguration;

  DEBUG ((DEBUG_INFO, "MmConfigurationMmNotify(%g) - %x\n", Protocol, Interface));

  MmConfiguration = Interface;

  //
  // Register the MM Entry Point provided by the MM Core with the MM COnfiguration protocol
  //
  Status = MmConfiguration->RegisterMmEntry (MmConfiguration, (EFI_MM_ENTRY_POINT)(UINTN)gMmCorePrivate.MmEntryPoint);
  ASSERT_EFI_ERROR (Status);

  //
  // Set flag to indicate that the MM Entry Point has been registered which
  // means that MMIs are now fully operational.
  //
  gMmCorePrivate.MmEntryPointRegistered = TRUE;

  //
  // Print debug message showing MM Core entry point address.
  //
  DEBUG ((DEBUG_INFO, "MM Core registered MM Entry Point address %p\n", (VOID *)(UINTN)gMmCorePrivate.MmEntryPoint));
  return EFI_SUCCESS;
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
  Install LoadedImage protocol for MM Core.
**/
VOID
MmCoreInstallLoadedImage (
  VOID
  )
{
  EFI_STATUS  Status;

  //
  // Allocate a Loaded Image Protocol in MM
  //
  Status = MmAllocateSupervisorPool (EfiRuntimeServicesData, sizeof (EFI_MM_DRIVER_ENTRY), (VOID **)&mMmCoreDriverEntry);
  ASSERT_EFI_ERROR (Status);

  ZeroMem (mMmCoreDriverEntry, sizeof (EFI_MM_DRIVER_ENTRY));

  Status = MmAllocateSupervisorPool (EfiRuntimeServicesData, sizeof (EFI_LOADED_IMAGE_PROTOCOL), (VOID **)&mMmCoreDriverEntry->LoadedImage);
  ASSERT_EFI_ERROR (Status);

  ZeroMem (mMmCoreDriverEntry->LoadedImage, sizeof (EFI_LOADED_IMAGE_PROTOCOL));

  //
  // Fill in the remaining fields of the Loaded Image Protocol instance.
  //
  mMmCoreDriverEntry->Signature                 = EFI_MM_DRIVER_ENTRY_SIGNATURE;
  mMmCoreDriverEntry->LoadedImage->Revision     = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
  mMmCoreDriverEntry->LoadedImage->ParentHandle = NULL;
  mMmCoreDriverEntry->LoadedImage->SystemTable  = mEfiSystemTable;
  mMmCoreDriverEntry->LoadedImage->DeviceHandle = NULL;
  mMmCoreDriverEntry->LoadedImage->FilePath     = NULL;

  mMmCoreDriverEntry->LoadedImage->ImageBase     = (VOID *)(UINTN)gMmCorePrivate.MmCoreImageBase;
  mMmCoreDriverEntry->LoadedImage->ImageSize     = gMmCorePrivate.MmCoreImageSize;
  mMmCoreDriverEntry->LoadedImage->ImageCodeType = EfiRuntimeServicesCode;
  mMmCoreDriverEntry->LoadedImage->ImageDataType = EfiRuntimeServicesData;

  mMmCoreDriverEntry->ImageEntryPoint = gMmCorePrivate.MmCoreEntryPoint;
  mMmCoreDriverEntry->ImageBuffer     = gMmCorePrivate.MmCoreImageBase;
  mMmCoreDriverEntry->NumberOfPage    = EFI_SIZE_TO_PAGES ((UINTN)gMmCorePrivate.MmCoreImageSize);

  //
  // Create a new image handle in the MM handle database for the MM Driver
  //
  mMmCoreDriverEntry->ImageHandle = NULL;
  Status                          = gMmCoreMmst.MmInstallProtocolInterface (
                                                  &mMmCoreDriverEntry->ImageHandle,
                                                  &gEfiLoadedImageProtocolGuid,
                                                  EFI_NATIVE_INTERFACE,
                                                  mMmCoreDriverEntry->LoadedImage
                                                  );
  ASSERT_EFI_ERROR (Status);

  return;
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
  VOID
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
        __FUNCTION__,
        (UINTN)FwVolHeader,
        FwVolHeader->FvLength
        ));

      ExtHeaderOffset = ReadUnaligned16 (&FwVolHeader->ExtHeaderOffset);
      if (ExtHeaderOffset != 0) {
        ExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)((UINT8 *)FwVolHeader + ExtHeaderOffset);
        DEBUG ((DEBUG_INFO, "[%a]   FV GUID = {%g}.\n", __FUNCTION__, &ExtHeader->FvName));
      }

      //
      // If a MM_STANDALONE or MM_CORE_STANDALONE driver is in the FV. Add the drivers
      // to the dispatch list. Mark the FV with this driver as the Standalone BFV.
      //
      FileHeader = NULL;
      Status     =  FfsFindNextFile (
                      EFI_FV_FILETYPE_MM_CORE_STANDALONE,
                      FwVolHeader,
                      &FileHeader
                      );
      if (!EFI_ERROR (Status)) {
        if (CompareGuid (&FileHeader->Name, &gMmSupervisorCoreGuid)) {
          gMmCorePrivate.StandaloneBfvAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)FwVolHeader;
          DEBUG ((
            DEBUG_INFO,
            "[%a]   Discovered Standalone MM Core [%g] in FV at 0x%x.\n",
            __FUNCTION__,
            &gEfiCallerIdGuid,
            (UINTN)FwVolHeader
            ));
        }
      } else {
        FileHeader = NULL;
        Status     =  FfsFindNextFile (
                        EFI_FV_FILETYPE_MM_STANDALONE,
                        FwVolHeader,
                        &FileHeader
                        );
      }

      if (!EFI_ERROR (Status)) {
        DEBUG ((
          DEBUG_INFO,
          "[%a]   Adding Standalone MM drivers in FV at 0x%x to the dispatch list.\n",
          __FUNCTION__,
          (UINTN)FwVolHeader
          ));
        Status = MmCoreFfsFindMmDriver (FwVolHeader);
        ASSERT_EFI_ERROR (Status);
      }

      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);

  return EFI_SUCCESS;
}

/**
  Routine for initializing policy data provided by firmware.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval Errors                The supervisor is unable to locate or protect the policy from firmware.

**/
EFI_STATUS
InitializePolicy (
  VOID
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
                (EFI_FIRMWARE_VOLUME_HEADER *)gMmCorePrivate.StandaloneBfvAddress,
                &FileHeader
                );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Failed to locate firmware policy file from given FV - %r\n",
        __FUNCTION__,
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
      __FUNCTION__,
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
        __FUNCTION__,
        Status
        ));
      break;
    }

    PolicySize = ((SMM_SUPV_SECURE_POLICY_DATA_V1_0 *)SectionData)->Size;
    if (PolicySize > SectionDataSize) {
      DEBUG ((
        DEBUG_ERROR,
        "[%a] Policy data size 0x%x > blob size 0x%x.\n",
        __FUNCTION__,
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
        __FUNCTION__,
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
    DEBUG ((DEBUG_ERROR, "%a Unable to locate a valid firmware policy from given FV, bail here - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  // Prepare the buffer for Mem policy snapshot, it will be compared against when non-MM entity requested
  Status = AllocateMemForPolicySnapshot (&MemPolicySnapshot);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to allocate buffer for memory policy snapshot - %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
    goto Done;
  }

  Status = SecurityPolicyCheck (FirmwarePolicy);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Policy check failed on policy blob from firmware - %r\n", __FUNCTION__, Status));
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
  VOID                            *Registration;
  EFI_HOB_GUID_TYPE               *GuidHob;
  MM_CORE_DATA_HOB_DATA           *DataInHob;
  EFI_HOB_GUID_TYPE               *MmramRangesHob;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *MmramRangesHobData;
  EFI_MMRAM_DESCRIPTOR            *MmramRanges;
  UINTN                           MmramRangeCount;
  UINT64                          StartTicker;
  UINT64                          EndTicker;

  DEBUG ((DEBUG_INFO, "MmMain - 0x%x\n", HobStart));

  //
  // Determine if the caller has passed a reference to a MM_CORE_PRIVATE_DATA
  // structure in the Hoblist. This choice will govern how boot information is
  // extracted later.
  //
  GuidHob = GetNextGuidHob (&gMmCoreDataHobGuid, HobStart);
  if (GuidHob == NULL) {
    //
    // Allocate and zero memory for a MM_CORE_PRIVATE_DATA table and then
    // initialise it
    //
    SetMem ((VOID *)&gMmCorePrivate, sizeof (MM_CORE_PRIVATE_DATA), 0);
    gMmCorePrivate.Signature              = MM_CORE_PRIVATE_DATA_SIGNATURE;
    gMmCorePrivate.MmEntryPointRegistered = FALSE;
    gMmCorePrivate.InMm                   = FALSE;
    gMmCorePrivate.ReturnStatus           = EFI_SUCCESS;

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
    ASSERT (MmramRangesHobData != NULL);
    MmramRanges     = MmramRangesHobData->Descriptor;
    MmramRangeCount = (UINTN)MmramRangesHobData->NumberOfMmReservedRegions;
    ASSERT (MmramRanges);
    ASSERT (MmramRangeCount);

    //
    // Copy the MMRAM ranges into MM_CORE_PRIVATE_DATA table just in case any
    // code relies on them being present there
    //
    gMmCorePrivate.MmramRangeCount = (UINT64)MmramRangeCount;
  } else {
    DataInHob      = GET_GUID_HOB_DATA (GuidHob);
    gMmCoreMailbox = (MM_CORE_PRIVATE_DATA *)(UINTN)DataInHob->Address;
    SetMem ((VOID *)&gMmCorePrivate, sizeof (MM_CORE_PRIVATE_DATA), 0);
    CopyMem (&gMmCorePrivate, gMmCoreMailbox, sizeof (MM_CORE_PRIVATE_DATA));
    MmramRanges     = (EFI_MMRAM_DESCRIPTOR *)(UINTN)gMmCorePrivate.MmramRanges;
    MmramRangeCount = (UINTN)gMmCorePrivate.MmramRangeCount;
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
  ASSERT (mMmramRanges != NULL);
  CopyMem (mMmramRanges, (VOID *)(UINTN)MmramRanges, mMmramRangeCount * sizeof (EFI_MMRAM_DESCRIPTOR));

  // Then we can use our own copy of MMRAM ranges
  gMmCorePrivate.MmramRanges  = (EFI_PHYSICAL_ADDRESS)(UINTN)mMmramRanges;
  gMmCorePrivate.Mmst         = (EFI_PHYSICAL_ADDRESS)(UINTN)&gMmCoreMmst;
  gMmCorePrivate.MmEntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)MmEntryPoint;

  DEBUG ((DEBUG_INFO, "MmInstallConfigurationTable For HobList\n"));
  //
  // Install HobList
  //
  mMmHobSize = GetHobListSize (HobStart);
  DEBUG ((DEBUG_INFO, "HobSize - 0x%x\n", mMmHobSize));
  // Allocated Hob data in code intentionally to guarantee it is read only in MM
  Status = MmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, EFI_SIZE_TO_PAGES (mMmHobSize), (EFI_PHYSICAL_ADDRESS *)&mMmHobStart);
  DEBUG ((DEBUG_INFO, "Allocated mMmHobStart: 0x%x - %r\n", mMmHobStart, Status));
  ASSERT_EFI_ERROR (Status);
  CopyMem (mMmHobStart, HobStart, mMmHobSize);
  Status = MmInstallConfigurationTable (&gMmCoreMmst, &gEfiHobListGuid, mMmHobStart, mMmHobSize);
  ASSERT_EFI_ERROR (Status);

  ProcessLibraryConstructorList (HobStart, &gMmCoreMmst);

  //
  // Discover Standalone MM drivers for dispatch
  //
  StartTicker = GetPerformanceCounter ();
  Status      = DiscoverStandaloneMmDriversInFvHobs ();
  EndTicker   = GetPerformanceCounter ();
  ASSERT_EFI_ERROR (Status);
  DEBUG ((
    DEBUG_INFO,
    "Mm Dispatch StandaloneBfvAddress - 0x%08x, consumed %dms.\n",
    gMmCorePrivate.StandaloneBfvAddress,
    (GetTimeInNanoSecond (EndTicker - StartTicker) / 1000000)
    ));

  //
  // Register notification for EFI_MM_CONFIGURATION_PROTOCOL registration and
  // use it to register the MM Foundation entrypoint
  //
  DEBUG ((DEBUG_INFO, "MmRegisterProtocolNotify - MmConfigurationMmProtocol\n"));
  Status = MmRegisterProtocolNotify (
             &gEfiMmConfigurationProtocolGuid,
             MmConfigurationMmNotify,
             &Registration
             );
  ASSERT_EFI_ERROR (Status);

  Status = SetupSmiEntryExit ();
  if (EFI_ERROR (Status)) {
    // Should not happen
    DEBUG ((DEBUG_ERROR, "Configuring SMI entry and exit failed - %r\n", Status));
    ASSERT (FALSE);
  }

  //
  // Register all handlers in the core table
  //
  for (Index = 0; mMmCoreMmiHandlers[Index].HandlerType != NULL; Index++) {
    Status = MmiSupvHandlerRegister (
               mMmCoreMmiHandlers[Index].Handler,
               mMmCoreMmiHandlers[Index].HandlerType,
               &mMmCoreMmiHandlers[Index].DispatchHandle
               );
    DEBUG ((DEBUG_INFO, "MmiHandlerRegister - GUID %g - Status %d\n", mMmCoreMmiHandlers[Index].HandlerType, Status));
  }

  Status = InitializeMmSupervisorTestAgents ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to initialize test agents - Status %d\n", __FUNCTION__, Status));
    ASSERT (FALSE);
    goto Exit;
  }

  Status = PrepareCommonBuffers ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to prepare comm buffer - Status %d\n", __FUNCTION__, Status));
    ASSERT (FALSE);
    goto Exit;
  }

  MmCoreInstallLoadedImage ();

  MmCoreInitializeSmiHandlerProfile ();

  InitializePolicy ();

  CallgateInit (mNumberOfCpus);

  SyscallInterfaceInit (mNumberOfCpus);

  CoalesceLooseExceptionHandlers ();

  LockMmCoreBeforeExit ();

  mCoreInitializationComplete = TRUE;

  if (gMmCoreMailbox != NULL) {
    CopyMem (gMmCoreMailbox, &gMmCorePrivate, sizeof (MM_CORE_PRIVATE_DATA));
  }

  PostRelocationRun ();

  DEBUG ((DEBUG_INFO, "MmMain Done!\n"));

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Standalone MM foundation not properly set, system may not boot - %r!\n", __FUNCTION__, Status));
  }

  return Status;
}
