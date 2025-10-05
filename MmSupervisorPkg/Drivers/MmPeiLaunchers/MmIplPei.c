/** @file
  MM IPL in PEI that produces MM related PPIs and load the MM Core into MMRAM

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>
#include <PiPei.h>

#include <Protocol/SmmCommunication.h>
#include <Ppi/MmAccess.h>
#include <Ppi/MmControl.h>
#include <Ppi/SmmCommunication.h>
#include <Ppi/EndOfPeiPhase.h>
#include <Ppi/MmSupervisorCommunication.h>
#include <Ppi/MmConfiguration.h> // MU_CHANGE: Added MM configuration PPI

#include <Guid/MmCommBuffer.h>
#include <Guid/MmCommonRegion.h>
#include <Guid/EventGroup.h>
#include <Guid/LoadModuleAtFixedAddress.h>
#include <Guid/MmSupervisorRequestData.h> // MU_CHANGE: MM_SUPV: Added MM Supervisor request data structure
#include <Guid/MmramMemoryReserve.h>

#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PanicLib.h>

#include <Library/SafeIntLib.h>           // MU_CHANGE: BZ3398
#include <Library/SecurityLockAuditLib.h> // MSCHANGE
#include <Library/MtrrLib.h>              // MU_CHANGE: MM_SUPV: Mark cachability for MMRAM regions

#include "Common/CommonHeader.h"
#include "Common/MmIplCommon.h"
#ifdef MDE_CPU_IA32
  #include "IA32/X64Loader.h"
#endif

#define SMRAM_CAPABILITIES  (EFI_MEMORY_WB | EFI_MEMORY_UC)

//
// Function prototypes from produced PPIs
//

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The EFI_PEI_SMM_COMMUNICATION_PPI instance.
  @param[in] CommBuffer          A pointer to the buffer to convey into SMRAM.
  @param[in] CommSize            The size of the data buffer being passed in.On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
**/
EFI_STATUS
EFIAPI
SmmCommunicationCommunicate (
  IN CONST EFI_PEI_SMM_COMMUNICATION_PPI  *This,
  IN OUT VOID                             *CommBuffer,
  IN OUT UINTN                            *CommSize
  );

// MU_CHANGE: MM_SUPV: Supervisor communication function prototype

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PPI instance.
  @param[in] CommBuffer          A pointer to the buffer to convey into SMRAM.
  @param[in] CommSize            The size of the data buffer being passed in.On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
**/
EFI_STATUS
EFIAPI
SupvCommunicationCommunicate (
  IN CONST MM_SUPERVISOR_COMMUNICATION_PPI  *This,
  IN OUT VOID                               *CommBuffer,
  IN OUT UINTN                              *CommSize OPTIONAL
  );

/**
  Event notification that is fired when a GUIDed Event Group is signaled.

  @param  PeiServices      Indirect reference to the PEI Services Table.
  @param  NotifyDescriptor Address of the notification descriptor data structure.
  @param  Ppi              Address of the PPI that was installed.

  @return Status of the notification.
          The status code returned from this function is ignored.

**/
EFI_STATUS
EFIAPI
SmmIplGuidedEventNotify (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  );

//
// MM Communication PPI instance
//
EFI_PEI_SMM_COMMUNICATION_PPI  mSmmCommunication = {
  .Communicate = SmmCommunicationCommunicate
};

// MU_CHANGE: MM_SUPV: Supervisor communication PPI instance
//
// Supervisor MM Communication PPI instance
//
MM_SUPERVISOR_COMMUNICATION_PPI  mMmSupvCommunication = {
  .Signature   = MM_SUPERVISOR_COMM_PPI_SIG,
  .Version     = MM_SUPERVISOR_COMM_PPI_VER,
  .Communicate = SupvCommunicationCommunicate
};

//
// List of PPIs to be installed at the success of MM foundation setup
//
STATIC EFI_PEI_PPI_DESCRIPTOR  mPeiMmIplPpiList[] =
{
  {
    EFI_PEI_PPI_DESCRIPTOR_PPI,
    &gEfiPeiSmmCommunicationPpiGuid,
    &mSmmCommunication
  },
  {
    (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
    &gPeiMmSupervisorCommunicationPpiGuid,
    &mMmSupvCommunication
  }
};

//
// SMM IPL global variables
//
EFI_PEI_MM_CONTROL_PPI  *mSmmControl;
EFI_PEI_MM_ACCESS_PPI   *mSmmAccess;
EFI_MMRAM_DESCRIPTOR    *mCurrentMmramRange;
EFI_PHYSICAL_ADDRESS    mMmramCacheBase;
UINT64                  mMmramCacheSize;

// MU_CHANGE: Loaded Fixed Address information is unsupported
// EFI_LOAD_FIXED_ADDRESS_CONFIGURATION_TABLE    *mLMFAConfigurationTable = NULL;

//
// Table of PPI notification and GUIDed Event notifications that the SMM IPL requires
//
STATIC EFI_PEI_NOTIFY_DESCRIPTOR  mPeiMmIplNotifyList =
{
  //
  // Declare event notification on Exit Boot Services Event Group.  This is used to inform the SMM Core
  // to notify SMM driver that system enter exit boot services.
  //
  (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiEndOfPeiSignalPpiGuid,
  SmmIplGuidedEventNotify
};

// MU_CHANGE: Abstracted function implementation of MmControl->Trigger for PEI

/**
  Abstraction layer for MM Control Trigger under various environments (PEI & DXE).
  The IPL driver will implement this functionality to be used by MM Communication
  routine.

  @retval Others            See definition of EFI_MM_ACTIVATE.

 **/
EFI_STATUS
InternalMmControlTrigger (
  VOID
  )
{
  return mSmmControl->Trigger ((EFI_PEI_SERVICES **)GetPeiServicesTablePointer (), mSmmControl, NULL, NULL, FALSE, 0);
}

/**
  Find the maximum SMRAM cache range that covers the range specified by MmramRange.

  This function searches and joins all adjacent ranges of MmramRange into a range to be cached.

  @param   MmramRange       The SMRAM range to search from.
  @param   MmramCacheBase   The returned cache range base.
  @param   MmramCacheSize   The returned cache range size.

**/
VOID
GetMmramCacheRange (
  IN  EFI_MMRAM_DESCRIPTOR  *MmramRange,
  IN  EFI_MMRAM_DESCRIPTOR  *MmramRanges,
  IN  UINTN                 MmramRangeCount,
  OUT EFI_PHYSICAL_ADDRESS  *MmramCacheBase,
  OUT UINT64                *MmramCacheSize
  )
{
  UINTN                 Index;
  EFI_PHYSICAL_ADDRESS  RangeCpuStart;
  UINT64                RangePhysicalSize;
  BOOLEAN               FoundAdjacentRange;

  *MmramCacheBase = MmramRange->CpuStart;
  *MmramCacheSize = MmramRange->PhysicalSize;

  do {
    FoundAdjacentRange = FALSE;
    for (Index = 0; (UINT64)Index < MmramRangeCount; Index++) {
      RangeCpuStart     = MmramRanges[Index].CpuStart;
      RangePhysicalSize = MmramRanges[Index].PhysicalSize;
      if ((RangeCpuStart < *MmramCacheBase) && (*MmramCacheBase == (RangeCpuStart + RangePhysicalSize))) {
        *MmramCacheBase    = RangeCpuStart;
        *MmramCacheSize   += RangePhysicalSize;
        FoundAdjacentRange = TRUE;
      } else if (((*MmramCacheBase + *MmramCacheSize) == RangeCpuStart) && (RangePhysicalSize > 0)) {
        *MmramCacheSize   += RangePhysicalSize;
        FoundAdjacentRange = TRUE;
      }
    }
  } while (FoundAdjacentRange);
}

// MU_CHANGE: MM_SUPV: MM Supervisor communication protocol, used to query MM policy,
//            region unblock, driver dispatching

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered UEFI service.

  @param[in] This                The MM_SUPERVISOR_COMMUNICATION_PPI instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into MMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SupvCommunicationCommunicate (
  IN CONST MM_SUPERVISOR_COMMUNICATION_PPI  *This,
  IN OUT VOID                               *CommBuffer,
  IN OUT UINTN                              *CommSize OPTIONAL
  )
{
  if ((This == NULL) ||
      (This->Signature != MM_SUPERVISOR_COMM_PPI_SIG) ||
      (This->Version != MM_SUPERVISOR_COMM_PPI_VER))
  {
    return EFI_INVALID_PARAMETER;
  }

  return SmmCommunicationCommunicateWorker (
           TRUE,
           CommBuffer,
           CommSize
           );
}

/**
  Communicates with a registered handler.

  This function provides a service to send and receive messages from a registered
  UEFI service.  This function is part of the SMM Communication PPI that may
  be called in physical mode prior to SetVirtualAddressMap() and in virtual mode
  after SetVirtualAddressMap().

  @param[in] This                The EFI_SMM_COMMUNICATION_PPI instance.
  @param[in, out] CommBuffer     A pointer to the buffer to convey into SMRAM.
  @param[in, out] CommSize       The size of the data buffer being passed in. On exit, the size of data
                                 being returned. Zero if the handler does not wish to reply with any data.
                                 This parameter is optional and may be NULL.

  @retval EFI_SUCCESS            The message was successfully posted.
  @retval EFI_INVALID_PARAMETER  The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE    The buffer is too large for the MM implementation.
                                 If this error is returned, the MessageLength field
                                 in the CommBuffer header or the integer pointed by
                                 CommSize, are updated to reflect the maximum payload
                                 size the implementation can accommodate.
  @retval EFI_ACCESS_DENIED      The CommunicateBuffer parameter or CommSize parameter,
                                 if not omitted, are in address range that cannot be
                                 accessed by the MM environment.

**/
EFI_STATUS
EFIAPI
SmmCommunicationCommunicate (
  IN CONST EFI_PEI_SMM_COMMUNICATION_PPI  *This,
  IN OUT VOID                             *CommBuffer,
  IN OUT UINTN                            *CommSize
  )
{
  // MU_CHANGE: MM_SUPV: Abstracted implementation to SmmCommunicationCommunicateWorker for
  // DXE and PEI, Supervisor and User.
  return SmmCommunicationCommunicateWorker (FALSE, CommBuffer, CommSize);
}

/**
  Event notification that is fired when a GUIDed Event Group is signaled.

  @param  PeiServices      Indirect reference to the PEI Services Table.
  @param  NotifyDescriptor Address of the notification descriptor data structure.
  @param  Ppi              Address of the PPI that was installed.

  @return Status of the notification.
          The status code returned from this function is ignored.

**/
EFI_STATUS
EFIAPI
SmmIplGuidedEventNotify (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  )
{
  if (NotifyDescriptor == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE: Abstracted implementation to SmmIplGuidedEventNotifyWork for DXE and PEI
  return SmmIplGuidedEventNotifyWorker (NotifyDescriptor->Guid);
}

// MU_CHANGE Starts: MM_SUPV: Will immediately signal MM core to dispatch MM drivers
#define COMM_BUFFER_MM_DISPATCH_ERROR    0x00
#define COMM_BUFFER_MM_DISPATCH_SUCCESS  0x01
#define COMM_BUFFER_MM_DISPATCH_RESTART  0x02
/**
  Invokes the MM core to dispatch drivers from inside MM environment. This
  function will only be called after MM foundation is successfully set.

  @return Status of the notification.
          The status code returned from this function is ignored.
**/
EFI_STATUS
EFIAPI
MmDriverDispatchNotify (
  VOID
  )
{
  UINTN       Size;
  EFI_STATUS  Status;

  //
  // Keep calling the SMM Core Dispatcher until there is no request to restart it.
  //
  while (TRUE) {
    // MU_CHANGE: MM_SUPV: Driver dispatcher command only deals with supervisor
    mCommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *)mMmSupvCommonBuffer;

    //
    // Use Guid to initialize EFI_MM_COMMUNICATE_HEADER structure
    // Clear the buffer passed into the Software SMI.  This buffer will return
    // the status of the SMM Core Dispatcher.
    //
    CopyGuid (&(mCommunicateHeader->HeaderGuid), &gMmSupervisorDriverDispatchGuid);
    mCommunicateHeader->MessageLength = 1;
    mCommunicateHeader->Data[0]       = 0;

    //
    // Generate the Software SMI and return the result
    //
    Size   = sizeof (EFI_MM_COMMUNICATE_HEADER);
    Status = SupvCommunicationCommunicate (&mMmSupvCommunication, mCommunicateHeader, &Size);

    //
    // Return if there is no request to restart the SMM Core Dispatcher
    //
    if (mCommunicateHeader->Data[0] != COMM_BUFFER_MM_DISPATCH_RESTART) {
      return Status;
    } else {
      ASSERT (FALSE);
    }
  }

  // Should not be here
  return EFI_DEVICE_ERROR;
}

// MU_CHANGE Ends: MM_SUPV

// MU_CHANGE: Loaded Fixed Address information is unsupported
// /**
//   Get the fixed loading address from image header assigned by build tool. This function only be called
//   when Loading module at Fixed address feature enabled.

//   @param  ImageContext              Pointer to the image context structure that describes the PE/COFF
//                                     image that needs to be examined by this function.
//   @retval EFI_SUCCESS               An fixed loading address is assigned to this image by build tools .
//   @retval EFI_NOT_FOUND             The image has no assigned fixed loading address.
// **/
// EFI_STATUS
// GetPeCoffImageFixLoadingAssignedAddress(
//   IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
//   )
// {
//    UINTN                              SectionHeaderOffset;
//    EFI_STATUS                         Status;
//    EFI_IMAGE_SECTION_HEADER           SectionHeader;
//    EFI_IMAGE_OPTIONAL_HEADER_UNION    *ImgHdr;
//    EFI_PHYSICAL_ADDRESS               FixLoadingAddress;
//    UINT16                             Index;
//    UINTN                              Size;
//    UINT16                             NumberOfSections;
//    EFI_PHYSICAL_ADDRESS               MmramBase;
//    UINT64                             MmCodeSize;
//    UINT64                             ValueInSectionHeader;
//    //
//    // Build tool will calculate the smm code size and then patch the PcdLoadFixAddressSmmCodePageNumber
//    //
//    MmCodeSize = EFI_PAGES_TO_SIZE (PcdGet32(PcdLoadFixAddressSmmCodePageNumber));

//    FixLoadingAddress = 0;
//    Status = EFI_NOT_FOUND;
//    MmramBase = mLMFAConfigurationTable->SmramBase;
//    //
//    // Get PeHeader pointer
//    //
//    ImgHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((CHAR8* )ImageContext->Handle + ImageContext->PeCoffHeaderOffset);
//    SectionHeaderOffset = ImageContext->PeCoffHeaderOffset +
//                          sizeof (UINT32) +
//                          sizeof (EFI_IMAGE_FILE_HEADER) +
//                          ImgHdr->Pe32.FileHeader.SizeOfOptionalHeader;
//    NumberOfSections = ImgHdr->Pe32.FileHeader.NumberOfSections;

//    //
//    // Get base address from the first section header that doesn't point to code section.
//    //
//    for (Index = 0; Index < NumberOfSections; Index++) {
//      //
//      // Read section header from file
//      //
//      Size = sizeof (EFI_IMAGE_SECTION_HEADER);
//      Status = ImageContext->ImageRead (
//                               ImageContext->Handle,
//                               SectionHeaderOffset,
//                               &Size,
//                               &SectionHeader
//                               );
//      if (EFI_ERROR (Status)) {
//        return Status;
//      }

//      Status = EFI_NOT_FOUND;

//      if ((SectionHeader.Characteristics & EFI_IMAGE_SCN_CNT_CODE) == 0) {
//        //
//        // Build tool saves the offset to SMRAM base as image base in PointerToRelocations & PointerToLineNumbers fields in the
//        // first section header that doesn't point to code section in image header. And there is an assumption that when the
//        // feature is enabled, if a module is assigned a loading address by tools, PointerToRelocations & PointerToLineNumbers
//        // fields should NOT be Zero, or else, these 2 fields should be set to Zero
//        //
//        ValueInSectionHeader = ReadUnaligned64((UINT64*)&SectionHeader.PointerToRelocations);
//        if (ValueInSectionHeader != 0) {
//          //
//          // Found first section header that doesn't point to code section in which build tool saves the
//          // offset to SMRAM base as image base in PointerToRelocations & PointerToLineNumbers fields
//          //
//          FixLoadingAddress = (EFI_PHYSICAL_ADDRESS)(MmramBase + (INT64)ValueInSectionHeader);

//          if (MmramBase + MmCodeSize > FixLoadingAddress && MmramBase <=  FixLoadingAddress) {
//            //
//            // The assigned address is valid. Return the specified loading address
//            //
//            ImageContext->ImageAddress = FixLoadingAddress;
//            Status = EFI_SUCCESS;
//          }
//        }
//        break;
//      }
//      SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
//    }
//    DEBUG ((DEBUG_INFO|DEBUG_LOAD, "LOADING MODULE FIXED INFO: Loading module at fixed address %x, Status = %r \n", FixLoadingAddress, Status));
//    return Status;
// }

// MU_CHANGE Starts: The MM core address found routine is updated with PEI services

/**
  Searches MmCore in all published firmware Volumes and loads the first
  instance that contains MmCore.

  @param[in]  Buffer    Placeholder for address of MM core located by this routine.

  @retval EFI_SUCCESS   This function located MM core successfully.
  @retval Others        Errors returned by PeiServices routines.

**/
EFI_STATUS
MmIplPeiFindMmCore (
  OUT VOID  **Buffer
  )
{
  EFI_STATUS           Status;
  UINTN                Instance;
  EFI_PEI_FV_HANDLE    VolumeHandle;
  EFI_PEI_FILE_HANDLE  FileHandle;

  Instance = 0;
  while (TRUE) {
    //
    // Traverse all firmware volume instances
    //
    Status = PeiServicesFfsFindNextVolume (Instance, &VolumeHandle);
    //
    // If some error occurs here, then we cannot find any firmware
    // volume that may contain MmCore.
    //
    if (EFI_ERROR (Status)) {
      REPORT_STATUS_CODE (EFI_PROGRESS_CODE, (EFI_SOFTWARE_PEI_MODULE | EFI_SW_PEI_CORE_EC_DXE_CORRUPT));
      ASSERT_EFI_ERROR (Status);
      break;
    }

    //
    // Find the MmCore file type from the beginning in this firmware volume.
    //
    FileHandle = NULL;
    Status     = PeiServicesFfsFindNextFile (EFI_FV_FILETYPE_MM_CORE_STANDALONE, VolumeHandle, &FileHandle);
    if (!EFI_ERROR (Status)) {
      //
      // Find MmCore FileHandle in this volume, then we skip other firmware volume and
      // return the FileHandle. Search Section now.
      //
      Status = PeiServicesFfsFindSectionData (EFI_SECTION_PE32, FileHandle, Buffer);
      if (EFI_ERROR (Status)) {
        break;
      }

      return EFI_SUCCESS;
      break;
    }

    //
    // We cannot find MmCore in this firmware volume, then search the next volume.
    //
    Instance++;
  }

  return Status;
}

/**
  Find largest unallocated MMRAM in current MMRAM descriptor block

  @param[in, out] LagestMmramRangeIndex  Lagest mmram range index.
  @param[in]      CurrentBlock           Current MMRAM descriptor block.

**/
VOID
FindLargestMmramRange (
  IN OUT UINTN                       *LagestMmramRangeIndex,
  IN EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *CurrentBlock
  )
{
  UINTN                 Index;
  UINT64                MaxSize;
  BOOLEAN               Found;
  EFI_MMRAM_DESCRIPTOR  *MmramRanges;

  MmramRanges = CurrentBlock->Descriptor;

  //
  // Find largest Mmram range.
  //
  Found = FALSE;
  for (Index = 0, MaxSize = SIZE_256KB - EFI_PAGE_SIZE; Index < CurrentBlock->NumberOfMmReservedRegions; Index++) {
    //
    // Skip any MMRAM region that is already allocated, needs testing, or needs ECC initialization
    //
    if ((MmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    if (MmramRanges[Index].CpuStart >= BASE_1MB) {
      if ((MmramRanges[Index].CpuStart + MmramRanges[Index].PhysicalSize) <= BASE_4GB) {
        if (MmramRanges[Index].PhysicalSize >= MaxSize) {
          Found                  = TRUE;
          *LagestMmramRangeIndex = Index;
          MaxSize                = MmramRanges[Index].PhysicalSize;
        }
      }
    }
  }

  if (Found == FALSE) {
    DEBUG ((DEBUG_ERROR, "Not found largest unlocated MMRAM\n"));
    ASSERT (FALSE);
    CpuDeadLoop ();
  }

  return;
}

/**
  Allocate available MMRAM for MM core image.

  @param[in]  Pages                     Page count of MM core image.

  @return  EFI_PHYSICAL_ADDRESS         Address for MM core image to be loaded in MMRAM.
**/
EFI_PHYSICAL_ADDRESS
MmIplAllocateMmramPage (
  IN  UINTN  Pages
  )
{
  UINTN                           LagestMmramRangeIndex;
  UINT32                          FullMmramRangeCount;
  EFI_HOB_GUID_TYPE               *MmramInfoHob;
  EFI_MMRAM_DESCRIPTOR            *Largest;
  EFI_MMRAM_DESCRIPTOR            *Allocated;
  EFI_MMRAM_DESCRIPTOR            *FullMmramRanges;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *CurrentBlock;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *NewDescriptorBlock;

  MmramInfoHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
  if (MmramInfoHob == NULL) {
    ASSERT (MmramInfoHob != NULL);
    DEBUG ((DEBUG_WARN, "SmramMemoryReserve HOB not found\n"));
    return 0;
  }

  CurrentBlock = (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK *)(GET_GUID_HOB_DATA (MmramInfoHob));

  //
  // 1. Find largest unallocated MMRAM region
  //
  FindLargestMmramRange (&LagestMmramRangeIndex, CurrentBlock);
  ASSERT (LagestMmramRangeIndex < CurrentBlock->NumberOfMmReservedRegions);

  //
  // 2. Split the largest region and mark the allocated region as ALLOCATED
  //
  FullMmramRangeCount = CurrentBlock->NumberOfMmReservedRegions + 1;
  NewDescriptorBlock  = (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK *)BuildGuidHob (
                                                            &gEfiSmmSmramMemoryGuid,
                                                            sizeof (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK) + ((FullMmramRangeCount - 1) * sizeof (EFI_MMRAM_DESCRIPTOR))
                                                            );
  ASSERT (NewDescriptorBlock != NULL);

  NewDescriptorBlock->NumberOfMmReservedRegions = FullMmramRangeCount;
  FullMmramRanges                               = NewDescriptorBlock->Descriptor;

  //
  // Get current MMRAM descriptors and fill to the full MMRAM ranges
  //
  CopyMem (NewDescriptorBlock->Descriptor, CurrentBlock->Descriptor, CurrentBlock->NumberOfMmReservedRegions * sizeof (EFI_MMRAM_DESCRIPTOR));

  Largest = &FullMmramRanges[LagestMmramRangeIndex];
  ASSERT ((Largest->PhysicalSize & EFI_PAGE_MASK) == 0);
  ASSERT (Largest->PhysicalSize > EFI_PAGES_TO_SIZE (Pages));

  Allocated = &NewDescriptorBlock->Descriptor[NewDescriptorBlock->NumberOfMmReservedRegions - 1];

  //
  // Allocate MMRAM
  //
  Largest->PhysicalSize   -= EFI_PAGES_TO_SIZE (Pages);
  Allocated->CpuStart      = Largest->CpuStart + Largest->PhysicalSize;
  Allocated->PhysicalStart = Largest->PhysicalStart + Largest->PhysicalSize;
  Allocated->RegionState   = Largest->RegionState | EFI_ALLOCATED;
  Allocated->PhysicalSize  = EFI_PAGES_TO_SIZE (Pages);

  //
  // Scrub old one
  //
  ZeroMem (&MmramInfoHob->Name, sizeof (MmramInfoHob->Name));

  return Allocated->CpuStart;
}

/**
  Builds a HOB for a loaded PE32 module.

  This function builds a HOB for a loaded PE32 module.
  It can only be invoked during PEI phase;
  If physical address of the Module is not 4K aligned, then ASSERT().
  If new HOB buffer is NULL, then ASSERT().

  @param[in]       Hob            The pointer of new HOB buffer.
  @param[in, out]  HobBufferSize  The available size of the HOB buffer when as input.
                                  The used size of when as output.
  @param[in]       ModuleName     The GUID File Name of the module.
  @param[in]       Base           The 64 bit physical address of the module.
  @param[in]       Length         The length of the module in bytes.
  @param[in]       EntryPoint     The 64 bit physical address of the module entry point.

**/
EFI_STATUS
MmIplBuildMmCoreAllocationHob (
  IN CONST EFI_GUID        *ModuleName,
  IN EFI_PHYSICAL_ADDRESS  Base,
  IN UINT64                Length,
  IN EFI_PHYSICAL_ADDRESS  EntryPoint
  )
{
  EFI_STATUS                        Status;

  if (!IS_ALIGNED (Base, EFI_PAGE_SIZE) || !IS_ALIGNED (Length, EFI_PAGE_SIZE)) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  if ((EntryPoint < Base) || (EntryPoint >= Base + Length)) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  // TODO: This deviates from the EDK2 implementation which uses
  // the build module HOB.
  BuildMemoryAllocationHob (
    Base,
    Length,
    EfiReservedMemoryType
  );

  TagMemoryAllocationHobWithGuid (
    Base,
    ModuleName
  );

  Status = EFI_SUCCESS;

Exit:
  return Status;
}

// MU_CHANGE Ends

/**
  Load the SMM Core image into SMRAM and executes the SMM Core from SMRAM.

  @param[in, out] MmramRange            Descriptor for the range of SMRAM to reload the
                                        currently executing image, the rang of SMRAM to
                                        hold SMM Core will be excluded.
  @param[in, out] MmramRangeSmmCore     Descriptor for the range of SMRAM to hold SMM Core.

  @return  EFI_STATUS

**/
EFI_STATUS
ExecuteMmCoreFromMmram (
  IN OUT EFI_MMRAM_DESCRIPTOR  *MmramRange,
  IN OUT EFI_MMRAM_DESCRIPTOR  *MmramRangeSmmCore
  )
{
  EFI_STATUS                            Status;
  VOID                                  *SourceBuffer;
  PE_COFF_LOADER_IMAGE_CONTEXT          ImageContext;
  UINTN                                 PageCount;
  STANDALONE_MM_FOUNDATION_ENTRY_POINT  EntryPoint;
  VOID                                  *HobStart;

  DEBUG ((DEBUG_INFO, "%a Enters...\n", __func__));
  //
  // Search all Firmware Volumes for a PE/COFF image in a file of type MM_CORE_STANDALONE
  //
  SourceBuffer = NULL;
  // MU_CHANGE: The MM core address found routine is updated with PEI services
  Status = MmIplPeiFindMmCore (&SourceBuffer);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Failed to find MM core file - %r...\n", __func__, Status));
    goto Exit;
  }

  //
  // Initialize ImageContext
  //
  ImageContext.Handle    = SourceBuffer;
  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;

  //
  // Get information about the image being loaded
  //
  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // MU_CHANGE: Loaded Fixed Address information is unsupported
  //
  // if Loading module at Fixed Address feature is enabled, the SMM core driver will be loaded to
  // the address assigned by build tool.
  //
  //
  // Allocate memory for the image being loaded from unallocated mmram range
  //
  PageCount = (UINTN)EFI_SIZE_TO_PAGES ((UINTN)ImageContext.ImageSize + ImageContext.SectionAlignment);

  ImageContext.ImageAddress = MmIplAllocateMmramPage (PageCount);
  if (ImageContext.ImageAddress == 0) {
    return EFI_NOT_FOUND;
  }

  ImageContext.ImageAddress += ImageContext.SectionAlignment - 1;
  ImageContext.ImageAddress &= ~((EFI_PHYSICAL_ADDRESS)ImageContext.SectionAlignment - 1);

  //
  // Print debug message showing SMM Core load address.
  //
  // MS_CHANGE_304324
  if (DebugCodeEnabled ()) {
    DEBUG ((DEBUG_INFO, "SMM IPL loading SMM Core at SMRAM address %p\n", (VOID *)(UINTN)ImageContext.ImageAddress));
  } else {
    DEBUG ((DEBUG_ERROR, "SMM IPL loading SMM Core (PiSmmCore.efi)\n"));
  }

  // END

  //
  // Load the image to our new buffer
  //
  Status = PeCoffLoaderLoadImage (&ImageContext);
  if (!EFI_ERROR (Status)) {
    //
    // Relocate the image in our new buffer
    //
    Status = PeCoffLoaderRelocateImage (&ImageContext);
    if (!EFI_ERROR (Status)) {
      //
      // Flush the instruction cache so the image data are written before we execute it
      //
      InvalidateInstructionCacheRange ((VOID *)(UINTN)ImageContext.ImageAddress, (UINTN)ImageContext.ImageSize);

      //
      // Print debug message showing SMM Core entry point address.
      //
      DEBUG ((DEBUG_INFO, "SMM IPL calling SMM Core at SMRAM address %p\n", (VOID *)(UINTN)ImageContext.EntryPoint));

      // MU_CHANGE Starts: To load x64 MM foundation, mode switch is needed
      EntryPoint = (STANDALONE_MM_FOUNDATION_ENTRY_POINT)(UINTN)ImageContext.EntryPoint;

      Status = MmIplBuildMmCoreAllocationHob (
                  &gMmSupervisorCoreGuid,
                  ImageContext.ImageAddress,
                  (UINT64)EFI_PAGES_TO_SIZE (PageCount),
                  (EFI_PHYSICAL_ADDRESS)(UINTN)ImageContext.EntryPoint
                  );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a Failed to build MM core module HOB - %r...\n", __func__, Status));
        goto Exit;
      }

      HobStart   = GetHobList ();
 #ifdef MDE_CPU_IA32
      //
      // Thunk to x64 then execute image , and then come back...
      //
      DEBUG ((DEBUG_INFO, "%a Need to switch mode in order to execute MM core...\n", __func__));
      Status = SetMmFoundationInX64Relay (EntryPoint, HobStart);
 #else
      //
      // Execute image directly
      //
      DEBUG ((DEBUG_INFO, "%a Easy mode, load it directly...\n", __func__));
      Status = EntryPoint (HobStart);
 #endif
      // MU_CHANGE Ends
    }
  }

Exit:
  //
  // Always free memory allocated by GetFileBufferByFilePath ()
  //
  if (SourceBuffer != NULL) {
    FreePool (SourceBuffer);
  }

  return Status;
}

/**
  SMM split SMRAM entry.

  @param[in, out] RangeToCompare             Pointer to EFI_MMRAM_DESCRIPTOR to compare.
  @param[in, out] ReservedRangeToCompare     Pointer to EFI_MM_RESERVED_MMRAM_REGION to compare.
  @param[out]     Ranges                     Output pointer to hold split EFI_MMRAM_DESCRIPTOR entry.
  @param[in, out] RangeCount                 Pointer to range count.
  @param[out]     ReservedRanges             Output pointer to hold split EFI_MM_RESERVED_MMRAM_REGION entry.
  @param[in, out] ReservedRangeCount         Pointer to reserved range count.
  @param[out]     FinalRanges                Output pointer to hold split final EFI_MMRAM_DESCRIPTOR entry
                                             that no need to be split anymore.
  @param[in, out] FinalRangeCount            Pointer to final range count.

**/
VOID
SmmSplitMmramEntry (
  IN OUT EFI_MMRAM_DESCRIPTOR          *RangeToCompare,
  IN OUT EFI_MM_RESERVED_MMRAM_REGION  *ReservedRangeToCompare,
  OUT    EFI_MMRAM_DESCRIPTOR          *Ranges,
  IN OUT UINTN                         *RangeCount,
  OUT    EFI_MM_RESERVED_MMRAM_REGION  *ReservedRanges,
  IN OUT UINTN                         *ReservedRangeCount,
  OUT    EFI_MMRAM_DESCRIPTOR          *FinalRanges,
  IN OUT UINTN                         *FinalRangeCount
  )
{
  UINT64  RangeToCompareEnd;
  UINT64  ReservedRangeToCompareEnd;

  RangeToCompareEnd         = RangeToCompare->CpuStart + RangeToCompare->PhysicalSize;
  ReservedRangeToCompareEnd = ReservedRangeToCompare->MmramReservedStart + ReservedRangeToCompare->MmramReservedSize;

  if ((RangeToCompare->CpuStart >= ReservedRangeToCompare->MmramReservedStart) &&
      (RangeToCompare->CpuStart < ReservedRangeToCompareEnd))
  {
    if (RangeToCompareEnd < ReservedRangeToCompareEnd) {
      //
      // RangeToCompare  ReservedRangeToCompare
      //                 ----                    ----    --------------------------------------
      //                 |  |                    |  | -> 1. ReservedRangeToCompare
      // ----            |  |                    |--|    --------------------------------------
      // |  |            |  |                    |  |
      // |  |            |  |                    |  | -> 2. FinalRanges[*FinalRangeCount] and increment *FinalRangeCount
      // |  |            |  |                    |  |       RangeToCompare->PhysicalSize = 0
      // ----            |  |                    |--|    --------------------------------------
      //                 |  |                    |  | -> 3. ReservedRanges[*ReservedRangeCount] and increment *ReservedRangeCount
      //                 ----                    ----    --------------------------------------
      //

      //
      // 1. Update ReservedRangeToCompare.
      //
      ReservedRangeToCompare->MmramReservedSize = RangeToCompare->CpuStart - ReservedRangeToCompare->MmramReservedStart;
      //
      // 2. Update FinalRanges[FinalRangeCount] and increment *FinalRangeCount.
      //    Zero RangeToCompare->PhysicalSize.
      //
      FinalRanges[*FinalRangeCount].CpuStart      = RangeToCompare->CpuStart;
      FinalRanges[*FinalRangeCount].PhysicalStart = RangeToCompare->PhysicalStart;
      FinalRanges[*FinalRangeCount].RegionState   = RangeToCompare->RegionState | EFI_ALLOCATED;
      FinalRanges[*FinalRangeCount].PhysicalSize  = RangeToCompare->PhysicalSize;
      *FinalRangeCount                           += 1;
      RangeToCompare->PhysicalSize                = 0;
      //
      // 3. Update ReservedRanges[*ReservedRangeCount] and increment *ReservedRangeCount.
      //
      ReservedRanges[*ReservedRangeCount].MmramReservedStart = FinalRanges[*FinalRangeCount - 1].CpuStart + FinalRanges[*FinalRangeCount - 1].PhysicalSize;
      ReservedRanges[*ReservedRangeCount].MmramReservedSize  = ReservedRangeToCompareEnd - RangeToCompareEnd;
      *ReservedRangeCount                                   += 1;
    } else {
      //
      // RangeToCompare  ReservedRangeToCompare
      //                 ----                    ----    --------------------------------------
      //                 |  |                    |  | -> 1. ReservedRangeToCompare
      // ----            |  |                    |--|    --------------------------------------
      // |  |            |  |                    |  |
      // |  |            |  |                    |  | -> 2. FinalRanges[*FinalRangeCount] and increment *FinalRangeCount
      // |  |            |  |                    |  |
      // |  |            ----                    |--|    --------------------------------------
      // |  |                                    |  | -> 3. RangeToCompare
      // ----                                    ----    --------------------------------------
      //

      //
      // 1. Update ReservedRangeToCompare.
      //
      ReservedRangeToCompare->MmramReservedSize = RangeToCompare->CpuStart - ReservedRangeToCompare->MmramReservedStart;
      //
      // 2. Update FinalRanges[FinalRangeCount] and increment *FinalRangeCount.
      //
      FinalRanges[*FinalRangeCount].CpuStart      = RangeToCompare->CpuStart;
      FinalRanges[*FinalRangeCount].PhysicalStart = RangeToCompare->PhysicalStart;
      FinalRanges[*FinalRangeCount].RegionState   = RangeToCompare->RegionState | EFI_ALLOCATED;
      FinalRanges[*FinalRangeCount].PhysicalSize  = ReservedRangeToCompareEnd - RangeToCompare->CpuStart;
      *FinalRangeCount                           += 1;
      //
      // 3. Update RangeToCompare.
      //
      RangeToCompare->CpuStart      += FinalRanges[*FinalRangeCount - 1].PhysicalSize;
      RangeToCompare->PhysicalStart += FinalRanges[*FinalRangeCount - 1].PhysicalSize;
      RangeToCompare->PhysicalSize  -= FinalRanges[*FinalRangeCount - 1].PhysicalSize;
    }
  } else if ((ReservedRangeToCompare->MmramReservedStart >= RangeToCompare->CpuStart) &&
             (ReservedRangeToCompare->MmramReservedStart < RangeToCompareEnd))
  {
    if (ReservedRangeToCompareEnd < RangeToCompareEnd) {
      //
      // RangeToCompare  ReservedRangeToCompare
      // ----                                    ----    --------------------------------------
      // |  |                                    |  | -> 1. RangeToCompare
      // |  |            ----                    |--|    --------------------------------------
      // |  |            |  |                    |  |
      // |  |            |  |                    |  | -> 2. FinalRanges[*FinalRangeCount] and increment *FinalRangeCount
      // |  |            |  |                    |  |       ReservedRangeToCompare->MmramReservedSize = 0
      // |  |            ----                    |--|    --------------------------------------
      // |  |                                    |  | -> 3. Ranges[*RangeCount] and increment *RangeCount
      // ----                                    ----    --------------------------------------
      //

      //
      // 1. Update RangeToCompare.
      //
      RangeToCompare->PhysicalSize = ReservedRangeToCompare->MmramReservedStart - RangeToCompare->CpuStart;
      //
      // 2. Update FinalRanges[FinalRangeCount] and increment *FinalRangeCount.
      //    ReservedRangeToCompare->MmramReservedSize = 0
      //
      FinalRanges[*FinalRangeCount].CpuStart      = ReservedRangeToCompare->MmramReservedStart;
      FinalRanges[*FinalRangeCount].PhysicalStart = RangeToCompare->PhysicalStart + RangeToCompare->PhysicalSize;
      FinalRanges[*FinalRangeCount].RegionState   = RangeToCompare->RegionState | EFI_ALLOCATED;
      FinalRanges[*FinalRangeCount].PhysicalSize  = ReservedRangeToCompare->MmramReservedSize;
      *FinalRangeCount                           += 1;
      ReservedRangeToCompare->MmramReservedSize   = 0;
      //
      // 3. Update Ranges[*RangeCount] and increment *RangeCount.
      //
      Ranges[*RangeCount].CpuStart      = FinalRanges[*FinalRangeCount - 1].CpuStart + FinalRanges[*FinalRangeCount - 1].PhysicalSize;
      Ranges[*RangeCount].PhysicalStart = FinalRanges[*FinalRangeCount - 1].PhysicalStart + FinalRanges[*FinalRangeCount - 1].PhysicalSize;
      Ranges[*RangeCount].RegionState   = RangeToCompare->RegionState;
      Ranges[*RangeCount].PhysicalSize  = RangeToCompareEnd - ReservedRangeToCompareEnd;
      *RangeCount                      += 1;
    } else {
      //
      // RangeToCompare  ReservedRangeToCompare
      // ----                                    ----    --------------------------------------
      // |  |                                    |  | -> 1. RangeToCompare
      // |  |            ----                    |--|    --------------------------------------
      // |  |            |  |                    |  |
      // |  |            |  |                    |  | -> 2. FinalRanges[*FinalRangeCount] and increment *FinalRangeCount
      // |  |            |  |                    |  |
      // ----            |  |                    |--|    --------------------------------------
      //                 |  |                    |  | -> 3. ReservedRangeToCompare
      //                 ----                    ----    --------------------------------------
      //

      //
      // 1. Update RangeToCompare.
      //
      RangeToCompare->PhysicalSize = ReservedRangeToCompare->MmramReservedStart - RangeToCompare->CpuStart;
      //
      // 2. Update FinalRanges[FinalRangeCount] and increment *FinalRangeCount.
      //    ReservedRangeToCompare->MmramReservedSize = 0
      //
      FinalRanges[*FinalRangeCount].CpuStart      = ReservedRangeToCompare->MmramReservedStart;
      FinalRanges[*FinalRangeCount].PhysicalStart = RangeToCompare->PhysicalStart + RangeToCompare->PhysicalSize;
      FinalRanges[*FinalRangeCount].RegionState   = RangeToCompare->RegionState | EFI_ALLOCATED;
      FinalRanges[*FinalRangeCount].PhysicalSize  = RangeToCompareEnd - ReservedRangeToCompare->MmramReservedStart;
      *FinalRangeCount                           += 1;
      //
      // 3. Update ReservedRangeToCompare.
      //
      ReservedRangeToCompare->MmramReservedStart += FinalRanges[*FinalRangeCount - 1].PhysicalSize;
      ReservedRangeToCompare->MmramReservedSize  -= FinalRanges[*FinalRangeCount - 1].PhysicalSize;
    }
  }
}

/**
  Returns if SMRAM range and SMRAM reserved range are overlapped.

  @param[in] RangeToCompare             Pointer to EFI_MMRAM_DESCRIPTOR to compare.
  @param[in] ReservedRangeToCompare     Pointer to EFI_MM_RESERVED_MMRAM_REGION to compare.

  @retval TRUE  There is overlap.
  @retval TRUE  Math error.
  @retval FALSE There is no overlap.

**/
BOOLEAN
SmmIsMmramOverlap (
  IN EFI_MMRAM_DESCRIPTOR          *RangeToCompare,
  IN EFI_MM_RESERVED_MMRAM_REGION  *ReservedRangeToCompare
  )
{
  UINT64   RangeToCompareEnd;
  UINT64   ReservedRangeToCompareEnd;
  BOOLEAN  IsOverUnderflow1;
  BOOLEAN  IsOverUnderflow2;

  // Check for over or underflow.
  IsOverUnderflow1 = EFI_ERROR (
                       SafeUint64Add (
                         (UINT64)RangeToCompare->CpuStart,
                         RangeToCompare->PhysicalSize,
                         &RangeToCompareEnd
                         )
                       );
  IsOverUnderflow2 = EFI_ERROR (
                       SafeUint64Add (
                         (UINT64)ReservedRangeToCompare->MmramReservedStart,
                         ReservedRangeToCompare->MmramReservedSize,
                         &ReservedRangeToCompareEnd
                         )
                       );
  if (IsOverUnderflow1 || IsOverUnderflow2) {
    return TRUE;
  }

  if ((RangeToCompare->CpuStart >= ReservedRangeToCompare->MmramReservedStart) &&
      (RangeToCompare->CpuStart < ReservedRangeToCompareEnd))
  {
    return TRUE;
  } else if ((ReservedRangeToCompare->MmramReservedStart >= RangeToCompare->CpuStart) &&
             (ReservedRangeToCompare->MmramReservedStart < RangeToCompareEnd))
  {
    return TRUE;
  }

  return FALSE;
}

/**
  The Entry Point for PEI MM IPL

  Load MM Core into MMRAM, register MM Core entry point for SMIs, install
  MM Communication PPI (both for user and supervisor), and register for the
  critical events required to coordinate between PEI and MM environments.

  @param[in]  FileHandle    Not used.
  @param[in]  PeiServices   General purpose services available to every PEIM.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval Other             Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmIplPeiEntry (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINT64      MaxSize;
  UINTN       Size;
  UINTN       MmramRangeCount;
  // UINT64                          MmCodeSize;
  // EFI_CPU_ARCH_PROTOCOL           *CpuArch;
  // EFI_STATUS                      SetAttrStatus;
  // EFI_MMRAM_DESCRIPTOR            *MmramRangeSmmDriver;
  // EFI_GCD_MEMORY_SPACE_DESCRIPTOR MemDesc;
  EFI_MMRAM_DESCRIPTOR  *MmramRanges;
  // MU_CHANGE: MM_SUPV: Test supervisor communication before publishing protocol
  MM_SUPERVISOR_VERSION_INFO_BUFFER  VersionInfo;
  MTRR_MEMORY_CACHE_TYPE             CacheAttribute;

  Status = PeiServicesRegisterForShadow (FileHandle);

  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  // MU_CHANGE: MM_SUPV: Initialize Comm buffer from HOBs first
  Status = InitializeCommunicationBufferFromHob (
             &mMmSupvCommunication.CommunicationRegion
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a Failed to initialize communication buffer from HOBs - %r\n", __func__, Status));
    return Status;
  }

  //
  // Get SMM Access PPI
  //
  Status = (*PeiServices)->LocatePpi (
                             PeiServices,
                             &gEfiPeiMmAccessPpiGuid,
                             0,
                             NULL,
                             (VOID **)&mSmmAccess
                             );
  ASSERT_EFI_ERROR (Status);

  //
  // Get SMM Control PPI
  //
  Status = (*PeiServices)->LocatePpi (
                             PeiServices,
                             &gEfiPeiMmControlPpiGuid,
                             0,
                             NULL,
                             (VOID **)&mSmmControl
                             );
  ASSERT_EFI_ERROR (Status);

  //
  // Open all SMRAM ranges
  //
  // MU_CHANGE Starts: Need to iterate through all MMRAMs to open one at a time for PPI interface
  Size   = 0;
  Status = mSmmAccess->GetCapabilities ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, &Size, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    // This is not right...
    ASSERT (FALSE);
    return EFI_DEVICE_ERROR;
  }

  MmramRanges = AllocatePool (Size);
  if (MmramRanges == NULL) {
    ASSERT (MmramRanges != NULL);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = mSmmAccess->GetCapabilities ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, &Size, MmramRanges);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SMM IPL failed to get SMRAM capabilities - %r\n", Status));
    ASSERT (FALSE);
    return Status;
  }

  MmramRangeCount = Size / sizeof (EFI_MMRAM_DESCRIPTOR);
  for (Index = 0; Index < MmramRangeCount; Index++) {
    Status = mSmmAccess->Open ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, Index);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SMM IPL failed to open SMRAM windows index %d - %r\n", Index, Status));
      ASSERT (FALSE);
      return Status;
    }
  }

  // MU_CHANGE Ends

  //
  // Print debug message that the SMRAM window is now open.
  //
  DEBUG ((DEBUG_INFO, "SMM IPL opened %d SMRAM windows\n", Index));

  //
  // Find the largest SMRAM range between 1MB and 4GB that is at least 256KB - 4K in size
  //
  mCurrentMmramRange = NULL;
  for (Index = 0, MaxSize = SIZE_256KB - EFI_PAGE_SIZE; (UINT64)Index < MmramRangeCount; Index++) {
    //
    // Skip any SMRAM region that is already allocated, needs testing, or needs ECC initialization
    //
    if ((MmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    if (MmramRanges[Index].CpuStart >= BASE_1MB) {
      if ((MmramRanges[Index].CpuStart + MmramRanges[Index].PhysicalSize - 1) <= MAX_ADDRESS) {
        if (MmramRanges[Index].PhysicalSize >= MaxSize) {
          MaxSize            = MmramRanges[Index].PhysicalSize;
          mCurrentMmramRange = &MmramRanges[Index];
        }
      }
    }
  }

  if (mCurrentMmramRange != NULL) {
    //
    // Print debug message showing SMRAM window that will be used by SMM IPL and SMM Core
    //
    DEBUG ((
      DEBUG_INFO,
      "SMM IPL found SMRAM window %p - %p\n",
      (VOID *)(UINTN)mCurrentMmramRange->CpuStart,
      (VOID *)(UINTN)(mCurrentMmramRange->CpuStart + mCurrentMmramRange->PhysicalSize - 1)
      ));

    GetMmramCacheRange (mCurrentMmramRange, MmramRanges, MmramRangeCount, &mMmramCacheBase, &mMmramCacheSize);
    // MU_CHANGE: MM_SUPV: Memory space descriptor marking is directly using MTRR registers
    //
    // Make sure we can change the desired memory attributes.
    //
    CacheAttribute = MtrrGetMemoryAttribute (mMmramCacheBase);
    if (CacheAttribute != CacheWriteBack) {
      // If current Mmram cache is not WB, set it this way during init
      Status = MtrrSetMemoryAttribute (mMmramCacheBase, mMmramCacheSize, CacheWriteBack);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "Could not set MMRAM cache region to WB - %r\n", Status));
        ASSERT (FALSE);
        return Status;
      }
    }

    //
    // Load SMM Core into SMRAM and execute it from SMRAM
    //
    Status = ExecuteMmCoreFromMmram (
               mCurrentMmramRange,
               &MmramRanges[MmramRangeCount - 1]
               );
    if (EFI_ERROR (Status)) {
      //
      // Print error message that the SMM Core failed to be loaded and executed.
      //
      DEBUG ((DEBUG_ERROR, "SMM IPL could not load and execute SMM Core from SMRAM\n"));
      ASSERT_EFI_ERROR (Status);

      // MU_CHANGE: SUPV: Memory space descriptor reverting uses MTRR for cachability update
      //
      // Attempt to reset SMRAM cacheability to UC
      //
      Status = MtrrSetMemoryAttribute (mMmramCacheBase, mMmramCacheSize, CacheUncacheable);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "Could not reset MMRAM cache region back to UC - %r\n", Status));
        ASSERT (FALSE);
        return Status;
      }
    }
  } else {
    //
    // Print error message that there are not enough SMRAM resources to load the SMM Core.
    //
    DEBUG ((DEBUG_ERROR, "SMM IPL could not find a large enough SMRAM region to load SMM Core\n"));
  }

  //
  // Close all SMRAM ranges
  //
  // MU_CHANGE: Iterate through each MMRAM for PPI instance
  for (Index = 0; Index < MmramRangeCount; Index++) {
    Status = mSmmAccess->Close ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, Index);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SMM IPL failed to close SMRAM windows index %d - %r\n", Index, Status));
      ASSERT (FALSE);
      return Status;
    }

    //
    // Print debug message that the SMRAM window is now closed.
    //
    DEBUG ((DEBUG_INFO, "MM IPL closed SMRAM window index %d\n", Index));
  }

  // MU_CHANGE: MM_SUPV: Locked immediately after closing instead of waiting for ready to lock event
  //
  // Lock the SMRAM (Note: Locking SMRAM may not be supported on all platforms)
  //
  for (Index = 0; Index < MmramRangeCount; Index++) {
    Status = mSmmAccess->Lock ((EFI_PEI_SERVICES **)PeiServices, mSmmAccess, Index);
    if (EFI_ERROR (Status)) {
      //
      // Print error message that the SMRAM failed to lock...
      //
      DEBUG ((DEBUG_ERROR, "MM IPL could not lock MMRAM (Index %d) after executing MM Core %r\n", Index, Status));
      ASSERT (FALSE);
      return Status;
    }

    //
    // Print debug message that the SMRAM window is now closed.
    //
    DEBUG ((DEBUG_INFO, "MM IPL locked SMRAM window index %d\n", Index));
  }

  SECURITY_LOCK_REPORT_EVENT ("Lock MMRAM", HARDWARE_LOCK); // MSCHANGE

  //
  // Print debug message that the SMRAM window is now locked.
  //
  DEBUG ((DEBUG_INFO, "SMM IPL locked SMRAM window\n"));

  // MU_CHANGE: MM_SUPV: We are just making sure this communication to supervisor does not fail after setup.
  Status = QuerySupervisorVersion (&VersionInfo);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // MU_CHANGE: MM_SUPV: Added a forced trigger to load all drivers in MM
  //
  // Trigger to dispatch MM drivers from inside MM
  //
  if (!EFI_ERROR (Status)) {
    Status = MmDriverDispatchNotify ();
    DEBUG ((DEBUG_INFO, "MM driver dispatching returned - %r\n", Status));
  }

  //
  // If the SMM Core could not be loaded then close SMRAM window, free allocated
  // resources, and return an error so SMM IPL will be unloaded.
  //
  if ((mCurrentMmramRange == NULL) || EFI_ERROR (Status)) {
    //
    // Free all allocated resources
    //
    FreePool ((VOID *)MmramRanges);

    return EFI_UNSUPPORTED;
  }

  //
  // Install MM Communication and Supervisor MM Communication PPI
  //
  Status = (*PeiServices)->InstallPpi (PeiServices, mPeiMmIplPpiList);
  ASSERT_EFI_ERROR (Status);

  //
  // Create the set of ppi and event notifications that the SMM IPL requires
  //
  Status = (*PeiServices)->NotifyPpi (PeiServices, &mPeiMmIplNotifyList);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
