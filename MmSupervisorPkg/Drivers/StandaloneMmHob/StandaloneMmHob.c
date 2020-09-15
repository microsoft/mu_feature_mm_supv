/** @file
  PEI module that builds placeholder HOBs for MM usage.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <StandaloneMm.h>

#include <Guid/MmCoreData.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MmCoreProfileData.h>
#include <Guid/MmCommonRegion.h>

#include <Library/PeiServicesLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>

/**
  The Entry Point for this PEI module. It builds placeholder HOBs for later
  MM usage.

  @param[in]  FileHandle           Not used.
  @param[in]  PeiServices          General purpose services available to every PEIM.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
StandaloneMmHobEntry (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  MM_CORE_DATA_HOB_DATA    *HobData;
  MM_CORE_MM_PROFILE_DATA  *HobData3;
  VOID                     *HobProbe;

  DEBUG ((DEBUG_INFO, "%a Entry...\n", __FUNCTION__));

  HobProbe = GetFirstGuidHob (&gMmCoreDataHobGuid);
  if (HobProbe == NULL) {
    // Build the dummy GUID'd HOB for MmCore, this will be populated by MM IPL
    HobData          = BuildGuidHob (&gMmCoreDataHobGuid, sizeof (MM_CORE_DATA_HOB_DATA));
    HobData->Address = 0;
  }

  HobProbe = GetFirstGuidHob (&gMmCoreMmProfileGuid);
  if (HobProbe == NULL) {
    // Build the dummy GUID'd HOB for MmCore, this will be populated by MM IPL
    HobData3 = BuildGuidHob (&gMmCoreMmProfileGuid, sizeof (MM_CORE_MM_PROFILE_DATA));
    ZeroMem (HobData3, sizeof (MM_CORE_MM_PROFILE_DATA));
  }

  return EFI_SUCCESS;
}
