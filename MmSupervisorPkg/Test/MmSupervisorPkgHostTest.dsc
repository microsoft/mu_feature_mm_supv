# *******************************************************************************
# Host Based Unit Test DSC file for MmSupervisorPkg.
#
# Copyright(C) 2020 Advanced Micro Devices, Inc. All rights reserved.
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# *******************************************************************************



[Defines]
  PLATFORM_NAME                  = MmSupervisor
  PLATFORM_GUID                  = 364AEF2C-2051-4466-8DDB-4DC3600F3BA0
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x0001001A
  OUTPUT_DIRECTORY               = Build/MmSupervisorPkg/HostTest
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = NOOPT
  SKUID_IDENTIFIER               = DEFAULT


!include UnitTestFrameworkPkg/UnitTestFrameworkPkgHost.dsc.inc

[LibraryClasses]
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf

[Components]
  MmSupervisorPkg/Library/SmmPolicyGateLib/UnitTest/SmmPolicyGateLibUnitTest.inf {
    <LibraryClasses>
      SmmPolicyGateLib|MmSupervisorPkg/Library/SmmPolicyGateLib/SmmPolicyGateLib.inf
  }
