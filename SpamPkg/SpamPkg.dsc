# *******************************************************************************
# Package DSC file for CI build of SpamPkg.
#
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# *******************************************************************************



[Defines]
  PLATFORM_NAME                  = SpamPkg
  PLATFORM_GUID                  = 2D12C504-6F63-458D-AECB-1F35184DB4B1
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x0001001A
  OUTPUT_DIRECTORY               = Build/SpamPkg
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses.common]

[Components.X64]
  SpamPkg/MmiEntrySpam/MmiEntrySpam.inf
