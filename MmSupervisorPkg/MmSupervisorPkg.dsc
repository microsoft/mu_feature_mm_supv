# *******************************************************************************
# Package DSC file for CI build of MmSupervisorPkg.
#
# Copyright(C) 2020 Advanced Micro Devices, Inc. All rights reserved.
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# *******************************************************************************



[Defines]
  PLATFORM_NAME                  = MmSupervisor
  PLATFORM_GUID                  = 6D68DC74-D29E-405B-9B8E-EE5E00728FFC
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x0001001A
  OUTPUT_DIRECTORY               = Build/MmSupervisorPkg
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses.common]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  PciLib|MdePkg/Library/BasePciLibPciExpress/BasePciLibPciExpress.inf
  PciExpressLib|MdePkg/Library/BasePciExpressLib/BasePciExpressLib.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  PeimEntryPoint|MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
  CacheMaintenanceLib|MdePkg/Library/BaseCacheMaintenanceLibNull/BaseCacheMaintenanceLibNull.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  UefiCpuLib|UefiCpuPkg/Library/BaseUefiCpuLib/BaseUefiCpuLib.inf
  MuTelemetryHelperLib|MsWheaPkg/Library/MuTelemetryHelperLib/MuTelemetryHelperLib.inf
  MsWheaEarlyStorageLib|MsWheaPkg/Library/MsWheaEarlyStorageLibNull/MsWheaEarlyStorageLibNull.inf
  MmMemoryProtectionHobLib|MdeModulePkg/Library/MemoryProtectionHobLibNull/MmMemoryProtectionHobLibNull.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  SecurityLockAuditLib|MdeModulePkg/Library/SecurityLockAuditDebugMessageLib/SecurityLockAuditDebugMessageLib.inf
  DebugAgentLib|MdeModulePkg/Library/DebugAgentLibNull/DebugAgentLibNull.inf
  SerialPortLib|MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  LocalApicLib|UefiCpuPkg/Library/BaseXApicLib/BaseXApicLib.inf
  VmgExitLib|UefiCpuPkg/Library/VmgExitLibNull/VmgExitLibNull.inf
  MtrrLib|UefiCpuPkg/Library/MtrrLib/MtrrLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

!if $(TOOL_CHAIN_TAG) == VS2017 or $(TOOL_CHAIN_TAG) == VS2015 or $(TOOL_CHAIN_TAG) == VS2019 or $(TOOL_CHAIN_TAG) == VS2022
  #if debug is enabled provide StackCookie support lib so that we can link to /GS exports
  NULL|MdePkg/Library/BaseBinSecurityLibRng/BaseBinSecurityLibRng.inf
  BaseBinSecurityLib|MdePkg/Library/BaseBinSecurityLibRng/BaseBinSecurityLibRng.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf
!else
  # otherwise use the null version for GCC and CLANG
  BaseBinSecurityLib|MdePkg/Library/BaseBinSecurityLibNull/BaseBinSecurityLibNull.inf
!endif

[LibraryClasses.IA32]
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf
  PeimEntryPoint|MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLibIdt/PeiServicesTablePointerLibIdt.inf
  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
  TimerLib|PcAtChipsetPkg/Library/AcpiTimerLib/PeiAcpiTimerLib.inf

[LibraryClasses.X64.PEIM]
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/SecPeiCpuExceptionHandlerLib.inf
  TimerLib|PcAtChipsetPkg/Library/AcpiTimerLib/BaseAcpiTimerLib.inf

[LibraryClasses.X64]
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeLib|MdePkg/Library/UefiRuntimeLib/UefiRuntimeLib.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  SortLib|MdeModulePkg/Library/BaseSortLib/BaseSortLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf

[LibraryClasses.X64.MM_CORE_STANDALONE]
  ExtractGuidedSectionLib|MdePkg/Library/BaseExtractGuidedSectionLib/BaseExtractGuidedSectionLib.inf
  FvLib|StandaloneMmPkg/Library/FvLib/FvLib.inf
  HobLib|StandaloneMmPkg/Library/StandaloneMmCoreHobLib/StandaloneMmCoreHobLib.inf
  MemoryAllocationLib|StandaloneMmPkg/Library/StandaloneMmCoreMemoryAllocationLib/StandaloneMmCoreMemoryAllocationLib.inf
  StandaloneMmCoreEntryPoint|StandaloneMmPkg/Library/StandaloneMmCoreEntryPoint/StandaloneMmCoreEntryPoint.inf
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/SmmCpuExceptionHandlerLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  SmmCpuFeaturesLib|UefiCpuPkg/Library/SmmCpuFeaturesLib/StandaloneMmCpuFeaturesLib.inf
  SmmCpuPlatformHookLib|UefiCpuPkg/Library/SmmCpuPlatformHookLibNull/SmmCpuPlatformHookLibNull.inf
  HwResetSystemLib|PcAtChipsetPkg/Library/ResetSystemLib/ResetSystemLib.inf
  TimerLib|PcAtChipsetPkg/Library/AcpiTimerLib/StandaloneMmAcpiTimerLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibStandaloneMm.inf
  SmmPolicyGateLib|MmSupervisorPkg/Library/SmmPolicyGateLib/SmmPolicyGateLib.inf
  MemLib|MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorCoreMemLib.inf
  IhvSmmSaveStateSupervisionLib|MmSupervisorPkg/Library/IhvMmSaveStateSupervisionLib/IhvMmSaveStateSupervisionLib.inf

[LibraryClasses.X64.MM_STANDALONE]
  BaseLib|MmSupervisorPkg/Library/BaseLibSysCall/BaseLib.inf
  IoLib|MmSupervisorPkg/Library/BaseIoLibIntrinsicSysCall/BaseIoLibIntrinsic.inf
  CpuLib|MmSupervisorPkg/Library/BaseCpuLibSysCall/BaseCpuLib.inf
  SysCallLib|MmSupervisorPkg/Library/SysCallLib/SysCallLib.inf
  MmServicesTableLib|MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  MemoryAllocationLib|StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
  HobLib|MmSupervisorPkg/Library/StandaloneMmHobLibSyscall/StandaloneMmHobLibSyscall.inf
  ReportStatusCodeLib|MdeModulePkg/Library/SmmReportStatusCodeLib/StandaloneMmReportStatusCodeLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibStandaloneMm.inf
  HwResetSystemLib|PcAtChipsetPkg/Library/ResetSystemLib/ResetSystemLib.inf
  StandaloneMmDriverEntryPoint|MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
  PlatformSecureLib|SecurityPkg/Library/PlatformSecureLibNull/PlatformSecureLibNull.inf
  MemLib|MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorMemLibSyscall.inf

[LibraryClasses.X64.UEFI_APPLICATION]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf

  UnitTestLib|UnitTestFrameworkPkg/Library/UnitTestLib/UnitTestLib.inf
  UnitTestPersistenceLib|UnitTestFrameworkPkg/Library/UnitTestPersistenceLibNull/UnitTestPersistenceLibNull.inf
  UnitTestResultReportLib|UnitTestFrameworkPkg/Library/UnitTestResultReportLib/UnitTestResultReportLibDebugLib.inf

[Components.IA32]
  MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibPei.inf

  MmSupervisorPkg/Drivers/StandaloneMmHob/StandaloneMmHob.inf
  MmSupervisorPkg/Drivers/MmCommunicationBuffer/MmCommunicationBufferPei.inf
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplPei.inf

[Components.X64]
  MmSupervisorPkg/Library/BaseCpuLibSysCall/BaseCpuLib.inf
  MmSupervisorPkg/Library/BaseIoLibIntrinsicSysCall/BaseIoLibIntrinsic.inf
  MmSupervisorPkg/Library/BaseLibSysCall/BaseLib.inf
  MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibDxe.inf
  MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
  MmSupervisorPkg/Library/StandaloneMmHobLibSyscall/StandaloneMmHobLibSyscall.inf
  MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  MmSupervisorPkg/Library/SysCallLib/SysCallLib.inf
  MmSupervisorPkg/Library/SmmPolicyGateLib/SmmPolicyGateLib.inf
  MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorCoreMemLib.inf
  MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorMemLibSyscall.inf
  MmSupervisorPkg/Library/IhvMmSaveStateSupervisionLib/IhvMmSaveStateSupervisionLib.inf

  MmSupervisorPkg/Core/MmSupervisorCore.inf

  MmSupervisorPkg/Drivers/MmSupervisorErrorReport/MmSupervisorErrorReport.inf
  MmSupervisorPkg/Drivers/MmSupervisorRing3Broker/MmSupervisorRing3Broker.inf
  MmSupervisorPkg/Drivers/StandaloneMmIpl/PiSmmIpl.inf
  MmSupervisorPkg/Drivers/StandaloneMmUnblockMem/StandaloneMmUnblockMem.inf
  MmSupervisorPkg/Drivers/MmCommunicationBuffer/MmCommunicationBufferDxe.inf
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplX64Relay.inf
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmDxeSupport.inf

  MmSupervisorPkg/Test/MmPagingAuditTest/UEFI/MmPagingAuditApp.inf
  MmSupervisorPkg/Test/MmSupvRequestUnitTestApp/MmSupvRequestUnitTestApp.inf
  MmSupervisorPkg/Test/MmiHandlerProfileInfo/MmiHandlerProfileInfo.inf

[BuildOptions.common.EDKII.DXE_SMM_DRIVER]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES
