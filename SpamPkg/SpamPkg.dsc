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
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  PciLib|MdePkg/Library/BasePciLibPciExpress/BasePciLibPciExpress.inf
  PciExpressLib|MdePkg/Library/BasePciExpressLib/BasePciExpressLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf
  StackCheckFailureHookLib|MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf

[LibraryClasses.common.PEIM]
  PeimEntryPoint|MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLib/PeiServicesTablePointerLib.inf

[LibraryClasses.common.USER_DEFINED]
  StmLib|SpamPkg/Library/StmLib/StmLib.inf
  StmPlatformLib|SpamPkg/Library/StmPlatformLibNull/StmPlatformLibNull.inf
  SynchronizationLib|SpamPkg/Library/SimpleSynchronizationLib/SimpleSynchronizationLib.inf
  HashLib|SpamPkg/Library/HashLibTpm2Raw/HashLibTpm2Raw.inf
  Tpm2CommandLib|SecurityPkg/Library/Tpm2CommandLib/Tpm2CommandLib.inf
  Tpm2DeviceLib|SecurityPkg/Library/Tpm2DeviceLibDTpm/Tpm2DeviceLibDTpmStandaloneMm.inf
  Tpm2DebugLib|SecurityPkg/Library/Tpm2DebugLib/Tpm2DebugLibNull.inf
  MemoryAllocationLib|SpamPkg/Library/SimpleMemoryAllocationLib/SimpleMemoryAllocationLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  PeCoffLibNegative|SpamPkg/Library/BasePeCoffLibNegative/BasePeCoffLibNegative.inf
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  SecurePolicyLib|MmSupervisorPkg/Library/SecurePolicyLib/SecurePolicyLib.inf

[Components]
  SpamPkg/Drivers/MsegSmramPei/MsegSmramPei.inf {
    <LibraryClasses>
      NULL|MdePkg/Library/StackCheckLib/StackCheckLibStaticInit.inf
  }

  SpamPkg/Library/MpSafeDebugLibSerialPort/MpSafeDebugLibSerialPort.inf
  SpamPkg/Library/StmLib/StmLib.inf
  SpamPkg/Library/StmPlatformLibNull/StmPlatformLibNull.inf

[Components.X64]
  SpamPkg/Core/Stm.inf {
    <LibraryClasses>
      NULL|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
  }
  SpamPkg/MmiEntrySpam/MmiEntrySpam.inf

  SpamPkg/Library/SimpleSynchronizationLib/SimpleSynchronizationLib.inf
  SpamPkg/Library/SmmCpuFeaturesLib/StandaloneMmCpuFeaturesLibStm.inf
  SpamPkg/Library/BasePeCoffLibNegative/BasePeCoffLibNegative.inf
  SpamPkg/Library/HashLibTpm2Raw/HashLibTpm2Raw.inf
  SpamPkg/Library/SimpleMemoryAllocationLib/SimpleMemoryAllocationLib.inf
