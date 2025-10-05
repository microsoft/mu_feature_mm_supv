# MM Supervisor Platform Integration

The MM Supervisor source code is intended to be used as-is by platforms. In order to integrate the MM Supervisor into
a platform firmware it is important to consider higher-level integration challenges specific to the platform in addition
to the required code changes to integrate all of the pieces.

## High-Level Considerations

1. [Standalone MM Changes](#standalone-mm-changes) - The supervisor will use Standalone MM as opposed to Traditional MM.
SMM modules and libraries will need to be converted to be compatible with Standalone MM.

1. [Silicon Vendor Changes](#silicon-vendor-changes) - The silicon vendor firmware may need changes for:
    1. Standalone MM compatibility
    1. Privilege constraints imposed by the supervisor

1. [Platform Data Requirements](#platform-data-requirements) - The MM Supervisor requires a new set of industry standard
defined data structures in addition to supervisor-specific data structures to be produced by the platform.

1. [Platform API Calls](#platform-api-calls) - Services that might need to be called by a platform.

1. [MM Supervisor Code Integration](#mm-supervisor-code-integration) - How to best integrate the `MmSupervisorPkg`
collateral into a platform firmware.

1. [Platform Security Goals](TODO/SUPERVISOR_SECURITY_OVERVIEW.md) - The MM Supervisor aims to improve security. It is
important to understand the goals of the supervisor and how that aligns with the platform security goals.

1. [MM Driver Load Process](TODO/DRIVER_LOAD_PROCESS.md) - The platform might need to organize MM modules differently
for the MM IPL than what was previously used for Traditional MM.

## Standalone MM Changes

Begin by reading the Standalone MM section of the Platform Initialization (PI) Specification to gain a basic
understanding of Standalone MM.

The following basic steps can be used to convert a Traditional MM library/module to Standalone MM:

- Change the driver entry point prototype from the Traditional MM API to the Standalone MM API.
  - The system table should be of type `EFI_MM_SYSTEM_TABLE`
  - The driver will now use `StandaloneMmDriverEntryPoint`

- In target INF files, use `MM_STANDALONE` as `MODULE_TYPE`
- In target INF files, set `PI_SPECIFICATION` version to `0x00010032`
- Update any `DXE_SMM_DRIVER` libraries that will now be ported for the Standalone MM environment, add support for the
  `MM_STANDALONE` and `MM_CORE_STANDALONE` driver types
- For packages that contains libraries/modules shared with consumers that will be a mix of Traditional MM and
  Standalone MM, consider the file path. In many cases, code sharing can be maximized for both cases by providing a
  Traditional MM INF and a Standalone MM INF in the same directory. Where common code is placed in a .c file included
  in both INF files and each INF has a corresponding .c file unique to its module type (e.g. different entry point
  type). This also has the benefit that the INF file path remains constant so it does not break present consumers while
  the new Standalone MM INF can be called `XxxStandaloneMm.inf`.
- Use `MemoryAllocationLib` functions to allocate and free memory as opposed to `gSmst` or `gMmst` directly. This can
  improve portability between the two services tables
- Find an alternative solution for `gBS`, `gDS`, and other DXE environment accesses
- Find an alternative solution for any PCDs that are not FixedAtBuild. The PCD protocol is not available within the
  Standalone MM environment
- Check MM driver DEPEX statements and dispatch order after removing DXE protocols to ensure dispatch requirements are
  still met.
- Determine the TSEG size needed. After changing the fundamental SMM core, additional TSEG size may be required.
- MM handlers should start to use `MmCommBufferValid` interface to validate incoming communicate buffers, instead of
  traditionally used `MmIsBufferOutsideMmValid`.

## Silicon Vendor Changes

First, determine whether the silicon vendor code already supports Standalone MM. If it does not, the platform owner
will either need to port the silicon vendor code directly (if practical) or work with the silicon vendor to enable
Standalone MM support.

In addition to the conversion guidelines in [Standalone MM Changes](#standalone-mm-changes), the silicon code should
also consider the hardware access limitations that will be enforced by the MM Supervisor policy. Conversely, the
MM Supervisor policy for the platform should consider the unique enforcements that should be applied for a given
silicon architecture/design.

## Platform Data Requirements

The platform needs to produce the data structures in this section. The structures are consumed by MM Supervisor code to
acquire platform-specific details.

### HOBs Required by MM IPL

1. `gMpInformationHobGuid` - Basic MP information.
   - [StandaloneMmPkg/Include/Guid/MpInformation.h](https://github.com/tianocore/edk2/blob/master/StandaloneMmPkg/Include/Guid/MpInformation.h)
   - Note that [`PeiStandaloneMmHobProductionLib`](https://github.com/microsoft/mu_basecore/blob/HEAD/StandaloneMmPkg/Library/PeiStandaloneMmHobProductionLib/PeiStandaloneMmHobProductionLib.inf)
   can be used to help produce this HOB.
1. `gEfiMmPeiMmramMemoryReserveGuid`/`gEfiSmmSmramMemoryGuid` - Describes MMRAM regions present, which must be updated
   through the `SmmRelocationLib` if using MU releases after 202405.
   - [MdePkg/Include/Guid/SmramMemoryReserve.h](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Guid/SmramMemoryReserve.h)
1. Resource descriptor HOBs with MMIO regions identified - Required to allow MM access to MMIO.
   - By default, the MM Supervisor will apply page table attributes based on the memory described by
   `EFI_HOB_TYPE_RESOURCE_DESCRIPTOR` HOBs. In order for MMIO to be accessible from MM, the MMIO range must be
   described in a resource descriptor HOB where the `EFI_RESOURCE_TYPE` field of the HOB is set to
   `EFI_RESOURCE_MEMORY_MAPPED_IO` or `EFI_RESOURCE_FIRMWARE_DEVICE`.
1. [_Optional_] `gMmProtectedRegionHobGuid` - Any protected MMIO regions such as IOMMU can be described in HOBs with
   this GUID to prevent access from MM.

### PPIs Required for PEI MM IPL

1. MM Access PPI (`gEfiPeiMmAccessPpiGuid`)

### MM Policy

The MM Supervisor policy is a data structure used to communicate the restrictions applied to certain hardware resources
such as I/O ports, MSRs, CPU instructions, and CPU Save State. The policy should be reviewed for each platform in order
as the hardware resources that might need to be restricted will vary across silicon families and platform-specific
security goals.

In order to verify the policy was discovered and read properly, the policy can be verified in debug output. Below is
an example of debug policy output:

``` text
[InitializePolicy] Discovered policy file in FV at 0x7D4BB6D0.
SMM_SUPV_SECURE_POLICY_DATA_V1_0:
Version Major:1
Version Minor:0
Size:0x1E8
MemoryPolicyOffset:0x0
MemoryPolicyCount:0x0
Flags:0
Capabilities:0
PolicyRootOffset:0x28
PolicyRootCount:0x5
Policy Root:
  Version: 1
  PolicyRootSize: 18
  Type: 2
  Offset: A0
  Count: 2
  AccessAttr: DENY
IO: [CF8-CFB] . W
IO: [CFC-CFF] . W
Policy Root:
  Version: 1
  PolicyRootSize: 18
  Type: 3
  Offset: B0
  Count: 20
  AccessAttr: DENY
MSR: [C0000080-C0000080] R W
MSR: [C0000081-C0000084] R W
MSR: [9E-9E] R W
MSR: [1D9-1D9] R W
MSR: [DA0-DA0] R W
MSR: [6A0-6A0] R W
MSR: [6A2-6A2] R W
MSR: [6A4-6A8] R W
MSR: [E4-E4] R W
MSR: [600-600] R W
MSR: [652-652] R W
MSR: [653-653] R W
MSR: [655-655] R W
MSR: [656-656] R W
MSR: [658-658] R W
MSR: [700-700] R W
MSR: [701-701] R W
MSR: [706-706] R W
MSR: [707-707] R W
MSR: [710-710] R W
MSR: [711-711] R W
MSR: [716-716] R W
MSR: [717-717] R W
MSR: [720-720] R W
MSR: [721-721] R W
MSR: [726-726] R W
MSR: [727-727] R W
MSR: [730-730] R W
MSR: [731-731] R W
MSR: [736-736] R W
MSR: [737-737] R W
MSR: [570-570] R W
Policy Root:
  Version: 1
  PolicyRootSize: 18
  Type: 4
  Offset: 1B0
  Count: 3
  AccessAttr: ALLOW
INSTRUCTION: [0] X
INSTRUCTION: [1] X
INSTRUCTION: [2] X
Policy Root:
  Version: 1
  PolicyRootSize: 18
  Type: 5
  Offset: 1C8
  Count: 2
  AccessAttr: ALLOW
SAVESTATE: [0] 10 IoWrite
SAVESTATE: [1] 1 Unconditional
Policy Root:
  Version: 1
  PolicyRootSize: 18
  Type: 1
  Offset: 1E8
  Count: 0
  AccessAttr: DENY
SecurityPolicyCheck - Policy overlap check entry ...
SecurityPolicyCheck - Policy overlap check exit ...
```

For more information about creating a policy and inserting the policy binary into firmware, see the
[MM Policy File](#mm-policy-file) instructions.

## Platform API Calls

These are APIs provided by `MmSupervisorPkg` that the platform might need to invoke if it needs to make use of the
service provided.

1. `MmSupervisorUnblockMemoryLib` - By default, the MM Supervisor will block all memory resources outside of MMRAM.
Regions that need to be accessed must be requested to be unblocked by the MM Supervisor.

## MM Supervisor Code Integration

1. Ensure all submodules for the platform are based on the latest Project Mu version (e.g. "202102")
1. Include this repo as a submodule for your platform repos and set the folder path as `Common/MU_MM_SUPV`
(also add `Common/MU_MM_SUPV` to required repos and module packages in the platform build script):
<https://windowspartners.visualstudio.com/MsCoreUefi_Thanos/_git/msft_mmsupervisor>

> Note: A list of the libraries and modules made available by this package is provided in the
  [Software Component Overview](SoftwareComponentOverview.md).

### Platform DSC statements

1. Add the DSC sections below.

> Note: There might be other silicon specific drivers/libraries a platform will need for these sections, i.e. SPI
flash drivers, SW MMI dispatcher drivers, etc.

``` bash
[PcdsFixedAtBuild]
  gEfiSecurityPkgTokenSpaceGuid.PcdUserPhysicalPresence               | FALSE
  # MM environment only set up the exception handler for the upper 32 entries.
  # The platform should set this to a non-conflicting exception number, otherwise
  # it will be treated as one of the normal types of CPU faults.
  gEfiMdePkgTokenSpaceGuid.PcdStackCookieExceptionVector              | 0x0F

[LibraryClasses.IA32]
  MmSupervisorUnblockMemoryLib|MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibPei.inf
  SmmRelocationLib|UefiCpuPkg/Library/SmmRelocationLib/SmmRelocationLib.inf

[LibraryClasses.X64]
  MmSupervisorUnblockMemoryLib|MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibDxe.inf

[LibraryClasses.X64.MM_CORE_STANDALONE]
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  # Note: Make sure ACPI timer is properly programmed at load time
  TimerLib|PcAtChipsetPkg/Library/AcpiTimerLib/StandaloneAcpiTimerLib.inf
  ExtractGuidedSectionLib|MdePkg/Library/BaseExtractGuidedSectionLib/BaseExtractGuidedSectionLib.inf
  FvLib|StandaloneMmPkg/Library/FvLib/FvLib.inf
  HobLib|StandaloneMmPkg/Library/StandaloneMmCoreHobLib/StandaloneMmCoreHobLib.inf
  MemoryAllocationLib|StandaloneMmPkg/Library/StandaloneMmCoreMemoryAllocationLib/StandaloneMmCoreMemoryAllocationLib.inf
  MemLib|MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorCoreMemLib.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
  StandaloneMmCoreEntryPoint|StandaloneMmPkg/Library/StandaloneMmCoreEntryPoint/StandaloneMmCoreEntryPoint.inf
  CpuExceptionHandlerLib|UefiCpuPkg/Library/CpuExceptionHandlerLib/SmmCpuExceptionHandlerLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibStandaloneMm.inf
  # Note: This API will be removed from core soon, leave the empty shell here
  SmmCpuPlatformHookLib|UefiCpuPkg/Library/SmmCpuPlatformHookLibNull/SmmCpuPlatformHookLibNull.inf
  IhvMmSaveStateSupervisionLib|MmSupervisorPkg/Library/IhvMmSaveStateSupervisionLib/IhvMmSaveStateSupervisionLib.inf
  MmSupervisorCoreInitLib|MmSupervisorPkg/Library/BaseMmSupervisorCoreInitLibNull/BaseMmSupervisorCoreInitLibNull.inf

[LibraryClasses.X64.MM_STANDALONE]
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  TimerLib|PcAtChipsetPkg/Library/AcpiTimerLib/StandaloneAcpiTimerLib.inf
  MmServicesTableLib|MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  MemoryAllocationLib|StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
  HobLib|MmSupervisorPkg/Library/StandaloneMmHobLibSyscall/StandaloneMmHobLibSyscall.inf
  ReportStatusCodeLib|MdeModulePkg/Library/SmmReportStatusCodeLib/StandaloneMmReportStatusCodeLib.inf
  HwResetSystemLib|PcAtChipsetPkg/Library/ResetSystemLib/ResetSystemLib.inf
  StandaloneMmDriverEntryPoint|MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/SmmCryptLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  AdvLoggerAccessLib|MdeModulePkg/Library/AdvLoggerAccessLibNull/AdvLoggerAccessLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibStandaloneMm.inf
  LockBoxLib|MdeModulePkg/Library/SmmLockBoxLib/SmmLockBoxStandaloneMmLib.inf
  MemLib|MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorMemLibSyscall.inf
  Tcg2PhysicalPresenceLib|SecurityPkg/Library/SmmTcg2PhysicalPresenceLib/StandaloneMmTcg2PhysicalPresenceLib.inf
  PlatformSecureLib|SecurityPkg/Library/PlatformSecureLibNull/PlatformSecureLibNull.inf

  BaseLib|MmSupervisorPkg/Library/BaseLibSysCall/BaseLib.inf
  IoLib|MmSupervisorPkg/Library/BaseIoLibIntrinsicSysCall/BaseIoLibIntrinsic.inf
  SysCallLib|MmSupervisorPkg/Library/SysCallLib/SysCallLib.inf

  # This library instance is only necessary if performance tracing is enabled in MM code.
  PerformanceLib|MdeModulePkg/Library/SmmPerformanceLib/StandaloneMmPerformanceLib.inf

[Components.IA32]
  MmSupervisorPkg/Drivers/MmCommunicationBuffer/MmCommunicationBufferPei.inf
!if $(PEI_MM_IPL_ENABLED) == TRUE
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplPei.inf
!endif

[Components.X64]
!if $(PEI_MM_IPL_ENABLED) == TRUE
  # Note: MmIplX64Relay is a 64-bit PEI module.
  #       - Any libraries linked to this module should not make 32-bit PEI assumptions
  #       - Any libraries linked to this module should not use PEI Services
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplX64Relay.inf
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmDxeSupport.inf {
    <LibraryClasses>
      NULL|StandaloneMmPkg/Library/VariableMmDependency/VariableMmDependency.inf
      # Note: This library can be linked against any DXE_DRIVER or DXE_RUNTIME_DRIVER in the platform. It is an
      #       optional library that publishes a UEFI variable with MM Supervisor information. It requires that
      #       an instance of gEdkiiVariablePolicyProtocolGuid (and gMmSupervisorCommunicationProtocolGuid) be
      #       produced in order to publish the variable.
      NULL|MmSupervisorPkg/Library/DxeMmSupervisorVersionPublicationLib/DxeMmSupervisorVersionPublicationLib.inf
  }
!endif
  MmSupervisorPkg/Drivers/StandaloneMmUnblockMem/StandaloneMmUnblockMem.inf
  MmSupervisorPkg/Core/MmSupervisorCore.inf {
    <LibraryClasses>
      # Note that this should be whatever suits the target platform + MM standalone conversion for constructor input arguments
      SmmCpuFeaturesLib|$(PLATFORM_SI_PACKAGE)/Library/SmmCpuFeaturesLib/SmmCpuFeaturesLib.inf
  }
  MmSupervisorPkg/Drivers/MmSupervisorRing3Broker/MmSupervisorRing3Broker.inf {
    <LibraryClasses>
      # Because the Ring 3 Broker is the first MM_STANDALONE driver to load. The MM Performance protocol will
      # not be installed yet.
      PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  }
  # Note: The following driver is only necessary if performance tracing is enabled in MM code.
  MmSupervisorPkg/Drivers/MmSupervisorRing3Performance/MmSupervisorRing3Performance.inf {
    <LibraryClasses>
      # It is recommended to link this instance of the Standalone MM Core performance library against this
      # driver.
      PerformanceLib|MdeModulePkg/Library/SmmCorePerformanceLib/StandaloneMmCorePerformanceLib.inf
  }

  MdeModulePkg/Universal/ReportStatusCodeRouter/Smm/ReportStatusCodeRouterStandaloneMm.inf
  UefiCpuPkg/CpuIo2Smm/CpuIo2StandaloneMm.inf
  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableStandaloneMm.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Universal/Variable/UefiVariablePolicy/Library/VarCheckPolicyLib/VarCheckPolicyLibStandaloneMm.inf
      NULL|MdeModulePkg/Library/VarCheckUefiLib/VarCheckUefiLib.inf
  }
  MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteStandaloneMm.inf
  MdeModulePkg/Universal/Acpi/FirmwarePerformanceDataTableSmm/FirmwarePerformanceStandaloneMm.inf
  SecurityPkg/Tcg/Tcg2Acpi/Tcg2Acpi.inf
  SecurityPkg/Tcg/Tcg2StandaloneMm/Tcg2StandaloneMm.inf {
    <LibraryClasses>
      Tpm2DeviceLib|SecurityPkg/Library/Tpm2DeviceLibDTpm/Tpm2DeviceLibDTpmStandaloneMm.inf
  }

  # Optional
  MsCorePkg/Universal/StatusCodeHandler/Serial/StandaloneMm/SerialStatusCodeHandlerStandaloneMm.inf
  MsWheaPkg/MsWheaReport/Smm/MsWheaReportStandaloneMm.inf
  MmSupervisorPkg/Drivers/MmSupervisorErrorReport/MmSupervisorErrorReport.inf

[BuildOptions.common.EDKII.MM_STANDALONE, BuildOptions.common.EDKII.MM_CORE_STANDALONE]
  #DLink flags to cut out project names from binaries
  MSFT:*_*_*_DLINK_FLAGS = /ALIGN:4096
```

1. Remove the DSC sections below.

``` bash
[Components.X64]
  # MdeModulePkg/Core/PiSmmCore/PiSmmCore.inf
  # MdeModulePkg/Core/PiSmmCore/PiSmmIpl.inf
  # UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.inf

  # MdeModulePkg/Universal/ReportStatusCodeRouter/Smm/ReportStatusCodeRouterSmm.inf
  # MdeModulePkg/Universal/Acpi/FirmwarePerformanceDataTableSmm/FirmwarePerformanceSmm.inf
  # UefiCpuPkg/CpuIo2Smm/CpuIo2Smm.inf
  # MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.inf
  # UefiCpuPkg/PiSmmCommunication/PiSmmCommunicationSmm.inf
  # MsCorePkg/Universal/StatusCodeHandler/Serial/Smm/SerialStatusCodeHandlerSmm.inf
  # SecurityPkg/Tcg/Tcg2Smm/Tcg2Smm.inf
  # MdeModulePkg/Universal/SmmCommunicationBufferDxe/SmmCommunicationBufferDxe.inf
  # MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteSmm.inf
```

1. Given that current Standalone MM environment does not support dynamic PCDs, the SMM drivers currently consuming
dynamic PCDs need to be configured to avoid this.

1. Be aware that if the platform previously loaded the MM IPL in DXE, the MM initialization drivers such as the
MM Control driver might assume the environment is not initialized and clear registers that were set up in the PEI
phase. Modify the drivers as appropriate to avoid losing initialization performed in PEI.

### Platform FDF statements

1. Add the FDF sections below.

Note: There might be other silicon specific drivers a platform will need for these sections

``` bash
[FV.YOUR_PEI_FV]
  INF  MmSupervisorPkg/Drivers/MmCommunicationBuffer/MmCommunicationBufferPei.inf
!if $(PEI_MM_IPL_ENABLED) == TRUE
  INF  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplPei.inf
!endif

[FV.YOUR_POST_MEM_PEI_FV]
!if $(PEI_MM_IPL_ENABLED) == TRUE
  INF  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplX64Relay.inf
  INF  MmSupervisorPkg/Core/MmSupervisorCore.inf
  FILE FREEFORM = gMmSupervisorPolicyFileGuid {
    SECTION RAW = $(POLICY_BIN_PATH)
  }
!endif

[FV.YOUR_DXE_FV]
!if $(PEI_MM_IPL_ENABLED) == TRUE
  INF  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmDxeSupport.inf
!endif
  INF  MmSupervisorPkg/Drivers/StandaloneMmUnblockMem/StandaloneMmUnblockMem.inf
  INF  MmSupervisorPkg/Drivers/MmSupervisorRing3Broker/MmSupervisorRing3Broker.inf

  INF  MdeModulePkg/Universal/ReportStatusCodeRouter/Smm/ReportStatusCodeRouterStandaloneMm.inf
  INF  MdeModulePkg/Universal/Acpi/FirmwarePerformanceDataTableSmm/FirmwarePerformanceStandaloneMm.inf
  INF  UefiCpuPkg/CpuIo2Smm/CpuIo2StandaloneMm.inf
  INF  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableStandaloneMm.inf
  INF  MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteStandaloneMm.inf
  INF  RuleOverride = DRIVER_ACPITABLE SecurityPkg/Tcg/Tcg2Acpi/Tcg2Acpi.inf
  INF  SecurityPkg/Tcg/Tcg2StandaloneMm/Tcg2StandaloneMm.inf

  # Optional
  INF  MsCorePkg/Universal/StatusCodeHandler/Serial/StandaloneMm/SerialStatusCodeHandlerStandaloneMm.inf
  INF  MsWheaPkg/MsWheaReport/Smm/MsWheaReportStandaloneMm.inf
  INF  MmSupervisorPkg/Drivers/MmSupervisorErrorReport/MmSupervisorErrorReport.inf

[Rule.Common.MM_CORE_STANDALONE]
  FILE MM_CORE_STANDALONE = $(NAMED_GUID) {
    PE32     PE32           $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI       STRING="$(MODULE_NAME)" Optional
    VERSION  STRING="$(INF_VERSION)" Optional BUILD_NUM=$(BUILD_NUMBER)
  }

[Rule.Common.MM_STANDALONE]
  FILE MM_STANDALONE = $(NAMED_GUID) {
    SMM_DEPEX    SMM_DEPEX Optional      $(INF_OUTPUT)/$(MODULE_NAME).depex
    PE32     PE32                    $(INF_OUTPUT)/$(MODULE_NAME).efi
    UI       STRING="$(MODULE_NAME)" Optional
    VERSION  STRING="$(INF_VERSION)" Optional BUILD_NUM=$(BUILD_NUMBER)
  }
```

1. Remove the FDF sections below.

``` bash
[FV.YOUR_DXE_FV]
  # INF  MdeModulePkg/Core/PiSmmCore/PiSmmIpl.inf
  # INF  MdeModulePkg/Core/PiSmmCore/PiSmmCore.inf
  # INF  UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.inf

  # INF  MdeModulePkg/Universal/ReportStatusCodeRouter/Smm/ReportStatusCodeRouterSmm.inf
  # INF  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm.inf
  # INF  MdeModulePkg/Universal/Acpi/FirmwarePerformanceDataTableSmm/FirmwarePerformanceSmm.inf
  # INF  UefiCpuPkg/CpuIo2Smm/CpuIo2Smm.inf
  # INF  UefiCpuPkg/PiSmmCommunication/PiSmmCommunicationSmm.inf
  # INF  MdeModulePkg/Universal/SmmCommunicationBufferDxe/SmmCommunicationBufferDxe.inf
  # INF  MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteSmm.inf

  # INF  RuleOverride = DRIVER_ACPITABLE SecurityPkg/Tcg/Tcg2Smm/Tcg2Smm.inf
```

#### MM Policy File

1. Create secure policy binary file using [MmSupervisorPkg/SupervisorPolicyTools/SupervisorPolicyMaker.py](../../SupervisorPolicyTools/SupervisorPolicyMaker.py)
per platform needs (an example can be found in [SupervisorPolicyTools folder](../../SupervisorPolicyTools/MmIsolationPoliciesExample.xml)).
1. Place the created secure policy as a FREEFORM binary in the FDF file within the same FV as the MmSupervisor image.
The file should be GUIDed as `gMmSupervisorPolicyFileGuid` so it can be discovered by the MM Supervisor.

#### MM Policy XML File Schema

An example can be found in [SupervisorPolicyTools folder](../../SupervisorPolicyTools/MmIsolationPoliciesExample.xml).

1. All XML files should use the `<SmmIsolationPolicy>` as the root tag.
1. Under the root, all supported protection categories should listed under `<SmmCategory>` nodes, with a `name` attribute
denoting the specific category.

    - Currently ony support 'MSR', 'IO', 'INSTRUCTION' and 'SAVESTATE'
    - There should be only one `<SmmCategory>` node for each category in a single XML file.

1. For each protection category group, a `<PolicyAccessAttribute>` must be included to indicate the corresponding policy
entries belong to a deny list or allow list.
1. In addition to policy attributes, multiple `<PolicyEntry>` nodes coud be included in a `<SmmCategory>` group. This will
be an individual policy protection entry.

- For `MSR` protection group, each entry should be described with the following 3 children nodes:

```xml
<StartAddress Value="0xC0000080"/> <!-- The starting base address of MSR -->
<Size Value="0x2"/> <!-- The range of MSRs to be protected. In this example, MSR 0xC0000080 and 0xC0000081 will be
protected. -->
<SecurityAttributes Value="Read | Write" /> <!-- Indicate the intended MSR access type to be protected. Only Read, Write
or their combination are accepted. -->
```

- For `IO` protection group, each entry should be described with the following 3 children nodes:

```xml
<StartAddress Value="0xCF8"/> <!-- The IO port to be protected -->
<Size Value="0x4"/> <!-- The width of IO ports access to be protected. -->
<SecurityAttributes Value="Read | Write | StrictWidth" /> <!-- Indicate the intended IO access type to be protected.
Only Read, Write, StrictWidth or their combination are accepted. Note that when StrictWidth is indicated, only the access
of StartAddress with specific Size width will be protected. Otherwise, it will be similar to MSR policy entry -->
```

- For `INSTRUCTION` protection group, each entry should be described with the following 3 children nodes:

```xml
<Instruction Value="HLT" /> <!-- The instruction name to be protected, only HLT, WBINVD and CLI are supported. -->
<Size Value="0x4"/> <!-- The width of IO ports access to be protected. -->
<SecurityAttributes Value="Execute" /> <!-- Only execute attribute is allowed here. -->
```

- For `SAVESTATE` protection group, each entry should be described with the following 3 children nodes:

```xml
<SaveStateField Value="IO_TRAP" /> <!-- The save state register name to be protected, only IO_TRAP and RAX are supported. -->
<SecurityAttributes Value="Read" /> <!-- Indicate the intended save state access type to be protected. Only Read and
LimitedRead are accepted. Note that when LimitedRead is indicated, the AccessCondition node must be supplied. -->
<AccessCondition Value="IoWrite" /> <!-- Optional node to indicate what condition of LimitedRead can be accepted. Only
IoWrite is accepted for RAX LimitedRead entry. -->
```
