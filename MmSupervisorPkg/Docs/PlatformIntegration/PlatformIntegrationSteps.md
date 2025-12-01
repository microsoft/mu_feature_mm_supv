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

> Note that the PEI module `MmSupervisorPkg/Drivers/StandaloneMmHob` will produce `gMmCoreDataHobGuid` which is used to
  hold [`MM_CORE_PRIVATE_DATA`](https://github.com/tianocore/edk2/blob/master/StandaloneMmPkg/Include/Guid/MmCoreData.h)
  and `gMmCoreMmProfileGuid` which is used to hold `MM_CORE_MM_PROFILE_DATA` as defined in `MmSupervisorPkg`.

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

1. Add the DSC sections below. This is the basic setup required, but platforms may require additional
drivers for proper function.

``` bash
[PcdsFixedAtBuild]
  gEfiSecurityPkgTokenSpaceGuid.PcdUserPhysicalPresence               | FALSE
  # MM environment only set up the exception handler for the upper 32 entries.
  # The platform should set this to a non-conflicting exception number, otherwise
  # it will be treated as one of the normal types of CPU faults.
  gEfiMdePkgTokenSpaceGuid.PcdStackCookieExceptionVector              | 0x0F

[LibraryClasses.IA32.PEIM, LibraryClasses.X64.PEIM]
  # Replace instances of UefiCpuPkg/Library/MmUnblockMemoryLib/MmUnblockMemoryLib.inf with Mm Supervisor Version
  MmSupervisorUnblockMemoryLib  |MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibPei.inf

  # Replace instances of MdePkg/Library/MmUnblockMemoryLib/MmUnblockMemoryLibNull.inf
[LibraryClasses.X64]
  MmSupervisorUnblockMemoryLib  |MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibDxe.inf

[LibraryClasses.X64.MM_CORE_STANDALONE]

  # Mm Supervisor only supports FixedatBuild/PatchableInModule PCDs
  PcdLib                        |MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

  # Library classes coming from MmSupervisorPkg 
  IhvMmSaveStateSupervisionLib  |MmSupervisorPkg/Library/IhvMmSaveStateSupervisionLib/IhvMmSaveStateSupervisionLib.inf
  MemLib                        |MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorCoreMemLib.inf
  MemoryAllocationLib           |StandaloneMmPkg/Library/StandaloneMmCoreMemoryAllocationLib/StandaloneMmCoreMemoryAllocationLib.inf
  MmSupervisorCoreInitLib       |MmSupervisorPkg/Library/BaseMmSupervisorCoreInitLibNull/BaseMmSupervisorCoreInitLibNull.inf

  # Library Classes coming from UefiCpuPkg
  CpuExceptionHandlerLib        |UefiCpuPkg/Library/CpuExceptionHandlerLib/SmmCpuExceptionHandlerLib.inf
  SmmCpuPlatformHookLib         |UefiCpuPkg/Library/SmmCpuPlatformHookLibNull/SmmCpuPlatformHookLibNull.inf

  # Library Classes coming from StandaloneMmPkg
  HobLib                        |StandaloneMmPkg/Library/StandaloneMmCoreHobLib/StandaloneMmCoreHobLib.inf
  FvLib                         |StandaloneMmPkg/Library/FvLib/FvLib.inf
  StandaloneMmCoreEntryPoint    |StandaloneMmPkg/Library/StandaloneMmCoreEntryPoint/StandaloneMmCoreEntryPoint.inf

  # Library Classes coming from MdePkg
  DevicePathLib                 |MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibStandaloneMm.inf
  ExtractGuidedSectionLib       |MdePkg/Library/BaseExtractGuidedSectionLib/BaseExtractGuidedSectionLib.inf
  ReportStatusCodeLib           |MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf

  # Note: If chosen timer lib is platform dependent, and needs to be initialized before
  #  MmSupervisor is executed.
  TimerLib                      |PcAtChipsetPkg/Library/AcpiTimerLib/StandaloneAcpiTimerLib.inf


[LibraryClasses.X64.MM_STANDALONE]
  BaseLib                       |MmSupervisorPkg/Library/BaseLibSysCall/BaseLib.inf
  HobLib                        |MmSupervisorPkg/Library/StandaloneMmHobLibSyscall/StandaloneMmHobLibSyscall.inf
  IoLib                         |MmSupervisorPkg/Library/BaseIoLibIntrinsicSysCall/BaseIoLibIntrinsic.inf
  MemLib                        |MmSupervisorPkg/Library/MmSupervisorMemLib/MmSupervisorMemLibSyscall.inf
  MmServicesTableLib            |MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf  
  StandaloneMmDriverEntryPoint  |MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
  SysCallLib                    |MmSupervisorPkg/Library/SysCallLib/SysCallLib.inf

  MemoryAllocationLib           |StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf

  LockBoxLib                    |MdeModulePkg/Library/SmmLockBoxLib/SmmLockBoxStandaloneMmLib.inf
  ReportStatusCodeLib           |MdeModulePkg/Library/SmmReportStatusCodeLib/StandaloneMmReportStatusCodeLib.inf

  DevicePathLib                 |MdePkg/Library/UefiDevicePathLib/UefiDevicePathLibStandaloneMm.inf
  PcdLib                        |MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

  BaseCryptLib                  |CryptoPkg/Library/BaseCryptLib/SmmCryptLib.inf
  OpensslLib                    |CryptoPkg/Library/OpensslLib/OpensslLib.inf
  IntrinsicLib                  |CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf

  # Note: This needs to be a platform chosen ResetSystemLib (which should act as HwResetSystemLib instance)
  #  MmSupervisor is executed.
  HwResetSystemLib              |PcAtChipsetPkg/Library/ResetSystemLib/ResetSystemLib.inf

  PlatformSecureLib             |SecurityPkg/Library/PlatformSecureLibNull/PlatformSecureLibNull.inf
  Tcg2PhysicalPresenceLib       |SecurityPkg/Library/SmmTcg2PhysicalPresenceLib/StandaloneMmTcg2PhysicalPresenceLib.inf

  # Note: This needs to be the platform's chosen TimerLib instance
  TimerLib                      |PcAtChipsetPkg/Library/AcpiTimerLib/StandaloneAcpiTimerLib.inf

  # This library instance is only necessary if performance tracing is enabled in MM code.
  PerformanceLib                |MdeModulePkg/Library/SmmPerformanceLib/StandaloneMmPerformanceLib.inf

# Note: If PEI is x64, change these drivers to x64.
[Components.IA32]
  MmSupervisorPkg/Drivers/StandaloneMmHob/StandaloneMmHob.inf
  MmSupervisorPkg/Drivers/MmCommunicationBuffer/MmCommunicationBufferPei.inf
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplPei.inf

[Components.X64]
  # Note: MmIplX64Relay is a 64-bit PEI module used to support X64 MM Supervisor from 
  #  IA32 PEI phase. 
  #       - Any libraries linked to this module should not make 32-bit PEI assumptions
  #       - Any libraries linked to this module should not use PEI Services
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplX64Relay.inf

  # Runtime Dxe Driver which verifies Communicaiton is working during Dxe phase and provide 
  #  MM Communcation Buffers during Dxe phase.
  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmDxeSupport.inf {
    <LibraryClasses>
      NULL|StandaloneMmPkg/Library/VariableMmDependency/VariableMmDependency.inf
      # Note: This library can be linked against any DXE_DRIVER or DXE_RUNTIME_DRIVER in the platform. It is an
      #       optional library that publishes a UEFI variable with MM Supervisor information. It requires that
      #       an instance of gEdkiiVariablePolicyProtocolGuid (and gMmSupervisorCommunicationProtocolGuid) be
      #       produced in order to publish the variable.
      NULL|MmSupervisorPkg/Library/DxeMmSupervisorVersionPublicationLib/DxeMmSupervisorVersionPublicationLib.inf
  }

  # Supports MM Unblock requests during Dxe phase. 
  MmSupervisorPkg/Drivers/StandaloneMmUnblockMem/StandaloneMmUnblockMem.inf

  MmSupervisorPkg/Core/MmSupervisorCore.inf {
    <LibraryClasses>
      # Note that this should be whatever suits the target platform + MM standalone conversion for constructor input arguments
      SmmCpuFeaturesLib|$(PLATFORM_SI_PACKAGE)/Library/SmmCpuFeaturesLib/SmmCpuFeaturesLib.inf
  }

  # Main communication funnel which allows Ring3 (Standalone MM drivers) to request access to Ring0 data.
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


[BuildOptions.common.EDKII.MM_STANDALONE, BuildOptions.common.EDKII.MM_CORE_STANDALONE]
  # DLink flags to cut out project names from binaries
  # Note: 4K alignment is required to support memory protections. 
  # As the projects proceed, this may not be required anymore, but verify the project.
  MSFT:*_*_*_DLINK_FLAGS = /ALIGN:4096
```

1. Remove the INFs listed below from the Platform DSC, if they exist.

``` bash
[Components.X64]

  # SMM Drivers and Ipl and Core drivers
  # MdeModulePkg/Core/PiSmmCore/PiSmmCore.inf
  # MdeModulePkg/Core/PiSmmCore/PiSmmIpl.inf

  # Functionality for this is part of MmSupervisorCore so it has Ring 0 access
  # UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.inf

  # StandaloneMmPkg/Drivers/StandaloneMmIplPei/StandaloneMmIplPei.inf
  # StandaloneMmPkg/Drivers/MmCommunicationNotifyDxe/MmCommunicationNotifyDxe.inf
  # StandaloneMmPkg/Drivers/MmCommunicationDxe/MmCommunicationDxe.inf

  # Functionality for this is part of MmSupervisorCore so it has Ring 0 access
  # UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuStandaloneMm.inf

  # Modules of type DXE_SMM_DRIVER will not be dispatched, they can all be removed.

```

1. Given that current Standalone MM environment does not support dynamic PCDs, the SMM drivers consuming
dynamic PCDs need to be configured to avoid this. Switching to fixed at build or patchable in module
can be used.

1. Be aware that if the platform previously loaded the MM IPL in DXE, the MM initialization drivers such as the
MM Control driver might assume the environment is not initialized and clear registers that were set up in the PEI
phase. Modify the drivers as appropriate to avoid losing initialization performed in PEI.

1. PiSmmCpuDxeSmm functionality is absorbed into the MmSupervisorCore. The PiSmmCpuDxeSmm is no longer required.

### Platform FDF statements

1. Add the FDF sections below.

Note: There might be other silicon specific drivers a platform will need for these sections

``` bash
[FV.YOUR_PEI_FV]
  INF  MmSupervisorPkg/Drivers/StandaloneMmHob/StandaloneMmHob.inf
  INF  MmSupervisorPkg/Drivers/MmCommunicationBuffer/MmCommunicationBufferPei.inf
  INF  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplPei.inf

[FV.YOUR_POST_MEM_PEI_FV]
  # MmIplX64Relay is only required if PEI is IA32
  INF  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmIplX64Relay.inf
  INF  MmSupervisorPkg/Core/MmSupervisorCore.inf
  FILE FREEFORM = gMmSupervisorPolicyFileGuid {
    SECTION RAW = $(POLICY_BIN_PATH)
  }

[FV.YOUR_DXE_FV]
  INF  MmSupervisorPkg/Drivers/MmPeiLaunchers/MmDxeSupport.inf
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

### Integration Troubleshooting

#### Build Time Failures

- For override validation failures, ensure all submodules are updated to the correct Project Mu version.
- For unresolved external symbols related to BaseLib or IoLib functions, this might indicate that the platform is trying
to use a privileged instruction or function that is intentionally left out by the syscall instance of these libraries.
__These functions will not work in a non-privileged context even if the build errors are resolved__ but can be resolved by
either filing a github issue that extends the syscall interface to support the needed function or by finding an alternative
implementation that does not require privileged access.

#### Runtime Failures

After integrating the Mm Supervisor, verifying that the Standalone MM drivers function correctly is the next step.
This becomes a process of building the platform firmware, and attempting to execute it. Some of the more common
errors are detailed below.

##### The resource HOB range [0x0, 0xNNNN] overlaps with MMRAM range

A resource descriptor HOB's address space overlaps with the MM addresses. This points to the resource descriptor
HOBs being incorrect because resources described should not have any overlap with the MM memory ranges.

##### Non-MM memory region starts with <> clashes with range <>

There are multilple resource descriptor hobs that overlap their memory ranges.
Resource descriptor HOBs are intended to describe system memory. From the system’s perspective, there should
never be overlapping descriptor HOBs. For example, if a flash device is reported as an MMIO resource
descriptor HOB and an APIC is mapped within that same MMIO range, the APIC’s MMIO descriptor HOB adds
no value and only creates confusion. While programmers may benefit from knowing the detailed breakdown
of individual MMIO ranges, the system only needs to know the start and end addresses of the MMIO region.

##### Variable Services never become available during DXE

In a supervised mm system, the variable services MM handler becomes available during the PEI timeframe.
The VariableRuntimeSmmDxe driver requires gSmmVariableWriteGuid and gEfiSmmVariableProtocolGuid to be
installed for callbacks in VariableSmmRuntimeDxe to provide the variable services.

Since variable mm handlers are available from the start of PEI, the NULL library VariableMmDependency is
expected to be linked into a DXE driver (MmSupportDxe is recommend) that will provide these protocols.

##### Exception with Access SMM communication forbidden address

MM Supervisor is strict about memory accesses. To access memory outside of the MM environment,
the memory needs to be unblocked. Similarly, for MMIO regions, the MM Supervisor needs to be
aware of the MMIO regions. MMIO regions should be reported to the system through
resources descriptor hobs.

For the exception below, there is a clear message about the address that resulted
in an access violation. A debugger can be used to step through the code to find what resource
is missing an appropiate unblock or resource descriptor hob. Knowledge of the platform's
memory regions is also beneficial understand what resources is at the offending address.

``` bash
!!!! X64 Exception Type - 0E(#PF - Page-Fault)  CPU Apic ID - 00000000 !!!!
ExceptionData - 0000000000000004  I:0 R:0 U:1 W:0 P:0 PK:0 SS:0 SGX:0
RIP  - 00000000DD5AC03A, CS  - 000000000000005B, RFLAGS - 0000000000010046
RAX  - 0000000000000000, RCX - 00001000000FD010, RDX - 00000FFFF0000000
RBX  - 00001000000FD010, RSP - 00000000DF74BED0, RBP - 00000000DF87B900
RSI  - 8000000000000000, RDI - 00000000DF66E818
R8   - 00000000DF66E800, R9  - 0000000000000000, R10 - 80000000DF724001
R11  - 00000000DF87B840, R12 - 0000000000000000, R13 - 0000000076726473
R14  - 0000000000000040, R15 - 0000006300000000
DS   - 0000000000000053, ES  - 0000000000000053, FS  - 0000000000000053
GS   - 0000000000000053, SS  - 0000000000000053
CR0  - 0000000080010033, CR2 - 00001000000FD010, CR3 - 00000000DF704000
CR4  - 0000000000101E68, CR8 - 0000000000000000
DR0  - 0000000000000000, DR1 - 0000000000000000, DR2 - 0000000000000000
DR3  - 0000000000000000, DR6 - 00000000FFFF0FF0, DR7 - 0000000000000400
GDTR - 00000000DF724000 000000000000007F, LDTR - 0000000000000000
IDTR - 00000000DF738000 00000000000001FF,   TR - 0000000000000070
FXSAVE_STATE - 00000000DF86AC60
Access SMM communication forbidden address (0x1000000FD010)!
```

The platform can compile drivers with optimizations enabled, which can complicate
debugging efforts. Is it possible to modify a single Inf file to disable optimizations
and simplify debugging. This can be done for msvc through the below addition to the Inf.

``` bash
[BuildOptions]
  MSFT:*_*_*_CC_FLAGS = /Od
```

If it would be beneficial to view the assembly that is generated from the source code,
the following can be added to the Inf as well, and msvc will generate .cod files in the
associated build folder corresponding to the source file name.

``` bash
[BuildOptions]
  MSFT:*_*_*_CC_FLAGS = /FAs
```
