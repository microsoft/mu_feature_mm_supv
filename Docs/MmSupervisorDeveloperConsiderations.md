# Microsoft MM Supervisor Developer Considerations

The objective is to binary release MM Supervisor as core component. Thus ideally there should be platform DSC and FDF
file change to include these entries into the UEFI code base for core capabilities.

There are 4 essential drivers to be added to the device UEFI code base:

* `StandaloneMmUnblockMem.efi`
* `PiSmmIpl.efi`
* `MmSupervisorCore.efi`
* `MmSupervisorRing3Broker.efi`

One requirement is that both of the drivers above and other MM drivers should reside in the same firmware volume. In
the current design, the MM Supervisor will not look for extra FVs once it has exited its entry point.

## MM Drivers Implementation/Conversion

This section targets the MM handler drivers of which module types are `DXE_SMM_DRIVER`. All `gSmst` table entries will have
a one-to-one mapped field in `gMmst`. But there are still some limitations for currently existing MM handler drivers.

Once the MM Supervisor is loaded, the data it can consumes must solely come from the HOB list, meaning SMM handlers
drivers (type `DXE_SMM_DRIVER`) will not be able to consume the protocols, dependencies or event notification from
DXE drivers unless relayed by a combination of one DXE driver communicate to a corresponding MMI handler.

Due to the above reasons, there some functionalities that not present in the MM Supervisor environment:

1. Dynamic PCD consumption
1. `gBS` services, i.e. memory allocation and free, get DXE memory map
1. `gDS` services, i.e. install or check configuration tables
1. For MM drivers that needs to access non-MMRAM region, an explicit `MmUnblockMemoryRequest` call needs to be
   invoked prior to its usage. Knowing the limitations listed below:
    * When installation of MM foundation occurs in DXE phase, the `MmUnblockMemoryRequest` will not be available from
      the beginning in DXE until `gEfiMmBaseProtocolGuid` is installed. It is suggested to advance the unblock request
      as early as PEI if necessary.
1. The `MmSupervisorRing3Broker` driver has to be the first user mode driver loaded, assuming all user mode drivers
   rely on `gMmst`. Thus the libraries linked to this driver can neither have any dependency on `MmServicesTableLib`
   nor attempt to access the `EFI_MM_SYSTEM_TABLE` passed in from library constructors.

### Platform Specific Isolation Policy Configuration

This section describes how a platform can choose to add or remove protected MSRs, IO, memory region and instruction
execution (if supported) based on platform needs.

There is a minimum requirement for SMM isolation policy published by Microsoft where each platform has to block certain
MSR, IO and memory region accesses to meet the criteria for Level 3 Secured-core PC. So a platform has to fullfil these
requirements.

If platform has other resources would like to protect, i.e. proprietary MSR for special purpose, MMIO region for secure
device, etc, platform can elect to add these entries to the corresponding section of MM Supervisor policy file.

### Other MM Supervisor Developer Docs

Refer to these documents for more technical details about integrating the MM Supervisor.

* [MM Supervisor Platform Integration Steps](../MmSupervisorPkg/Docs/PlatformIntegration/PlatformIntegrationSteps.md)
* [MM Supervisor Software Component Overview](../MmSupervisorPkg/Docs/PlatformIntegration/SoftwareComponentOverview.md)
* [Using a Deny-by-Default MM Supervisor Policy](../MmSupervisorPkg/Docs/PlatformIntegration/SwitchingToDenyByDefault.md)
