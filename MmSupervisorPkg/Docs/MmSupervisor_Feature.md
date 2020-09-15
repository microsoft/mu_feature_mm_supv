# Microsoft MM Supervisor Introduction

## Overview

The Microsoft MM Supervisor brings new levels of security and usability to PC management mode. It is a new feature of
UEFI that enables platform adaptive isolation protection under MM environment. The MM Supervisor intends to leverage
standalone MM framework and CPU privilege level management to implement Kernel and User mode software environment for MM
handler drivers. The objective is to enable platform MM isolation with binary release model for MM Supervisor and its loader.

### Why Isolating System Management Mode

Traditional UEFI system management mode work flow is described in [Traditional SMM Framework Flow](TraditionalSmmFramework/traditional_smm_framework.md).
This solution has various drawbacks listed below:

* Late loading in the boot phase, so that other malicious DXE code may cause damage before SMM framework was set up
* Excessive interaction with boot code, which involves entangled database with DXE core, exposing extra attack interfaces
* SMI handlers run under Kernel mode, thus highly privileged code execution requires SMI handler author proceed with
extra precaution

More detailed introduction to existed SMM framework setup flow is included in (MmSupervisorDesign/mm_supervisor_design.md)

### Existed Intermediate Solutions

Different silicon partners have their own solutions:

* Intel: **??? (Need some description here)**
* AMD: [SMM supervisor](https://windowspartners.visualstudio.com/Partner_Amd_UEFI/_git/mu_mm_supv)
that will stick to traditional boot flow but change SMI entry point code to demote execution to CPL3 starting from
gEfiDxeSmmReadyToLockProtocolGuid event and screen MSR, IO and memory access by attested platform policy.
* QC: **??? (Need some description here)**

### MM Supervisor Mechanism

* MM foundation initialized early in the boot process and has isolated protocol and configuration table database
* MM supervisor mechanism holds separate service database
* MM drivers and handlers execute under user mode (CPL3)

## OEM Enablement Summary

MM Isolation enablement is comprised of:

1. MM Supervisor UEFI BIOS integration
1. MM drivers implementation/conversion
1. Platform specific isolation policy configuration

### MM Supervisor UEFI BIOS Integration

The objective is to binary release MM Supervisor as core component. Thus ideally there should be platform dsc and fdf
file change to include these entries into the UEFI code base for core capabilities.

There are 4 essential drivers to be added to the device UEFI code base:

* ```StandaloneMmUnblockMem.efi```
* ```PiSmmIpl.efi```
* ```MmSupervisorCore.efi```
* ```MmSupervisorRing3Broker.efi```

One requirement is that both of the drivers above and other MM drivers should reside in the same firmware volume. For
current design, the MM Supervisor will not look for extra FVs once it has exited its entry point.

### MM Drivers Implementation/Conversion

This section targets the SMM handler drivers of which module types are DXE_SMM_DRIVER. All gSmst table entries will have
a one-to-one mapped field in gMmst. But there are still some limitations for currently existed SMM handler drivers.

Once MM Supervisor is loaded, the data it can consume soly come from hob list, meaning SMM handlers drivers(type DXE_SMM_DRIVER)
will not be able to consume the protocols, dependencies or event notification from DXE drivers unless relayed by a
combination of one DXE driver communicate to one MM handler.

Due to the above reason, there some functionalities that will not be provided in MM environment:

1. Dynamic PCD consumption
1. gBS services, i.e. memory allocation and free, get DXE memory map
1. gDS services, i.e. install or check configuration tables
1. For MM drivers that needs to access non-MMRAM region, an explicit MmUnblockMemoryRequest call needs to be invoke prior
to its usage. Knowing the limitations listed below:
    * When installation of MM foundation occurs in DXE phase, the MmUnblockMemoryRequest will not be available from the beginning
in DXE till gEfiMmBaseProtocolGuid is installed. It is suggested to advance the unblock request as early as PEI if necessary.
    * When MM foundation is installed in PEI, TBD...
1. `MmSupervisorRing3Broker` driver has to be the first user mode driver loaded, assuming all user mode driver relies on
gMmst. Thus the libraries linked to this driver can neither have any dependency on MmServicesTableLib nor attempt to
access the EFI_MM_SYSTEM_TABLE passed in from library constructors.

### Platform Specific Isolation Policy Configuration

This section describes how a platform can choose to add or remove protected MSRs, IO, memory region and instruction
execution (if supported) based on platform needs.

There is a minimum requirement for SMM isolation policy published by Microsoft where each platform has to block certain
MSR, IO and memory region accesses to meet the criteria for Level 3 Secured Core PC environment. So a platform has to
fullfil these requirements. (TODO: Link TBD)

If platform has other resources would like to protect, i.e. proprietary MSR for special purpose, MMIO region for secure
device, etc, platform can elect to add these entries to the corresponding section of policy file. Specific policy
definition can be found [here](TODO:TBD).

## UEFI Implementation Details

1. [**Design:** Proposed MM Supervisor boot flow and isolation mechanism](MmSupervisorDesign/mm_supervisor_design.md)
1. [**Tradition:** Introduction to traditional SMM implementation](TraditionalSmmFramework/traditional_smm_framework.md)

## OEM Integration Guide

1. [**Integration:** MM Supervisor Integration Guides](PlatformIntegration/PlatformIntegrationOverview.md)
