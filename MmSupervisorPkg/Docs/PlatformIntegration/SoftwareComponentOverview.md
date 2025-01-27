# Software Components of the MM Supervisor

This section of documentation is focused on the software components of the MM Supervisor that are useful during
platform integration.

The MM Supervisor provides a software implementation that installs the MM foundation for X64. In order to load MM
Supervisor properly, certain software prerequisites (libraries, drivers, hobs, etc.) needs to be met, most of which are
included in this package.

By including the proper software components, a platform can ensure the MM Supervisor features function as intended and
the platform can meet Secured Core PC specification requirements. To enable an end-to-end Standalone MM based Secured
Core solution, custom requirements may exist in adjacent UEFI firmware components.

For more general background about the steps necessary to integrate the MM Supervisor, please review the
[Platform Integration Steps](PlatformIntegrationSteps.md).

## MM Standalone Mode PEI Modules

| PEI Module | Location |
| ---| ---|
| StandaloneMmHob | MmSupervisorPkg/Drivers/StandaloneMmHob/StandaloneMmHob.inf |

## MM PEI Libraries

| PEI Library | Location |
| ---| ---|
| MmSupervisorUnblockMemoryLib | MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibPei.inf |

## MM Standalone Mode DXE Drivers

| DXE Driver | Location |
| ---| ---|
| StandaloneMmUnblockMem | MmSupervisorPkg/Drivers/StandaloneMmUnblockMem/StandaloneMmUnblockMem.inf |

## MM DXE Libraries

| DXE Library | Location |
| ---| ---|
| DxeMmSupervisorVersionPublicationLib | MmSupervisorPkg/Library/DxeMmSupervisorVersionPublicationLib/DxeMmSupervisorVersionPublicationLib.inf |
| MmSupervisorUnblockMemoryLib | MmSupervisorPkg/Library/MmSupervisorUnblockMemoryLib/MmSupervisorUnblockMemoryLibDxe.inf |

## MM Standalone Mode MM Core

| MM Driver | Location |
| ---| ---|
| MmSupervisorCore | MmSupervisorPkg/Core/MmSupervisorCore.inf |

## MM Standalone Mode MM Drivers

| MM Driver | Location |
| ---| ---|
| MmSupervisorRing3Broker | MmSupervisorPkg/Drivers/MmSupervisorRing3Broker/MmSupervisorRing3Broker.inf |
| MmSupervisorErrorReport | MmSupervisorPkg/Drivers/MmSupervisorErrorReport/MmSupervisorErrorReport.inf |

## MM Standalone User Mode Libraries

*These MM User Mode libraries are expected to be used as is and linked to other MM standalone drivers for standard functionality.*

| Library | Location |
| --- | ---|
| BaseIoLibIntrinsic | MmSupervisorPkg/Library/BaseIoLibIntrinsicSysCall/BaseIoLibIntrinsic.inf |
| BaseLib | MmSupervisorPkg/Library/BaseLibSysCall/BaseLib.inf |
| StandaloneMmCommunicationLib | MmSupervisorPkg/Library/StandaloneMmCommunicationLib/StandaloneMmCommunicationLib.inf |
| StandaloneMmDriverEntryPoint | MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf |
| StandaloneMmHobLibSyscall | MmSupervisorPkg/Library/StandaloneMmHobLibSyscall/StandaloneMmHobLibSyscall.inf |
| StandaloneMmMemMapLib | MmSupervisorPkg/Library/StandaloneMmMemMapLib/StandaloneMmMemMapLib.inf |
| StandaloneMmServicesTableLib | MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf |
| StandaloneMmSystemTableLib | MmSupervisorPkg/Library/StandaloneMmSystemTableLib/StandaloneMmSystemTableLib.inf |
| SysCallLib | MmSupervisorPkg/Library/SysCallLib/SysCallLib.inf |
