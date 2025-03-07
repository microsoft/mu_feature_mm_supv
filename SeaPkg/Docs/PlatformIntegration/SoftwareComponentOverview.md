# Software Components of the SEA

This section of documentation is focused on the software components of the SEA that are important during platform
integration.

The SEA provides a software implementation that installs the MM foundation for the Intel X64 architecture. In order to
load SEA and MM Supervisor properly, certain software prerequisites (libraries, drivers, hobs, etc.) needs to be met,
most of which are included in this package.

By including the proper software components, a platform can ensure the SEA feature function as intended and the platform
can meet Secured-core PC specification requirements. To enable an end-to-end Standalone MM based Secured Core solution,
custom requirements may exist in adjacent UEFI firmware components.

For more general background about the steps necessary to integrate the MM Supervisor to work with SEA, please review the
[Platform Integration Steps](PlatformIntegrationSteps.md).

## SEA PEI Modules

| PEI Module | Location |
| ---| ---|
| MsegSmramPei | SeaPkg/Drivers/MsegSmramPei/MsegSmramPei.inf |

## SEA Standalone MM Core Libraries

| Library | Location |
| --- | ---|
| SmmCpuFeaturesLib | SeaPkg/Library/SmmCpuFeaturesLib/StandaloneMmCpuFeaturesLibStm.inf |

## SEA Standalone MM Entry Point

| MM Component | Location |
| ---| ---|
| MmiEntrySea | SeaPkg/MmiEntrySea/MmiEntrySea.inf |

## SEA Core

| MM Component | Location |
| ---| ---|
| SeaCore | SeaPkg/Core/Stm.inf |

## SEA Libraries

| Library | Location |
| --- | ---|
| BaseCryptLib | SeaPkg/Library/BaseCryptLibMbedTls/BaseCryptLib.inf |
| BasePeCoffLibNegative | SeaPkg/Library/BasePeCoffLibNegative/BasePeCoffLibNegative.inf |
| BasePeCoffValidationLib | SeaPkg/Library/BasePeCoffValidationLib/BasePeCoffValidationLib.inf |
| DxeSeaManifestPublicationLibConfigTable | SeaPkg/Library/DxeSeaManifestPublicationLibConfigTable/DxeSeaManifestPublicationLibConfigTable.inf |
| MbedTlsLib | SeaPkg/Library/MbedTlsLib/MbedTlsLib.inf |
| MpSafeDebugLibSerialPort | SeaPkg/Library/MpSafeDebugLibSerialPort/MpSafeDebugLibSerialPort.inf |
| SimpleMemoryAllocationLib | SeaPkg/Library/SimpleMemoryAllocationLib/SimpleMemoryAllocationLib.inf |
| SimpleSynchronizationLib | SeaPkg/Library/SimpleSynchronizationLib/SimpleSynchronizationLib.inf |
| StmLib | Features/MM_SUPV/SeaPkg/Library/StmLib/StmLib.inf |
| StmPlatformLib | Features/MM_SUPV/SeaPkg/Library/StmPlatformLibNull/StmPlatformLibNull.inf |

## SEA Validation Test Application

| Application | Location |
| --- | ---|
| ResponderValidationTestApp | SeaPkg/Tests/ResponderValidationTest/ResponderValidationTestApp.inf |
