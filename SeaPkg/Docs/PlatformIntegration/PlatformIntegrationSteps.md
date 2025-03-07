# SMM Enhanced Attestation (SEA) Platform Integration

The SEA source code is intended to be used as-is by platforms. In order to integrate the SEA core and MM supervisor into
a platform firmware it is important to consider higher-level integration challenges specific to the platform in addition
to the required code changes to integrate all of the pieces.

## High-Level Considerations

1. [MM Supervisor Changes](#mm-supervisor-changes) - The supervisor is accountable for loading SEA core into MSEG region
and protect the resources before SEA is loaded.

1. [Executed Supervisor Validation](#executed-supervisor-validation) - The SEA core is responsible for inspecting the MM
supervisor environment and validating the MM supervisor code and data. This is a critical step in the DRTM process.

1. [Platform Data Requirements](#platform-data-requirements) - The MM Supervisor requires a new set of industry standard
defined data structures in addition to supervisor-specific data structures to be produced by the platform.

1. [SEA Code Integration](#sea-code-integration) - How to best integrate the `SEA core` collateral into a platform firmware.

1. [Platform Security Goals](TODO/SUPERVISOR_SECURITY_OVERVIEW.md) - The MM Supervisor aims to improve security. It is
important to understand the goals of the supervisor and how that aligns with the platform security goals.

1. [MM Driver Load Process](TODO/DRIVER_LOAD_PROCESS.md) - The platform might need to organize MM modules differently
for the MM IPL than what was previously used for Traditional MM.

## MM Supervisor Changes

Begin by reading the [MM supervisor documentation](../../../MmSupervisorPkg/Docs/MmSupervisor_Feature.md) to gain a basic
understanding of Standalone MM and MM supervisor.

In the SEA approach, the SEA is responsible for validating the entire flow of the MMI, which starts from the MMI entrypoint,
jumping to the MM supervisor, and ended with return. This will require the MM entrypoint code to be decoupled from the MM
supervisor, and the new MMI entrypoint code is auditable with respect to the jump point into the MM supervisor.

Hence, a new [MMI entrypoint](../../MmiEntrySea/MmiEntrySea.inf) is created to allow the MM supervisor to load using MM
relocation phase. It is also crafted so that the jump point into the MM supervisor is located at the end of the MMI entrypoint
code. This allows the SEA to validate the entire flow of the MMI.

Thus, a new [SmmCpuFeaturesLib](../../Library/SmmCpuFeaturesLib/StandaloneMmCpuFeaturesLibStm.inf)
is created to provide the necessary CPU features for the MM Supervisor to load the SEA core.

Specifically, the library, linked to the MM supervisor, will locate the resources needed, load the SEA core into MSEG, load
the MMI entrypoint code blob to MM_BASE for each core, fix up the jump points based on MM supervisor function pointers, and
finally protected the loaded images.

## Executed Supervisor Validation

As part of a DRTM effort, the SEA core is respoinsble for verifying the entire environment of the MM supervisor. As DRTM
event occurs, the system has already booted into the OS, and the MM supervisor is already loaded and executed. Thus the
validation routine from SEA needs to inspect the data, code and the environment of the MM supervisor.

![Validation Illustration](validation_illustration.png)

As illustrated above, in order to accomplish this, the SEA core will perform the following steps:

1. Validate inputted digest list for the MMI entries and Supervisor core
1. Confirm the MM Entry code is inside MMRAM
1. Validate the AUX file (that it's present, inside MMRAM and that we have the valid header signature)
1. Validate the KEY symbols from the AUX file
1. Create the fixup data and copy the MMI entry into it
1. Revert regions in the fixup MMI entry (zero it)
1. Validate MMI Entry through hashing
1. Get current MM CORE information with MM rendezvous
1. Verify the current image is inside MMRAM
1. Verify the GDTR is inside MMRAM
1. Verify CR3 points to the same page table from the symbol list in the AUX file
1. Verify CR3 is inside MMRAM
1. Verify Supervisor stack is inside MMRAM
1. Verify MM Debug Entry and Exit are inside MMRAM
1. Verify IDTR is inside the MM CORE region
1. Verify firmware policy is inside MMRAM
1. Verify the MM Core code through a hash
1. Report the Policy code 

The complicated validation and reversion happens with the function VerifyAndHashImage for the MM CORE in step
"Verify the MM Core code through a hash".

The VerifyAndHashImage has the following flow:

1. Verify the image is in MMRAM
1. Copy the image over to MSEG and grab the image information
1. Create a buffer to copy the image into and then validate the differences found based on the AUX file
    - Everything labelled a Rule is validated based on the type of rule and then the contents of the original binary is
    copied over to maintain coherency for the hash validation
1. Revert the loaded image and put it into a newly created buffer
1. Hash the reverted image and compare it to the original hash of the supervisor binary

The behavior of the reversion code is a bit complicated and relies on reported image sections. This leads to different
behavior between the DEBUG and RELEASE builds. The reversion process is shown below:

1. Validate section alignment
1. Read the PE/COFF header into memory and read the first section which gets us the Number of sections
1. Loop through each section of the image copying over the sections if they have a SizeOfRawData > 0
    - The behavior is different here between the DEBUG and RELEASE builds. Below the difference is highlighted
1. Load the Codeview information if present
1. Make sure the size of the image is correctly aligned

All these steps are done with the guidance of platform validation rules. For more information on the validation rules, please
see the [SEA Validation Rules](#sea-validation-rules) section.

## Platform Data Requirements

The platform needs to produce the data structures in this section. The structures are consumed by MM Supervisor code to allow
the `SmmCpuFeaturesLib` acquire platform-specific details.

### HOBs Required by `SmmCpuFeaturesLib`

1. `gMsegSmramGuid` - MSEG memory region information.
   - [UefiCpuPkg/Include/Guid/MsegSmram.h](https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/Include/Guid/MsegSmram.h)
   - Note that [`MsegSmramPei`](../../Drivers/MsegSmramPei/MsegSmramPei.inf)
   can be used to help produce this HOB.

### SEA Validation Rules

The SEA Validation Rule is a data structure used to guide the SEA core to validate certain data regions of MM supervisor
core. Platform authors need to provide the validation rules during build time, which will be compiled and baked into the
SEA core binary. The rules will be used to validate the state of the MM supervisor and revert the content of the MM supervisor
before SEA attempts to de-relocate the MM supervisor for signature validation.

As defined in this [header file](../../Include/SeaAuxiliary.h), the SEA core will use the following rules to validate the
MM memory regions:

1. `IMAGE_VALIDATION_ENTRY_TYPE_NONE`: Ignore the region corresponding to this entry.
1. `IMAGE_VALIDATION_ENTRY_TYPE_MSEG`: The region is MSEG, SEA core will validate the region to be MSEG.
1. `IMAGE_VALIDATION_ENTRY_TYPE_CONTENT`: The content inside this region matches exactly the content inside the rule.
1. `IMAGE_VALIDATION_ENTRY_TYPE_MEM_ATTR`: The memory attribute of the region matches the rule.
1. `IMAGE_VALIDATION_ENTRY_TYPE_SELF_REF`: The region is self-referenced, SEA core will validate the region to be pointing
to another point inside the MM supervisor.
1. `IMAGE_VALIDATION_ENTRY_TYPE_POINTER`: The entry is a pointer to and the pointer needs to be not null, pointing to non
MSEG, or pointing to outside of TSEG, depending on the rule.

The syntax of the rules is as described in this [documentation](../../Tools/GenSeaArtifacts/gen_aux/readme.md).

## SEA Code Integration

A general description of SEA and MM supervisor code integration is depicted below:

![SEA and MM Supervisor Assert Layout](Images/asset_layout.png)

1. Ensure all submodules for the platform are based on the latest Project Mu version (e.g. "202102")
1. Include this repo as a submodule for your platform repos and set the folder path as `Common/MU_MM_SUPV`
(also add `Common/MU_MM_SUPV` to required repos and module packages in the platform build script):
<https://windowspartners.visualstudio.com/MsCoreUefi_Thanos/_git/msft_mmsupervisor>

> Note: A list of the libraries and modules made available by this package is provided in the
  [Software Component Overview](SoftwareComponentOverview.md).

### Platform DSC statements

The changes below assumes that the platform has already integrated the MM Supervisor.

1. Add the DSC sections below.

``` bash
[LibraryClasses]
  SecurePolicyLib|MmSupervisorPkg/Library/SecurePolicyLib/SecurePolicyLib.inf

[LibraryClasses.X64.MM_CORE_STANDALONE]
  SmmCpuFeaturesLib|SeaPkg/Library/SmmCpuFeaturesLib/StandaloneMmCpuFeaturesLibStm.inf

[LibraryClasses.common.USER_DEFINED]
  StmLib|SeaPkg/Library/StmLib/StmLib.inf
  StmPlatformLib|SeaPkg/Library/StmPlatformLibNull/StmPlatformLibNull.inf
  SynchronizationLib|SeaPkg/Library/SimpleSynchronizationLib/SimpleSynchronizationLib.inf

[Components.IA32]
  SeaPkg/Drivers/MsegSmramPei/MsegSmramPei.inf

[Components.X64]
  SeaPkg/MmiEntrySea/MmiEntrySea.inf
```

Note that the supervisor needs to be built and pass through the gen_aux to output the `MmArtifacts.dsc.inc`,
which is a the binary representation of the validation rules and the hash of the MM supervisor and the MMI entry
code. The `MmArtifacts.dsc.inc` file is generated by the `GenSeaArtifacts.py` tool.

These values are then used to build the SEA core for final integration.

``` bash
[Components.X64]
  SeaPkg/Core/Stm.inf {
    <LibraryClasses>
      NULL|MdePkg/Library/StackCheckLib/StackCheckLibStaticInit.inf
      HashLib|SeaPkg/Library/HashLibTpm2Raw/HashLibTpm2Raw.inf
      BaseCryptLib|CryptoPkg/Library/BaseCryptLibMbedTls/BaseCryptLib.inf
      MbedTlsLib|CryptoPkg/Library/MbedTlsLib/MbedTlsLib.inf
      IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
      PeCoffLibNegative|SeaPkg/Library/BasePeCoffLibNegative/BasePeCoffLibNegative.inf
      MemoryAllocationLib|MdeModulePkg/Library/BaseMemoryAllocationLibNull/BaseMemoryAllocationLibNull.inf
    <PcdsFixedAtBuild>
      !include $(OUTPUT_DIRECTORY)/$(TARGET)_$(TOOL_CHAIN_TAG)/MmArtifacts.dsc.inc
  }
  # Optionally, you can add the following test application to run the validation test
  # for the SEA core from shell.
  SeaPkg/Tests/ResponderValidationTest/ResponderValidationTestApp.inf {
    <PcdsFixedAtBuild>
      !include $(OUTPUT_DIRECTORY)/$(TARGET)_$(TOOL_CHAIN_TAG)/MmArtifacts.dsc.inc
  }
```

### Platform FDF statements

1. Add the FDF sections below.

Note: There might be other silicon specific drivers a platform will need for these sections

``` bash
[FV.YOUR_PEI_FV]
  INF SeaPkg/Drivers/MsegSmramPei/MsegSmramPei.inf

[FV.YOUR_POST_MEM_PEI_FV]
  FILE MM_CORE_STANDALONE=gMmSupervisorCoreGuid {
    SECTION PE32=$(OUTPUT_DIRECTORY)/$(TARGET)_$(TOOL_CHAIN_TAG)/X64/MmSupervisorCore.efi
    SECTION UI= "MmSupervisorCore"
  }
  FILE FREEFORM = gMmiEntrySeaFileGuid {
    SECTION RAW = $(OUTPUT_DIRECTORY)/$(TARGET)_$(TOOL_CHAIN_TAG)/X64/SeaPkg/MmiEntrySea/MmiEntrySea/OUTPUT/MmiEntrySea.bin
  }
  FILE FREEFORM = gSeaBinFileGuid {
    SECTION RAW = $(OUTPUT_DIRECTORY)/$(TARGET)_$(TOOL_CHAIN_TAG)/X64/SeaPkg/Core/Stm/DEBUG/Stm.bin
  }
```
