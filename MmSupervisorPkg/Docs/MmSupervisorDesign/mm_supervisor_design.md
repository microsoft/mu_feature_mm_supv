# Proposed Flow of MM Supervisor

The proposed flow currently supports 2 platforms for development:

* OVMF Virtual Platform: Intel Q35 based virtual platform from Tianocore. It can be run on QEMU simulator
* AMD Renoir Reference Platform: AMD Renoir based CRB platform, requiring NDA with AMD

*Note*: Please see Resources section for more links and tutorials

## Objective

![Boot flow comparison between SMM and Standalone MM kernel](boot_flow_comparison.png)

* MM foundation initialized early in the boot process and has isolated protocol and configuration table database
* MM supervisor mechanism holds separate service database
* MM drivers and handlers execute under user mode (CPL3)
* Binary release model

## Standalone MM Hob (PEIM) Creates Necessary Hobs Serving as Placeholder

1. EfiSystemTable
1. MM Core private data
1. ACPI communication buffer address
1. TCG NVS address from Tpm ACPI table
1. Memory Map for DXE environment

## In DXE, at MM IPL entry point

1. Populates Hobs 1 and 2 Prior to Loading MM Supervisor
    * Memory Map as of now is still populated only in ready to lock
    * Hobs 3 and 4 are populated in their separate drivers during their loading
    * TODO: the ideal process would be all these hob population can be moved to null library and IPL can stay out of it
1. Finds the largest available MMRAM region and copy MM Supervisor to this region and load it
1. After MM Supervisor loading, close SMRAM to prevent SMRAM access
1. Before publishing Supervisor communication, IPL should test communication to Supervisor to query Supervisor version
and verify the returned version and patch level is non-zero AND meets other system requirements. Known limitations for GCC
toolchain:
    * **Patch level information, which should be embedded into image version of built Pe/Coff header cannot be integrated
    when using GCC toolchain. User builds with GCC tools are welcome to reach out to MsCoreUefi@microsoft.com for
    technical discussion in that regards.**
    * **Driver version embedded into subsystem version of Pe/Coff header is being parsed by objcopy when using GCC
    toolchain. This tool would parse input numeric strings with implicit base (i.e. strings beginning with 0s will be
    parsed as octal numbers). However, MSFT linker specifically only parse it as decimal numbers.**
1. Publish protocol to be used by DXE drivers for brokage pipeline
1. Send brokage command to MM Supervisor to load the rest of MM drivers (this is done so that all drivers can be
transitioned to CPL3 under MM environment instead of DXE environment)

## Core Responsibility By MM Supervisor

1. Provide memory service
1. Provide protocol publication and notification
1. Provide MMI handler register and unregister
1. Provide gMmst table for usage
1. Relocate MMI entry for x64 architecture
1. Setup GDT, IDT, exception handlers for MMI environment
1. Setup stack for each CPU in MMI environment
1. Setup DXE to MM Supervisor brokage pipeline
    * This will be a MM Supervisor registered handler that run under CPL0 for DXE to demand special commands from MM
    Supervisor (i.e. dispatch MM drivers, query version or configuration information, fetch isolation policy)
    * This will be provided as DXE_DRIVER type library API for consumption
1. Mark supervisor pages corresponds to data consumed by MM Supervisor as well as Supervisor code and lock MM control
registers if applicable
1. Return to DXE

## MM foundation isolation

1. Page table:
    * Once MM foundation sets up MMI environment, the foundation data and code needs to be marked as supervisor pages.
    * More data allocated internally will also be marked as supervisor pages.
    * Memory services from subsequent drivers will be marked as user pages.
    * At ready to lock event, ring 0 GDT and IDT and page table itself will be patched to read only
1. Privilege level:
    * MM foundation will execute at CPL0 to access all data and code if allowed by page table
    * Before loading MM drivers, core will update stack pointer in TSS and return address from call gate. Return far with
    target SS:RSP and CS:RIP
    * After MM driver returns, call far will return to the original return address from call gate set up
    * For MMI. Before dispatching each MMI handlers, if prior to ready to lock, core will update stack pointer in TSS and
    return address from call gate. Return far with target SS:RSP and CS:RIP. *Note: this will need to be in APHandler for
    APs and around MMI handler dispatching for BSP*
    * After MMI returns, call far will return to the original return address from call gate set up

![Syscall flow illustration](isolated_smi_handler.png)

1. Syscall (see the flow chart) to enforce all services needs to execute under CPL0 from CPL3 must go through syscall interface:
    * Core services provided through gMmst provided under CPL3 will be a syscall shim, it implements most gMmst service
    by invoking syscall and have core service replay the request.
    * Certain privileged instructions such as IO read/write, MSR read/write, and INT, WBI, HLT will be evaluated through
    policy gate before proceeding. An example defined by AMD for v1 SMM isolation can be found in ```SmmSupervisorPkg```
    [here](https://windowspartners.visualstudio.com/Partner_Amd_UEFI/_git/mu_mm_supv?path=%2FSmmSupervisorPkg%2FInclude%2FSmmSecurePolicy.h)
    * Telemetry records: when prohibited syscall occurs, core service will jump to preset variable service in Ring 3,
    write NV variable and long jump back to the point where Ring 3 is enforced.

## Individual MMI Input Flow

1. At the MMI entry point, each core will setup their MSR of STARs to point to core syscall center in MM core. And
restore MSR back before rsm from MMI.
1. Each core will still go through SmiRendezvous flow. BSP will go all the way to MMI handler dispatcher and transition
to Ring 3, then run the handler code in Ring 3. And then come back to Ring 0 upon returning.
1. AP will wait at idle state, till notified that there are schedules in the queue. Before loading the function pointers,
AP will transition to Ring 3 and then execute procedures in Ring 3. And then come back to Ring 0 upon returning.
1. Prior to dispatching individual MMI handlers, MM supervisor will copy incoming communicate buffers into MMRAM region,
marked with proper memory attributes (user vs. kernel). The copied buffers will be dispatched to MMI handlers.
1. Note that when ring level changes, the stack switch will occur as well. Thus when setting up stack, the Ring 3 stack
needs to be allocated separately.

## MM Core <-> Driver Interface

1. Between MM drivers and MM Supervisor, a shim driver will be loaded first to publish a shim gMmst, which will implement
some of the real gMmst function through syscall request.
    * This driver will also manage protocol data base in Ring 3, meaning the entire protocol publication, notification,
    location will be under Ring 3 and application level. And there will be no protocol published from MM core.
    * The driver will also need to refresh the content of table when there is potential to change the values in the table
    (number of configuration table entries, etc)
1. Also between MM drivers and MM Supervisor, syscall version of BaseLib, CpuLib and IoLib for MM EFI drivers. This will
provide a direct interface to request privileged information from MM core.
1. Between DXE drivers and MM Supervisor, a brokage pipeline (special MM handler) will be set up for information querying
and driver dispatching

## Launch MM in PEI

1. At the entrypoint of MM PEI IPL, the PEIM will go over system prerequisites to make sure MM foundation is ready to settle.
These requirements include designated MM communication buffers for both user and supervisor, MM control PPI to trigger MMI,
MM access PPI to coalesce all available MMRAM regions and lock/close them once MM foundation is set.
1. MM PEI IPL will iterate through all available MMRAMs and load the located MM core (supervisor in this case) into MMRAM.
1. If the system operates PEI in 32-bit mode where as MM foundation needs to run in X64, MM PEI IPL will load a MM IPL X64
relay module, which runs similar to the CapsuleX64.inf from MdeModulePkg. MM PEI IPL will cache system context then switch
the operation mode to X64 to execute X64 relay module.
    * Although X64 relay module is a PEIM module in UEFI environment, but it does not have PEI services like other PEIMs
    * MM core is loaded and relocated in normal PEI environment. X64 relay routine will only execute the core entrypoint
    with supplied hob start pointer.
1. After MM core foundation is setup, the system will, fist return to 32-bit mode with cached context information if applicable,
close and lock all available MMRAM regions.
1. MM PEI IPL initiate test communication to Supervisor by querying Supervisor version before proceeding.
1. MM PEI IPL then install MM communicate and MM supervisor communicate PPIs for usage in the rest of PEI phase.
1. Once DXE environment is launched, a MM DXE IPL that depends on MM control protocol will test communication to MM supervisor
by querying supervisor version.
    * Entities that publish MM control protocol might need to avoid double-initialization
1. Once test communication is successful, MM DXE IPL will publish MM communicate and MM supervisor communicate protocols
for further usage in UEFI DXE or runtime.

## Resources

* Project MU Repositories: <https://github.com/topics/projectmu>
* Standalone MM Specification: Vol. 4:
Management Mode Core Interface, [UEFI Platform Initialization (PI) Specification 1.7 A](https://uefi.org/sites/default/files/resources/PI_Spec_1_7_A_final_May1.pdf)
* MU Q35 Platform: <https://github.com/microsoft/mu_tiano_platforms>
* QEMU Instructions: <https://github.com/tianocore/edk2/blob/master/OvmfPkg/PlatformCI/ReadMe.md>
