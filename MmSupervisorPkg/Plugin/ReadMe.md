# MM Supervisor Post Build Scan Plugin

This plugin performs post-build scanning of MM Standalone modules to detect usage of protected/privileged instructions
that would exception when executing in the security model of the MM Supervisor. The plugin analyzes the build binaries
and warns about found violations in the compiled binaries.

`MmSupervisorPostBuildScan.py` -> Scans MM Standalone modules for protected instruction usage during post-build phase.
`MmSupervisorPostBuildScan_plug_in.yaml` -> Configuration file defining plugin scope, name, and module reference.

## Usability

The plugin is scoped to `mmsupvscanning` and will be invoked during the post-build phase when building a project.
It requires a valid `BUILDREPORT_FILE` to determine the MM_STANDALONE modules which need to be scanned. Any
potential violations will be reported as build warnings. Check the build logs for any protected instruction usage reports.

## Protected Instruction Categories

The plugin monitors for several categories of instructions that are restricted in MM Standalone modules to maintain
the security boundaries enforced by the MM Supervisor.

### Interrupt Control

Instructions that manipulate interrupt flags and could affect system interrupt handling:

```text
- cli         # clear interrupt flag – disables maskable interrupts
- sti         # set interrupt flag – enables maskable interrupts  
- hlt         # halt – stops CPU until next external interrupt
```

### Memory Management

Instructions that control memory segmentation and paging structures:

```text
- lgdt        # load global descriptor table – sets up memory segmentation
- sgdt        # store global descriptor table – reads current GDT
- lidt        # load interrupt descriptor table – sets up interrupt handling
- sidt        # store interrupt descriptor table – reads current IDT
- lldt        # load local descriptor table – sets up task-specific segment descriptors
- sldt        # store local descriptor table – reads current LDT
- ltr         # load task register – sets the task register for multitasking
- str         # store task register – reads the current task register
- invlpg      # invalidate TLB entry – flushes a single page from the TLB
- invd        # invalidate caches – invalidates internal CPU caches without writing back
- wbinvd      # write back and invalidate cache – writes back and invalidates caches
```

### System Register Instructions

Instructions that access model-specific registers and system control registers:

```text
- rdmsr       # read model-specific register – reads from MSRs (used for CPU control)
- wrmsr       # write model-specific register – writes to MSRs
```

### System Mode Instructions

Instructions related to system management mode and system calls:

```text
- rsm         # resume from system management mode – resumes from SMM (ring -2)
- sysret      # fast system call return – returns from syscall
- sysenter    # fast system call entry (intel) – requires ring 0 setup
- sysexit     # fast system call return (intel)
```

### Virtualization Instructions

Instructions used for hardware virtualization control:

```text
- vmcall      # call to hypervisor – used in virtualization
- vmlaunch    # launch a virtual machine – enters vmx non-root mode
- vmresume    # resume a virtual machine – resumes from vm exit
- vmxon       # enter vmx operation – enables virtualization
- vmxoff      # exit vmx operation – disables virtualization
- vmread      # read from vmcs – reads VM control structure
- vmwrite     # write to vmcs – writes to VM control structure
- vmptrld     # load pointer to vmcs – sets current VMCS
- vmptrst     # store pointer to vmcs – gets current VMCS pointer
```

## Toolchain Support

The plugin supports multiple toolchains and automatically adapts its disassembly approach:

### VS2022

- Uses `dumpbin.exe` from Visual Studio installation
- Automatically locates dumpbin using VsWhere
- Command: `dumpbin /DISASM <file.dll>`

### CLANG

- Uses `llvm-objdump` from CLANG_BIN or system PATH  
- Command: `llvm-objdump -d -S --x86-asm-syntax=intel --show-all-symbols --debuginfod`

NOTE: llvm-objdump does not have the ability to differentiate between jump tables (data) and
executable code. The current implementation of the utility has shown false positives
when the jump tables are incorrectly interpreted as executable code.

### GCC

- Uses standard `objdump` utility
- Command: `objdump -d -S -M intel --show-all-symbols --debuginfod`

NOTE: objdump does not have the ability to differentiate between jump tables (data) and
executable code. The current implementation of the utility has shown false positives
when the jump tables are incorrectly interpreted as executable code.

## Scan Process

1. **Build Report Analysis**: Parses the build report file to identify MM_STANDALONE modules
2. **Module Discovery**: Locates corresponding .dll files in the build output directories
3. **Disassembly**: Disassembles each module using the appropriate toolchain disassembler
4. **Pattern Matching**: Searches disassembly output for protected instruction patterns
5. **Function Context**: Attempts to identify the function containing each violation
6. **Reporting**: Logs warnings for any violations found, including function context

## Error Reporting

When protected instructions are detected, the plugin reports:

- The file containing the violation
- The specific instruction(s) found
- The function context where possible
- Returns a non-zero error count to indicate build issues

## Adding New Protected Instructions

To add monitoring for additional protected instructions:

1. Add the instruction mnemonic to the `privileged_instructions` list in `MmSupervisorPostBuildScan.py`
2. Ensure the instruction pattern will be matched by the existing regex patterns
3. Update this documentation to reflect the new instruction category if needed

The plugin automatically scans for any instructions in the `privileged_instructions` list, so no additional
code changes are required beyond updating the list.

## Copyright & License

| Copyright (c) Microsoft Corporation
| SPDX-License-Identifier: BSD-2-Clause-Patent
