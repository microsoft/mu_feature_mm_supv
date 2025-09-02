"""Post-build plugin to scan MM Standalone modules for use of protected instructions."""

import glob
import logging
from io import StringIO
from pathlib import Path

from edk2toolext.environment.plugintypes.uefi_build_plugin import (
    IUefiBuildPlugin
)
from edk2toollib.uefi.edk2.parsers.buildreport_parser import BuildReport
from edk2toollib.utility_functions import RunCmd
from edk2toollib.windows.locate_tools import GetVsWherePath
import re

privileged_instructions = [
    "clts",       # Clear the task-switched (TS) flag in CR0
    "lmsw",       # Load machine status word (lower bits of CR0)
    "smsw",       # Store machine status word (lower bits of CR0)
    "lgdt",       # Load global descriptor table register
    "sgdt",       # Store global descriptor table register
    "lidt",       # Load interrupt descriptor table register
    "sidt",       # Store interrupt descriptor table register
    "lldt",       # Load local descriptor table register
    "sldt",       # Store local descriptor table register
    "ltr",        # Load task register
    "str",        # Store task register
    "arpl",       # Adjust requested privilege level of a selector
    "verr",       # Verify segment for read access
    "verw",       # Verify segment for write access
    "sti",        # Set interrupt flag (enable interrupts)
    "cli",        # Clear interrupt flag (disable interrupts)
    "iret",       # Return from interrupt
    "in",         # Read from I/O port
    "out",        # Write to I/O port
    "invd",       # Invalidate internal caches
    "wbinvd",     # Write back and invalidate caches
    "hlt",        # Halt the processor until the next interrupt
    "rsm",        # Resume from system management mode
    "sysenter",   # Fast system call entry (used in 32-bit systems)
    "sysexit",    # Fast system call exit (used in 32-bit systems)
    "sysret",     # Fast system call return (used in 64-bit systems)
    "rdpmc",      # Read performance-monitoring counters
    "rdmsr",      # Read model-specific register
    "wrmsr",      # Write model-specific register
    "rdtsc",      # Read time-stamp counter
    "vmread",     # Read from a virtual machine control structure
    "vmwrite",    # Write to a virtual machine control structure
    "vmcall",     # Call to hypervisor (used in virtualization)
    "vmlaunch",   # Launch a virtual machine
    "vmresume",   # Resume a virtual machine
    "vmptrld",    # Load pointer to VMCS
    "vmptrst",    # Store pointer to VMCS
    "invept",     # Invalidate extended page tables
    "invvpid",    # Invalidate virtual processor ID mappings
    "invpcid"     # Invalidate process-context identifier mappings
]


class MmSupervisorPostBuildScan(IUefiBuildPlugin):
    """Plugin to scan MM Standalone modules for MSR instructions.

    This plugin analyzes the build output to find and report usage of MSR
    instructions (rdmsr/wrmsr) in MM Standalone modules.
    """

    def do_post_build(self, thebuilder) -> int:
        """Perform post-build scanning for MSR instructions.

        Args:
            thebuilder: The builder object containing environment and paths.

        Returns:
            int: Return code (0 for success).
        """
        env = (thebuilder.env.GetAllBuildKeyValues() |
               thebuilder.env.GetAllNonBuildKeyValues())

        self.build_report = Path(env.get("BUILDREPORT_FILE", ""))
        if not self.build_report.exists():
            logging.info(
                "Build report not present, skipping Mm Standalone Scanning"
            )
            return

        self.parse_build_report_file(thebuilder)
        self.find_standalonemm_modules(thebuilder)

        if self.module_list:
            self.dumpbin_path = self.find_dumpbin()
#            self.objdump_path = self.file_objdump()

            for efi_file in self.module_list:
                workspace_path = thebuilder.edk2path.WorkspacePath
                file_pattern = Path(workspace_path, "**", efi_file + ".efi")
                path_to_efi_file = glob.glob(
                    file_pattern.as_posix(), recursive=True
                )
                if path_to_efi_file:
                    disassembly = self.disassemble_efi_file(path_to_efi_file[0])
                    Instructions = self.find_protected_instructions(disassembly)
                    if Instructions:
                        logging.warning(f"Protected Instructions found in {path_to_efi_file[0]}")
                        logging.warning(f"\t{Instructions}")

        return 0

    def parse_build_report_file(self, thebuilder):

        self.report = BuildReport(
            self.build_report,
            thebuilder.edk2path.WorkspacePath,
            ",".join(thebuilder.edk2path.PackagePathList),
            {}
        )
        self.report.BasicParse()
        return

    def find_standalonemm_modules(self, thebuilder):
        self.module_list = []
        for module in self.report.Modules.values():
            if module.FvName and module.Type == "MM_STANDALONE":
                self.module_list.append(module.Name)
        return

    def find_dumpbin(self) -> str:
        """Find the path to the dumpbin.exe tool.

        Returns:
            str: Path to dumpbin.exe.

        Raises:
            EnvironmentError: If VsWhere executable cannot be located.
            RuntimeError: If VsWhere execution fails.
        """
        vs_where_path = GetVsWherePath()
        if vs_where_path is None:
            raise EnvironmentError("Unable to locate the VsWhere Executable.")

        cmd = (
            "-latest -products * -requires "
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64 "
            "-find **\\dumpbin.exe"
        )
        a = StringIO()
        ret = RunCmd(vs_where_path, cmd, outstream=a)
        if ret != 0:
            a.close()
            raise RuntimeError(
                f"Unknown Error while executing VsWhere: errcode {ret}."
            )

        possible_bins = a.getvalue().replace("\r\n", ";").split(";")
        a.close()
        return possible_bins[0]

    def disassemble_efi_file(self, file_path: str) -> str:
        """Disassemble a file.

        Args:
            file_path: Path to the file to disassemble.

        Returns:
            List of disassembly lines.
        """
        result_io = StringIO()
        ret = RunCmd(
            self.dumpbin_path,
            f'/DISASM "{file_path}"',
            outstream=result_io,
            capture=True,
            logging_level=logging.DEBUG
        )
#        ret = RunCmd(
#            self.objdump_path,
#            f'-d -M intel -j .text {file_path}',
#            outstream=result_io
#        )
        if ret != 0:
            logging.error(f"Failed to disassemble {file_path}: exit code {ret}")
            return []
        return result_io.getvalue()

    def find_protected_instructions(self, diss: str):
        found = set()
        for instr in privileged_instructions:
            pattern = r'\b' + re.escape(instr) + r'\b'
            for m in re.finditer(pattern, diss, re.IGNORECASE):
                found.add(instr)
        return found
