"""Post-build plugin to scan MM Standalone modules for use of protected
instrs."""

import glob
import logging
import re
from io import StringIO
from pathlib import Path
from typing import Any, List, Set

from edk2toolext.environment.plugintypes.uefi_build_plugin import (
    IUefiBuildPlugin
)
from edk2toollib.uefi.edk2.parsers.buildreport_parser import BuildReport
from edk2toollib.utility_functions import RunCmd
from edk2toollib.windows.locate_tools import GetVsWherePath
from edk2toolext.environment import shell_environment


privileged_instructions: List[str] = [
    "cli",        # clear interrupt flag – disables maskable interrupts
    "sti",        # set interrupt flag – enables maskable interrupts
    "hlt",        # halt – stops CPU until next external interrupt
    "lgdt",       # load global descriptor table – sets up memory segmentation
    "sgdt",       # store global descriptor table – reads current GDT
                  # (privileged in 64-bit mode)
    "lidt",       # load interrupt descriptor table – sets up interrupt
                  # handling
    "sidt",       # store interrupt descriptor table – reads current IDT
                  # (privileged in 64-bit mode)
    "lldt",       # load local descriptor table – sets up task-specific
                  # segment descriptors
    "sldt",       # store local descriptor table – reads current LDT
                  # (privileged in 64-bit mode)
    "ltr",        # load task register – sets the task register for
                  # multitasking
    "str",        # store task register – reads the current task register
    "invlpg",     # invalidate TLB entry – flushes a single page from the TLB
    "invd",       # invalidate caches – invalidates internal CPU caches
                  # without writing back
    "wbinvd",     # write back and invalidate cache – writes back and
                  # invalidates caches
    "rdmsr",      # read model-specific register – reads from MSRs
                  # (used for CPU control)
    "wrmsr",      # write model-specific register – writes to MSRs
    "rsm",        # resume from system management mode – resumes from SMM
                  # (ring -2)
    "sysret",     # fast system call return – returns from syscall
    "sysenter",   # fast system call entry (intel) – requires ring 0 setup
    "sysexit",    # fast system call return (intel)
    "vmcall",     # call to hypervisor – used in virtualization
    "vmlaunch",   # launch a virtual machine – enters vmx non-root mode
    "vmresume",   # resume a virtual machine – resumes from vm exit
    "vmxon",      # enter vmx operation – enables virtualization
    "vmxoff",     # exit vmx operation – disables virtualization
    "vmread",     # read from vmcs – reads VM control structure
    "vmwrite",    # write to vmcs – writes to VM control structure
    "vmptrld",    # load pointer to vmcs – sets current VMCS
    "vmptrst"     # store pointer to vmcs – gets current VMCS pointer
]


class MmSupervisorPostBuildScan(IUefiBuildPlugin):
    """Plugin to scan MM Standalone modules for MSR instructions.

    This plugin analyzes the build output to find and report usage of MSR
    instructions (rdmsr/wrmsr) in MM Standalone modules.
    """

    def do_post_build(self, thebuilder: Any) -> int:
        """Perform post-build scanning for protected instructions.

        Analyzes the build output to find and report usage of protected
        instructions in MM Standalone modules.

        Args:
            thebuilder: The builder object containing environment and paths.

        Returns:
            int: Return code (0 for success).
        """
        error_count = 0
        env = (thebuilder.env.GetAllBuildKeyValues() |
               thebuilder.env.GetAllNonBuildKeyValues())

        self.build_report = Path(env.get("BUILDREPORT_FILE", ""))
        if not self.build_report.exists():
            logging.info(
                "Build report not present, skipping Mm Standalone Scanning"
            )
            return 0

        # yes, this really is only handing x86/x64 because that is all mm
        # supv supports.
        self.ToolChain = env.get("TOOL_CHAIN_TAG", "")
        if self.ToolChain == "VS2022":
            self.disassemble_executable = self.find_dumpbin()
            self.disassemble_options = "/DISASM "
            # Match function labels that appear on their own line ending
            # with colon
            self.function_regex = r'^([A-Za-z_][A-Za-z_0-9@?$]*)\s*:\s*$'
        elif "CLANG" in self.ToolChain:
            # ClangPdb could technically use dumpbin from Vs2022, but it would
            # introduce a dependency on an unspecified tool chain.
            clang_bin = shell_environment.GetEnvironment().get_shell_var(
                "CLANG_BIN"
            )
            if clang_bin:
                self.disassemble_executable = clang_bin + "llvm-objdump"
            else:
                # Fall back to system PATH if CLANG_BIN is not defined
                self.disassemble_executable = "llvm-objdump"
            self.disassemble_options = (
                "-d -S --x86-asm-syntax=intel --show-all-symbols --debuginfod"
            )
            # Match function symbols, excluding static string labels that
            # start with .L
            self.function_regex = (
                r'^\w+\s*<([A-Za-z_][A-Za-z_0-9]*(?:@[A-Za-z_0-9]+)?)>:$'
            )
        elif "GCC" in self.ToolChain:
            self.disassemble_executable = "objdump"
            self.disassemble_options = "-d -S -M intel --show-all-symbols --debuginfod "
            self.function_regex = r'^([A-Za-z_][A-Za-z_0-9@?$]*)\s*:\s*$'
        else:
            logging.info("Unknown tool chain, skipping MmStandaloneScanning")
            return 0

        self.parse_build_report_file(thebuilder)
        self.find_standalonemm_modules(thebuilder)

        if self.module_list:
            for efi_file in self.module_list:
                workspace_path = thebuilder.edk2path.WorkspacePath
                file_pattern = Path(
                    workspace_path,
                    "**/*_" + self.ToolChain + "/**/DEBUG/",
                    efi_file + ".dll"
                )
                path_to_efi_file = glob.glob(
                    file_pattern.as_posix(), recursive=True
                )
                if path_to_efi_file:
                    disassembly = self.disassemble_efi_file(
                        path_to_efi_file[0]
                    )
                    instructions = self.find_protected_instructions(
                        disassembly
                    )
                    if instructions:
                        error_count = error_count + 1
                        logging.warning(
                            f"Protected Instructions found in "
                            f"{path_to_efi_file[0]}"
                        )
                        logging.warning(f"\t{instructions}\n")

        return error_count

    def parse_build_report_file(self, thebuilder: Any) -> None:
        """Parse the build report file to extract module information.

        Args:
            thebuilder: The builder object containing environment and paths.

        Returns:
            None
        """
        self.report = BuildReport(
            self.build_report,
            thebuilder.edk2path.WorkspacePath,
            ",".join(thebuilder.edk2path.PackagePathList),
            {}
        )
        self.report.BasicParse()
        return

    def find_standalonemm_modules(self, thebuilder: Any) -> None:
        """Find all MM Standalone modules in the build report.

        Args:
            thebuilder: The builder object containing environment and paths.

        Returns:
            None
        """
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
        """Disassemble an EFI file using dumpbin.

        Args:
            file_path: Path to the EFI file to disassemble.

        Returns:
            str: The disassembly output as a string.
        """
        result_io = StringIO()
        ret = RunCmd(
            self.disassemble_executable,
            self.disassemble_options + f" {file_path}",
            outstream=result_io,
            capture=True,
            logging_level=logging.DEBUG
        )
        if ret != 0:
            logging.error(
                f"Failed to disassemble {file_path}: exit code {ret}"
            )
            return ""
        return result_io.getvalue()

    def find_protected_instructions(self, diss: str) -> Set[str]:
        """Find protected instructions in disassembly output.

        Args:
            diss: The disassembly output as a string.

        Returns:
            Set[str]: Set of protected instruction names found.
        """
        found = set()
        for instr in privileged_instructions:
            # Why is this \s instead of \b? Because objdump will leave
            # a lot of <.L.str.1.153> in the disassmebly
            pattern = r'\s+' + re.escape(instr) + r'\b'
            for m in re.finditer(pattern, diss, re.IGNORECASE):
                # A Ring0 instruction was found, attempt to find the function
                # where it was referenced
                function_header_pattern = re.compile(
                    self.function_regex, re.MULTILINE | re.IGNORECASE
                )

                matches = list(function_header_pattern.finditer(
                    diss[:m.start()]
                ))
                if matches:
                    found.add(matches[-1].group(1) + " " + instr)
                else:
                    found.add("<unknown function> " + instr)
        return found
