"""Post-build plugin to scan MM Standalone modules for MSR instructions."""

import glob
import logging
import re
import subprocess
from io import StringIO
from pathlib import Path
from typing import List, Tuple

from edk2toolext.environment.plugintypes.uefi_build_plugin import (
    IUefiBuildPlugin
)
from edk2toollib.uefi.edk2.parsers.buildreport_parser import BuildReport
from edk2toollib.utility_functions import RunCmd
from edk2toollib.windows.locate_tools import GetVsWherePath


class PostBuildScanMmStandalone(IUefiBuildPlugin):
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
        build_report = Path(env.get("BUILDREPORT_FILE", ""))
        if not build_report.exists():
            logging.warning(
                "Build report not present, skipping build report table "
                "parsing."
            )
            return
        self.dumpbin_path = self.find_dumpbin()

        report = BuildReport(
            build_report,
            thebuilder.edk2path.WorkspacePath,
            ",".join(thebuilder.edk2path.PackagePathList),
            {}
        )
        report.BasicParse()

        module_list = []
        for module in report.Modules.values():
            if module.FvName and module.Type == "MM_STANDALONE":
                module_list.append(module.Name)
        for efi_file in module_list:
            workspace_path = thebuilder.edk2path.WorkspacePath
            file_pattern = Path(workspace_path, "**", efi_file + ".efi")
            path_to_efi_file = glob.glob(
                file_pattern.as_posix(), recursive=True
            )
            if path_to_efi_file:
                disassembly = self.disassemble_with_dumpbin(
                    path_to_efi_file[0]
                )
                msr_hits = self.find_msr_instructions_with_context(
                    disassembly
                )
                if msr_hits:
                    logging.info(f"\nScanning: {efi_file}")
                    for (formatted_line,) in msr_hits:
                        logging.info(formatted_line)
        return 0

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

    def disassemble_with_dumpbin(self, file_path: str) -> List[str]:
        """Disassemble a file using dumpbin.exe.

        Args:
            file_path: Path to the file to disassemble.

        Returns:
            List of disassembly lines.
        """
        try:
            result = subprocess.run(
                [self.dumpbin_path, '/DISASM', file_path],
                capture_output=True, text=True, check=True
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to disassemble {file_path}: {e}")
            return []

    def modifies_ecx_or_rcx(self, line: str) -> bool:
        """Check if a line modifies ECX or RCX register.

        Args:
            line: Assembly code line to check.

        Returns:
            True if the line modifies ECX or RCX register.
        """
        return bool(re.search(r'\bmov\s+(ecx|rcx)\b', line, re.IGNORECASE))

    def find_msr_instructions_with_context(
        self, disassembly_lines: List[str]
    ) -> List[Tuple[str]]:
        """Find MSR instructions in disassembly with context.

        Args:
            disassembly_lines: List of disassembly lines to analyze.

        Returns:
            List of tuples containing formatted MSR instruction information.
        """
        msr_hits = []

        for i, line in enumerate(disassembly_lines):
            if self.modifies_ecx_or_rcx(line):
                match = re.match(
                    r"^(\w+):.*?\bmov\s+\w+,\s*([^\s]+)",
                    line.strip(),
                    re.IGNORECASE
                )
                if match:
                    ecx_addr, msr_value = match.groups()

            if 'rdmsr' in line.lower():
                msr_hits.append((f"Read MSR  {msr_value} at {ecx_addr}",))
            elif 'wrmsr' in line.lower():
                msr_hits.append((f"Write MSR {msr_value} at {ecx_addr}",))

        return msr_hits
