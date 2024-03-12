# @file
# Script to Build QemuQ35 Mu UEFI firmware
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import glob
import logging
import os
import sys
import hashlib
from pathlib import Path
from typing import Tuple

from edk2toolext import codeql as codeql_helpers
from edk2toolext.environment import shell_environment
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import (RequiredSubmodule,
                                               SetupSettingsManager)
from edk2toolext.invocables.edk2_ci_setup import CiSetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
from edk2toollib.utility_functions import RunCmd

WORKSPACE_ROOT = str(Path(__file__).parent.parent)


# ####################################################################################### #
#                                Common Configuration                                     #
# ####################################################################################### #
class CommonPlatform():
    ''' Common settings for this platform.  Define static data here and use
        for the different parts of stuart
    '''
    PackagesSupported = ("SpamPkg",)
    ArchSupported = ("X64")
    TargetsSupported = ("DEBUG", "RELEASE", "NO-TARGET", "NOOPT")
    Scopes = ('edk2-build', 'cibuild')
    PackagesPath = (
        "MU_BASECORE",
        "Common/MU",
        "Common/MU_TIANO"
    )

    @staticmethod
    def add_common_command_line_options(parserObj) -> None:
        """Adds command line options common to settings managers."""
        codeql_helpers.add_command_line_option(parserObj)

    @staticmethod
    def is_codeql_enabled(args) -> bool:
        """Retrieves whether CodeQL is enabled."""
        return codeql_helpers.is_codeql_enabled_on_command_line(args)

    @staticmethod
    def get_active_scopes(codeql_enabled: bool) -> Tuple[str]:
        """Returns the active scopes for the platform."""
        active_scopes = CommonPlatform.Scopes
        active_scopes += codeql_helpers.get_scopes(codeql_enabled)

        if codeql_enabled:
            codeql_filter_files = [str(n) for n in glob.glob(
                os.path.join(WORKSPACE_ROOT,
                             '**/CodeQlFilters.yml'), recursive=True)]
            shell_environment.GetBuildVars().SetValue(
                "STUART_CODEQL_FILTER_FILES",
                ','.join(codeql_filter_files),
                "Set in CISettings.py")

        return active_scopes

    # ####################################################################################### #
    #                         Configuration for Update & Setup                                #
    # ####################################################################################### #
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, CiSetupSettingsManager, BuildSettingsManager):

    def AddCommandLineOptions(self, parserObj):
        """Add command line options to the argparser"""
        CommonPlatform.add_common_command_line_options(parserObj)

    def RetrieveCommandLineOptions(self, args):
        """Retrieve command line options from the argparser"""
        self.codeql = CommonPlatform.is_codeql_enabled(args)

    def GetPackagesSupported(self):
        ''' return iterable of edk2 packages supported by this build.
        These should be edk2 workspace relative paths '''
        return CommonPlatform.PackagesSupported

    def GetArchitecturesSupported(self):
        ''' return iterable of edk2 architectures supported by this build '''
        return CommonPlatform.ArchSupported

    def GetTargetsSupported(self):
        ''' return iterable of edk2 target tags supported by this build '''
        return CommonPlatform.TargetsSupported

    def GetRequiredSubmodules(self):
        """Return iterable containing RequiredSubmodule objects.

        !!! note
            If no RequiredSubmodules return an empty iterable
        """
        return [
            RequiredSubmodule("MU_BASECORE", True),
            RequiredSubmodule("Common/MU", True),
            RequiredSubmodule("Common/MU_TIANO", True)
        ]

    def SetArchitectures(self, list_of_requested_architectures):
        ''' Confirm the requests architecture list is valid and configure SettingsManager
        to run only the requested architectures.

        Raise Exception if a list_of_requested_architectures is not supported
        '''
        unsupported = set(list_of_requested_architectures) - \
            set(self.GetArchitecturesSupported())
        if(len(unsupported) > 0):
            errorString = (
                "Unsupported Architecture Requested: " + " ".join(unsupported))
            logging.critical( errorString )
            raise Exception( errorString )
        self.ActualArchitectures = list_of_requested_architectures

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return WORKSPACE_ROOT

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        return CommonPlatform.get_active_scopes(self.codeql)

    def FilterPackagesToTest(self, changedFilesList: list, potentialPackagesList: list) -> list:
        ''' Filter other cases that this package should be built
        based on changed files. This should cover things that can't
        be detected as dependencies. '''
        build_these_packages = []
        possible_packages = potentialPackagesList.copy()
        for f in changedFilesList:
            # BaseTools files that might change the build
            if "BaseTools" in f:
                if os.path.splitext(f) not in [".txt", ".md"]:
                    build_these_packages = possible_packages
                    break

            # if the azure pipeline platform template file changed
            if "platform-build-run-steps.yml" in f:
                build_these_packages = possible_packages
                break

        return build_these_packages

    def GetPlatformDscAndConfig(self) -> tuple:
        ''' If a platform desires to provide its DSC then Policy 4 will evaluate if
        any of the changes will be built in the dsc.

        The tuple should be (<workspace relative path to dsc file>, <input dictionary of dsc key value pairs>)
        '''
        return ("SpamPkg/SpamPkgBin.dsc", {})

    def GetName(self):
        return "SpamPkgBin"

    def GetPackagesPath(self):
        ''' Return a list of paths that should be mapped as edk2 PackagesPath '''
        return CommonPlatform.PackagesPath

    def GetDependencies(self):
        """Get any Git Repository Dependencies.

        This list of repositories will be resolved during the setup step.

        !!! tip
            Optional Override in subclass

        !!! tip
            Return an iterable of dictionary objects with the following fields
            ```json
            {
                Path: <required> Workspace relative path
                Url: <required> Url of git repo
                Commit: <optional> Commit to checkout of repo
                Branch: <optional> Branch to checkout (will checkout most recent commit in branch)
                Full: <optional> Boolean to do shallow or Full checkout.  (default is False)
                ReferencePath: <optional> Workspace relative path to git repo to use as "reference"
            }
            ```
        """
        return [
            {
                "Path": "MU_BASECORE",
                "Url": "https://github.com/microsoft/mu_basecore.git",
                "Branch": "release/202311"
            },
            {
                "Path": "Common/MU",
                "Url": "https://github.com/microsoft/mu_plus.git",
                "Branch": "release/202311"
            },
            {
                "Path": "Common/MU_TIANO",
                "Url": "https://github.com/microsoft/mu_tiano_plus.git",
                "Branch": "release/202311"
            }
        ]

    # ####################################################################################### #
    #                         Actual Configuration for Platform Build                         #
    # ####################################################################################### #
class PlatformBuilder(UefiBuilder, SettingsManager):
    def __init__(self):
        UefiBuilder.__init__(self)

    def GetLoggingLevel(self, loggerType):
        """Get the logging level depending on logger type.

        Args:
            loggerType (str): type of logger being logged to

        Returns:
            (Logging.Level): The logging level

        !!! note "loggerType possible values"
            "base": lowest logging level supported

            "con": logs to screen

            "txt": logs to plain text file
        """
        return logging.INFO

    def SetPlatformEnv(self):
        logging.debug("PlatformBuilder SetPlatformEnv")
        self.env.SetValue("PRODUCT_NAME", "Spam", "Platform Hardcoded")
        self.env.SetValue("ACTIVE_PLATFORM", "SpamPkg/SpamPkgBin.dsc", "Platform Hardcoded")
        self.env.SetValue("TARGET_ARCH", "X64", "Platform Hardcoded")
        # needed to make FV size build report happy
        self.env.SetValue("BLD_*_BUILDID_STRING", "MU", "Default")
        # Default turn on build reporting.
        self.env.SetValue("BUILDREPORTING", "TRUE", "Enabling build report")
        self.env.SetValue("BUILDREPORT_TYPES", "PCD DEPEX FLASH BUILD_FLAGS LIBRARY FIXED_ADDRESS HASH", "Setting build report types")
        # Globally set CodeQL failures to be ignored in this repo.
        # Note: This has no impact if CodeQL is not active/enabled.
        self.env.SetValue("STUART_CODEQL_AUDIT_ONLY", "true", "Platform Defined")
        return 0

    def PlatformPostBuild(self):
        # Add a post build step to build spam core bin and assemble the FD files
        build_output = Path(self.env.GetValue("BUILD_OUTPUT_BASE"))
        mmsupv_dir = build_output / "X64" / "MmSupervisorPkg" / "Core" / "MmSupervisorCore" / "DEBUG"
        stm_dir = build_output / "X64" / "SpamPkg" / "Core" / "Stm" / "DEBUG"

        try:
            # Calculate the hash of the MmSupervisorCore auxilary file
            aux_file = mmsupv_dir / "MmSupervisorCore.aux"
            aux_hash = calculate_aux_hash(aux_file)

            # Find the offset of PcdAuxBinHash in the stm dll
            stm_dir = build_output / "X64" / "SpamPkg" / "Core" / "Stm" / "DEBUG"
            stm_map = stm_dir / "Stm.map"
            stm_dll = stm_dir / "Stm.dll"
            pcd = "PcdAuxBinHash"
            pcd_addr = get_patch_pcd_address(stm_map, stm_dll, pcd)

            if pcd_addr is None:
                logging.error(f"Pcd {pcd} not found in {stm_map}.")
                return -1

            # Patch the hash value into the stm dll
            patch_pcd_value(stm_dll, pcd_addr, aux_hash)
        except FileNotFoundError as e:
            logging.error(f"File {e} not found.")
            return -1
        except RuntimeError as e:
            logging.error(e)
            return -1

        # Generate the stm binary
        base_tools_dir = Path(os.environ['BASE_TOOLS_PATH'])
        gen_stm = base_tools_dir / "Bin" / "Win32" / "GenStm.exe"
        stm_dll = stm_dir / "Stm.dll"
        stm_bin = stm_dir / "Stm.bin"
        cmd = str(gen_stm)
        args = f"-e --debug 5 {stm_dll} -o {stm_bin}"
        return RunCmd(cmd, args)


def calculate_aux_hash(file: Path) -> str:
    """Calculates the hash of the given file.
    
    Returns:
        str: The hex form of the hash as a string

    Raises:    
        FileNotFoundError: The file does not exist
    """
    if not file.exists():
        raise FileNotFoundError(file)

    hasher = hashlib.new("sha256")
    with open(file, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()


def get_patch_pcd_address(map: Path, dll: Path, pcd_name: str) -> int:
    """Gets the address of the given PCD in the patch PCD table.

    Args:
        file (Path): the path to the patch PCD table
        pcd_name (str): the name of the PCD to find

    Returns:
        int: the address of the PCD in the patch PCD table
        None: The pcd does not exist in the table
    
    Raises:
        FileNotFoundError: if map or dll do not exist
        RuntimeError: if GenPatchPcdTable fails
    """
    if not map.exists():
        raise FileNotFoundError(map)
    if not dll.exists():
        raise FileNotFoundError(dll)

    cmd = "GenPatchPcdTable"
    args = f"-m {map} -e {dll}"
    RunCmd(cmd, args)

    pcd_table = map.with_suffix(".BinaryPcdTable.txt")
    if not pcd_table.exists():
        RuntimeError("GenPatchPcdTable Failed")

    offset = None
    with open(pcd_table, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith(pcd_name):
                offset = int(line.split()[1], 16)
                break
    return offset


def patch_pcd_value(file: Path, offset: int, value: Tuple[str, int]) -> int:
    """Patches the value at the given offset in the file.

    Args:
        file (Path): the file to patch
        offset (int): the offset to patch
        value (str|int): the value to patch (hex string or int)

    Raises:
        FileNotFoundError: if the file does not exist
    """
    if not file.exists():
        raise FileNotFoundError(file)

    if isinstance(value, int):
        hex_bytes = value.to_bytes(4, byteorder='little')
    else:
        hex_bytes = bytes.fromhex(value)
    bytes.fromhex(value)
    
    with open(file, 'r+b') as f:
        f.seek(offset)
        f.write(hex_bytes)
    

if __name__ == "__main__":
    import argparse
    import sys

    from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
    from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
    from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
    from edk2toolext.invocables.edk2_update import Edk2Update
    print(r"Invoking Stuart")
    print(r"     ) _     _")
    print(r"    ( (^)-~-(^)")
    print(r"__,-.\_( 0 0 )__,-.___")
    print(r"  'W'   \   /   'W'")
    print(r"         >o<")
    SCRIPT_PATH = os.path.relpath(__file__)
    parser = argparse.ArgumentParser(add_help=False)
    parse_group = parser.add_mutually_exclusive_group()
    parse_group.add_argument("--update", "--UPDATE",
                             action='store_true', help="Invokes stuart_update")
    parse_group.add_argument("--setup", "--SETUP",
                             action='store_true', help="Invokes stuart_setup")
    parse_group.add_argument("--ci-setup", "--CI-SETUP",
                             action='store_true', help="Invokes stuart_ci_setup")
    args, remaining = parser.parse_known_args()
    new_args = ["stuart", "-c", SCRIPT_PATH]
    new_args = new_args + remaining
    sys.argv = new_args
    if args.setup:
        print("Running stuart_setup -c " + SCRIPT_PATH)
        Edk2PlatformSetup().Invoke()
    elif args.ci_setup:
        print("Running stuart_ci_setup -c " + SCRIPT_PATH)
        Edk2CiBuildSetup().Invoke()
    elif args.update:
        print("Running stuart_update -c " + SCRIPT_PATH)
        Edk2Update().Invoke()
    else:
        print("Running stuart_build -c " + SCRIPT_PATH)
        Edk2PlatformBuild().Invoke()
