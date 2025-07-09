# @file
# UEFI Helper plugin for generating SEA artifacts based off of the MM Supervisor build.
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import hashlib
import logging
import json
from pathlib import Path
import shutil

from edk2toolext.environment.plugintypes.uefi_helper_plugin import IUefiHelperPlugin
from edk2toollib.utility_functions import RunCmd, RunPythonScript


HASH_ALGORITHM = "sha256"
AUX_CONFIG_NAME = "AuxConfig.toml"


class GenSeaArtifacts(IUefiHelperPlugin):
    def RegisterHelpers(self, obj):
        fp = os.path.abspath(__file__)
        obj.Register("generate_sea_includes", GenSeaArtifacts.generate_sea_includes, fp)
        obj.Register("generate_stm_binary", GenSeaArtifacts.generate_stm_binary, fp)
        obj.Register("generate_test_aux_binary", GenSeaArtifacts.generate_test_aux_binary, fp)
        obj.Register("generate_sea_manifest", GenSeaArtifacts.generate_sea_manifest, fp)
        obj.Register("validate_rule_coverage", GenSeaArtifacts.validate_rule_coverage, fp)

    @staticmethod
    def generate_sea_includes(
        scopes: list[str],
        aux_config_path: Path,
        mm_supervisor_build_dir: Path,
        mmi_file_path: Path,
        out_path: Path,
        workspace=None
    ):
        """Generates SEA artifacts.

        Generates the following artifacts:
        - MmSupervisorCore.aux: A validation rule file for the MM Supervisor Core EFI binary.
        - inc_file_path: a dsc.inc file containing PCDs
            - gEfiSeaPkgTokenSpaceGuid.PcdAuxBinFile: N sized PCD containing the auxiliary file for the MM Supervisor Core.
            - gEfiSeaPkgTokenSpaceGuid.PcdMmiEntryBinHash: Hash of the MmiEntrySea binary.
            - gEfiSeaPkgTokenSpaceGuid.PcdMmiEntryBinSize: Size of the MmiEntrySea binary.
            - gEfiSeaPkgTokenSpaceGuid.PcdMmSupervisorCoreHash: Hash of the MmSupervisorCore binary.

        Args:
            scopes: A list of scopes to activate for rule filtering. See gen_aux --help for more information.
            aux_config_path: Path to the aux gen config file.
            mm_supervisor_build_dir: Path to the MM Supervisor build output.
            mmi_file_path: Path to MmiEntrySea.bin file.
            out_path: Path to place all generated artifacts.
            workspace: Path to the workspace. If not provided, the current directory is used.
        """
        try:
            inc_file_path = out_path / "MmArtifacts.dsc.inc"
            temp_hash_dir = out_path / "temp_hash.bin"
            temp_out_dir = out_path / "temp_out.inc"

            aux_path = generate_aux_file(aux_config_path, mm_supervisor_build_dir, scopes, out_path, workspace=workspace)

            # Copy the aux configuration file to the same directory as the aux file.
            shutil.copy2(aux_config_path, out_path / AUX_CONFIG_NAME)

            cmd = "BinToPcd.py"
            args = f"-i {aux_path}"
            args += f" -o {inc_file_path}"
            args += " -p gEfiSeaPkgTokenSpaceGuid.PcdAuxBinFile"
            ret = RunPythonScript(cmd, args)
            if ret != 0:
                raise RuntimeError("BinToPcd.py failed to convert PcdAuxBinFile. Review command output.")

            # Read the data structure size from the last 4 bytes of the file
            with open(mmi_file_path, 'rb') as f:
                f.seek(-4, os.SEEK_END)
                mmi_entry_size = int.from_bytes(f.read(), byteorder='little')
            mmi_entry_hash = calculate_file_hash(mmi_file_path, length=(os.path.getsize(mmi_file_path) - mmi_entry_size - 4))
            hex_bytes = bytes.fromhex(mmi_entry_hash)
            with open(temp_hash_dir, 'wb') as f:
                f.write(hex_bytes)

            cmd = "BinToPcd.py"
            args = f"-i {temp_hash_dir}"
            args += f" -o {temp_out_dir}"
            args += " -p gEfiSeaPkgTokenSpaceGuid.PcdMmiEntryBinHash"
            ret = RunPythonScript(cmd, args)
            if ret != 0:
                raise RuntimeError("BinToPcd.py failed to convert PcdMmiEntryBinHash. Review command output.")

            # Write the hash to the inc file
            with open(temp_out_dir, 'r') as f, open(inc_file_path, 'a') as o:
                mmi_entry_hash_pcd = f.read().strip()
                o.write("\r\n  ")
                o.writelines(mmi_entry_hash_pcd)
                o.write("\r\n  ")
                o.write("gEfiSeaPkgTokenSpaceGuid.PcdMmiEntryBinSize|0x%08X" % os.path.getsize(mmi_file_path))

            # MM supervisor core hash patching
            mm_supv_file = mm_supervisor_build_dir / "MmSupervisorCore.efi"
            mm_supv_core_hash = calculate_file_hash(mm_supv_file)
            hex_bytes = bytes.fromhex(mm_supv_core_hash)
            with open(temp_hash_dir, 'wb') as f:
                f.write(hex_bytes)

            cmd = "BinToPcd.py"
            args = f"-i {temp_hash_dir}"
            args += f" -o {temp_out_dir}"
            args += " -p gEfiSeaPkgTokenSpaceGuid.PcdMmSupervisorCoreHash"
            ret = RunPythonScript(cmd, args)
            if ret != 0:
                raise RuntimeError("BinToPcd.py failed to convert PcdMmSupervisorCoreHash. Review command output.")

            # Write the hash to the inc file
            with open(temp_out_dir, 'r') as f, open(inc_file_path, 'a') as o:
                mm_supv_core_hash_pcd = f.read().strip()
                o.write("\r\n  ")
                o.write(mm_supv_core_hash_pcd)

            temp_hash_dir.unlink(missing_ok=True)
            temp_out_dir.unlink(missing_ok=True)

        except FileNotFoundError as e:
            logging.error(f"File {e} not found.")
            return 1
        except RuntimeError as e:
            logging.error(e)
            return -1

        return 0

    @staticmethod
    def generate_sea_manifest(stm_bin: Path, output_path: Path, config: dict, workspace = None):
        """Generates the manifest file for the STM binary.
        
        Args:
            stm_bin: Path to the STM binary.
            output_path: Path to place the manifest file including filename.
            config: Configuration for the manifest generation.
        """
        if not stm_bin.is_file():
            raise FileNotFoundError(stm_bin)

        sea_version = config.get("version", "0.0.1-beta")
        security_version = config.get("security_version", "0")
        manifest_version = config.get("manifest_version", "1")
        algorithms = ",".join(config.get("algorithms", []))

        manifest_path = Path(workspace if workspace else Path(__file__).parent) / "Cargo.toml"

        args = f'run --manifest-path {str(manifest_path)}'
        args += ' --bin gen_manifest --'
        args += f' {stm_bin}'
        args += f' -o {output_path}'
        args += f' -a {algorithms}' * (algorithms != '')
        args += f' --sea-version {sea_version}'
        args += f' --security-version {security_version}'
        args += f' --manifest-version {manifest_version}'

        ret = RunCmd("cargo", args)
        if ret != 0:
            raise RuntimeError("gen_manifest failed. Is your Cargo workspace setup correctly?")
        
        return 0

    @staticmethod
    def validate_rule_coverage(percent: float, aux_path: Path) -> bool:
        """Validates the rule coverage of the auxiliary file.

        Args:
            percent (float): The minimum percentage of the file that must be covered.
            aux_path (Path): Path to the auxiliary file.
        
        Raises:
            FileNotFoundError: The auxiliary file path does not exist or is not a file.
            json.JSONDecodeError: The auxiliary file is not a valid JSON file.

        Returns:
            true if the rule coverage is above the threshold, false otherwise.
        """
        if not aux_path.is_file():
            raise FileNotFoundError(aux_path)

        with open(aux_path, 'r') as f:
            data = json.load(f)

        # Start with a simple check. Should technically be correct.
        covered_percent = float(data.get('covered_percent', '0%').strip('%'))
        if covered_percent < percent:
            logging.error(f"Auxiliary file rule coverage is below the allowed threshold of {percent}%: {covered_percent}%")
            return False

        # Lets double check the coverage by actually calculating via sections.
        if 'segments' not in data:
            logging.error("Auxiliary file does not contain any segments, broken format?")
            return False

        covered = 0
        total = 0
        for segment in data['segments']:
            if segment.get('reason', '') in ['Padding', 'PE Header']:
                continue

            size = int(segment['end'], 16) - int(segment['start'], 16)
            if segment.get('covered', False):
                covered += size
            else:
                logging.debug(f"Segment {segment} is not covered.")
            total += size

        actual_percent = round((float(covered) / float(total)) * 100, 2)
        if actual_percent < percent:
            logging.error(f"Auxiliary file rule coverage is below the allowed threshold of {percent}%: {actual_percent}%")
            return False

        return True

    @staticmethod
    def generate_stm_binary(stm_dll: Path, output_dir: Path):
        """Generates the STM binary from the STM DLL.

        Args:
            stm_dll (Path): path to the STM DLL
            output_dir (Path): path to place the STM binary
        """
        base_tools_dir = Path(os.environ['BASE_TOOLS_PATH'])
        gen_stm = base_tools_dir / "Bin" / "Win32" / "GenStm.exe"
        cmd = str(gen_stm)

        args = f"-e --debug 5 {stm_dll} -o {output_dir / 'Stm.bin'}"
        ret = RunCmd(cmd, args)
        if ret != 0:
            logging.error("GenStm failed. Review command output.")
            return ret
        return 0

    @staticmethod
    def generate_test_aux_binary(output_path: Path, mm_supervisor_build_dir: Path, pecoff_validation_lib_build_dir: Path, workspace = None):
        """Generates the test-aux binary.

        Args:
            output_path (Path): Path to place the test-aux binary
            mm_supervisor_build_dir (Path): Path to the MM Supervisor build output.
            sea_build_dir (Path): Path to the Sea Package build output.
            workspace (Path): Path to the workspace. If not provided, the current directory is used.
        """

        manifest_path = Path(workspace if workspace else Path(__file__).parent) / "Cargo.toml"

        os.environ['TEST_AUX_PECOFF_VALIDATION_LIB_DIR'] = str(pecoff_validation_lib_build_dir)
        os.environ['TEST_AUX_MM_SUPERVISOR_CORE_PDB_PATH'] = str(mm_supervisor_build_dir / "MmSupervisorCore.pdb")
        os.environ['TEST_AUX_MM_SUPERVISOR_CORE_EFI_PATH'] = str(mm_supervisor_build_dir / "MmSupervisorCore.efi")
        os.environ['RUSTC_BOOTSTRAP'] = str("1")

        args = 'build --release'
        args += ' --bin test-aux'
        args += f' --manifest-path {str(manifest_path)}'

        ret = RunCmd("cargo", args)
        if ret != 0:
            logging.error("Failed to compile test-aux. Is your Cargo workspace setup correctly?")
            return ret
        
        bin_path = manifest_path.parent / "target" / "release" / "test-aux.exe"
        bin_path.rename(output_path / "test-aux.exe")
        return 0


def generate_aux_file(aux_config_path: Path, mm_supervisor_build_dir: Path, scopes: list[str], output_dir: Path, workspace = None):
    """Generates the auxiliary file for the MmsupervisorCore.

    Args:
        aux_config_path: Path to the aux gen config file.
        mm_supervisor_build_dir: Path to the MM Supervisor build output.
        scopes: A list of scopes to activate for rule filtering. See create-aux --help for more information.
        output_dir: Path to place the artifacts.

    Raises:
        RuntimeError: if create-aux fails
    """

    output_path = output_dir / 'MmSupervisorCore.aux'
    manifest_path = Path(workspace if workspace else Path(__file__).parent) / "Cargo.toml"

    args = f"run --manifest-path {str(manifest_path)}"
    args += " --bin create-aux --"
    args += f" --pdb {str(mm_supervisor_build_dir / 'MmSupervisorCore.pdb')}"
    args += f" --efi {str(mm_supervisor_build_dir / 'MmSupervisorCore.efi')}"
    args += f" --output {str(output_path)}"
    args += f" --config {str(aux_config_path)}"
    for scope in scopes: 
        args += f" --scope {scope}"

    ret = RunCmd("cargo", args)
    if ret != 0:
        raise RuntimeError("gen_aux failed. Is your Cargo workspace setup correctly?")

    return output_path


def calculate_file_hash(file: Path, offset: int = 0, length: int = -1):
    """Calculates the hash of the auxiliary file.

    Args:
        file: Path to the auxiliary file.

    Returns:
        The hash of the auxiliary file.

    Raises:
        FileNotFoundError: The file does not exist
    """
    if not file.exists():
        raise FileNotFoundError(file)

    hasher = hashlib.new(HASH_ALGORITHM)
    with open(file, 'rb') as f:
        f.seek(offset)
        while length != 0:
            data = f.read(65536)
            if not data:
                break
            if length > 0:
                data = data[:length]
                length -= len(data)
            hasher.update(data)
    return hasher.hexdigest()
