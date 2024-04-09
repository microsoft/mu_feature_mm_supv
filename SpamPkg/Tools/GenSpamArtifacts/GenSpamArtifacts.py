# @file
# UEFI Helper plugin for generating SPAM artifacts based off of the MM Supervisor build.
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import hashlib
import logging
from pathlib import Path
import shutil
from typing import Tuple

from edk2toolext.environment.plugintypes.uefi_helper_plugin import IUefiHelperPlugin
from edk2toollib.utility_functions import RunCmd


HASH_ALGORITHM = "sha256"


class GenSpamArtifacts(IUefiHelperPlugin):
    def RegisterHelpers(self, obj):
      fp = os.path.abspath(__file__)
      obj.Register("generate_spam_artifacts", GenSpamArtifacts.generate_spam_artifacts, fp)

    @staticmethod
    def generate_spam_artifacts(aux_config_path: Path, mm_supervisor_build_dir: Path, spam_build_dir: Path, output_dir: Path):
        """Generates SPAM artifacts.

        Generates the following artifacts:
        - MmSupervisorCore.aux (As build by gen_aux)
        - MmSupervisorCore.efi (As Build by edk2 build system)
        - Stm.bin (With the patched <HASH_ALGORITHM> hash of the MmSupervisorCore.aux file)

        Args:
            aux_config_path: Path to the aux gen config file.
            mm_supvervisor_build_dir: Path to the MM Supervisor build output.
            spam_build_dir: Path to the Spam Package build output.
            output_dir: Path to place the artifacts.
        """
        try:
            stm_build_dir = spam_build_dir / "Core" / "Stm" / "DEBUG"
            mmi_build_dir = spam_build_dir / "MmiEntrySpam" / "MmiEntrySpam" / "OUTPUT"

            aux_path = generate_aux_file(aux_config_path, mm_supervisor_build_dir, output_dir)
            aux_hash = calculate_aux_hash(aux_path)

            stm_dll = stm_build_dir / "Stm.dll"
            pcd = "PcdAuxBinHash"
            pcd_addr = get_patch_pcd_address(stm_build_dir / "Stm.map", stm_dll, pcd)

            if pcd_addr is None:
                logging.error(f"PCD {pcd} not found in STM PCD table.")
                return -1
            
            patch_pcd_value(stm_dll, pcd_addr, aux_hash)
            generate_stm_binary(stm_dll, output_dir)

            misc_dir = output_dir / "Misc"
            misc_dir.mkdir(exist_ok=True)

            # Copy over STM artifacts
            shutil.copy2(
                stm_build_dir / "Stm.map",
                misc_dir / "Stm.map"
            )

            shutil.copy2(
                stm_build_dir / "Stm.pdb",
                misc_dir / "Stm.pdb"
            )

            # Copy over MmSupervisorCore artifacts
            shutil.copy2(
                mm_supervisor_build_dir / "MmSupervisorCore.efi",
                output_dir / "MmSupervisorCore.efi"
            )
            shutil.copy2(
                mm_supervisor_build_dir / "MmSupervisorCore.map",
                misc_dir / "MmSupervisorCore.map"
            )
            shutil.copy2(
                mm_supervisor_build_dir / "MmSupervisorCore.pdb",
                misc_dir / "MmSupervisorCore.pdb"
            )

            # Copy over MmiEntrySpam artifacts
            shutil.copy2(
                mmi_build_dir / "MmiEntrySpam.bin",
                output_dir / "MmiEntrySpam.bin"
            )
            shutil.copy2(
                mmi_build_dir / "MmiEntrySpam.lst",
                misc_dir / "MmiEntrySpam.lst"
            )

        except FileNotFoundError as e:
            logging.error(f"File {e} not found.")
            return 1
        except RuntimeError as e:
            logging.error(e)
            return -1

        return 0


def generate_aux_file(aux_config_path: Path, mm_supervisor_build_dir: Path, output_dir: Path):
    """Generates the auxiliary file for the MmsupervisorCore.
   
    Args:
        aux_config_path: Path to the aux gen config file.
        mm_supvervisor_build_dir: Path to the MM Supervisor build output.
        output_dir: Path to place the artifacts.
        
    Raises:
        RuntimeError: if gen_aux fails
    """

    output_path = output_dir / 'MmSupervisorCore.aux'

    args = "run --"
    args += f" --pdb {str(mm_supervisor_build_dir / 'MmSupervisorCore.pdb')}"
    args += f" --efi {str(mm_supervisor_build_dir / 'MmSupervisorCore.efi')}"
    args += f" --output {str(output_path)}"
    args += f" --config {str(aux_config_path)}"

    ret = RunCmd("cargo", args)
    if ret != 0:
        raise RuntimeError("gen_aux failed. Is your Cargo workspace setup correctly?")
    
    return output_path


def calculate_aux_hash(file: Path):
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
        raise RuntimeError("GenPatchPcdTable Failed. Review command output.")

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


def generate_stm_binary(stm_dll: Path, output_dir: Path):
    """Generates the STM binary from the STM DLL.

    Args:
        stm_dll (Path): path to the STM DLL
        output_dir (Path): path to place the STM binary

    Raises:
        RuntimeError: if GenStm fails
    """
    base_tools_dir = Path(os.environ['BASE_TOOLS_PATH'])
    gen_stm = base_tools_dir / "Bin" / "Win32" / "GenStm.exe"
    cmd = str(gen_stm)

    args = f"-e --debug 5 {stm_dll} -o {output_dir / 'Stm.bin'}"
    ret = RunCmd(cmd, args)
    if ret != 0:
        raise RuntimeError("GenStm failed. Review command output.")

