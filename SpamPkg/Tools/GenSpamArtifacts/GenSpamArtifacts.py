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
from edk2toollib.utility_functions import RunCmd, RunPythonScript


HASH_ALGORITHM = "sha256"


class GenSpamArtifacts(IUefiHelperPlugin):
    def RegisterHelpers(self, obj):
        fp = os.path.abspath(__file__)
        obj.Register("generate_spam_includes", GenSpamArtifacts.generate_spam_includes, fp)
        obj.Register("generate_spam_artifacts", GenSpamArtifacts.generate_spam_artifacts, fp)

    @staticmethod
    def generate_spam_includes(aux_config_path: Path, mm_supervisor_build_dir: Path, spam_build_dir: Path, inc_file_path: Path):
        """Generates SPAM artifacts.

        Generates the following artifacts:
        - MmSupervisorCore.aux (As build by gen_aux)
        - MmSupervisorCore.efi (As Build by edk2 build system)

        Args:
            aux_config_path: Path to the aux gen config file.
            mm_supervisor_build_dir: Path to the MM Supervisor build output.
            spam_build_dir: Path to the Spam Package build output.
        """
        try:
            stm_build_dir = spam_build_dir / "Core" / "Stm" / "DEBUG"
            mmi_build_dir = spam_build_dir / "MmiEntrySpam" / "MmiEntrySpam" / "OUTPUT"

            if not os.path.exists(stm_build_dir):
                os.makedirs(stm_build_dir)

            temp_hash_dir = stm_build_dir / "temp_hash.bin"
            temp_out_dir = stm_build_dir / "temp_out.inc"

            aux_path = generate_aux_file(aux_config_path, mm_supervisor_build_dir, stm_build_dir)

            cmd = "BinToPcd.py"
            args = f"-i {aux_path}"
            args += f" -o {inc_file_path}"
            args += " -p gEfiSpamPkgTokenSpaceGuid.PcdAuxBinFile"
            ret = RunPythonScript(cmd, args)
            if ret != 0:
                raise RuntimeError("BinToPcd.py failed to convert PcdAuxBinFile. Review command output.")

            # MMI entry block hash patching
            mmi_entry_file = mmi_build_dir / "MmiEntrySpam.bin"
            # Read the data structure size from the last 4 bytes of the file
            with open(mmi_entry_file, 'rb') as f:
                f.seek(-4, os.SEEK_END)
                mmi_entry_size = int.from_bytes(f.read(), byteorder='little')
            mmi_entry_hash = calculate_file_hash(mmi_entry_file, length=(os.path.getsize(mmi_entry_file) - mmi_entry_size - 4))
            hex_bytes = bytes.fromhex(mmi_entry_hash)
            with open(temp_hash_dir, 'wb') as f:
                f.write(hex_bytes)

            cmd = "BinToPcd.py"
            args = f"-i {temp_hash_dir}"
            args += f" -o {temp_out_dir}"
            args += " -p gEfiSpamPkgTokenSpaceGuid.PcdMmiEntryBinHash"
            ret = RunPythonScript(cmd, args)
            if ret != 0:
                raise RuntimeError("BinToPcd.py failed to convert PcdMmiEntryBinHash. Review command output.")

            # Write the hash to the inc file
            with open(temp_out_dir, 'r') as f, open(inc_file_path, 'a') as o:
                mmi_entry_hash_pcd = f.read().strip()
                o.write("\r\n  ")
                o.writelines(mmi_entry_hash_pcd)
                o.write("\r\n  ")
                o.write("gEfiSpamPkgTokenSpaceGuid.PcdMmiEntryBinSize|0x%08X" % os.path.getsize(mmi_entry_file))

            # MM supervisor core hash patching
            mm_supv_file = mm_supervisor_build_dir / "MmSupervisorCore.efi"
            mm_supv_core_hash = calculate_file_hash(mm_supv_file)
            hex_bytes = bytes.fromhex(mm_supv_core_hash)
            with open(temp_hash_dir, 'wb') as f:
                f.write(hex_bytes)

            cmd = "BinToPcd.py"
            args = f"-i {temp_hash_dir}"
            args += f" -o {temp_out_dir}"
            args += " -p gEfiSpamPkgTokenSpaceGuid.PcdMmSupervisorCoreHash"
            ret = RunPythonScript(cmd, args)
            if ret != 0:
                raise RuntimeError("BinToPcd.py failed to convert PcdMmSupervisorCoreHash. Review command output.")

            # Write the hash to the inc file
            with open(temp_out_dir, 'r') as f, open(inc_file_path, 'a') as o:
                mm_supv_core_hash_pcd = f.read().strip()
                o.write("\r\n  ")
                o.write(mm_supv_core_hash_pcd)

        except FileNotFoundError as e:
            logging.error(f"File {e} not found.")
            return 1
        except RuntimeError as e:
            logging.error(e)
            return -1

        return 0

    @staticmethod
    def generate_spam_artifacts(mm_supervisor_build_dir: Path, spam_build_dir: Path, output_dir: Path):
        """Generates SPAM artifacts.

        Generates the following artifacts:
        - Stm.bin (With the patched <HASH_ALGORITHM> hash of the MmSupervisorCore and MmiEntrySpam file)

        Args:
            aux_config_path: Path to the aux gen config file.
            mm_supervisor_build_dir: Path to the MM Supervisor build output.
            spam_build_dir: Path to the Spam Package build output.
            output_dir: Path to place the artifacts.
        """
        try:
            stm_build_dir = spam_build_dir / "Core" / "Stm" / "DEBUG"
            mmi_build_dir = spam_build_dir / "MmiEntrySpam" / "MmiEntrySpam" / "OUTPUT"

            stm_dll = stm_build_dir / "Stm.dll"

            # Done with patching, generate STM binary
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
        mm_supervisor_build_dir: Path to the MM Supervisor build output.
        output_dir: Path to place the artifacts.

    Raises:
        RuntimeError: if gen_aux fails
    """

    output_path = output_dir / 'MmSupervisorCore.aux'

    args = "run --bin gen_aux --"
    args += f" --pdb {str(mm_supervisor_build_dir / 'MmSupervisorCore.pdb')}"
    args += f" --efi {str(mm_supervisor_build_dir / 'MmSupervisorCore.efi')}"
    args += f" --output {str(output_path)}"
    args += f" --config {str(aux_config_path)}"

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
