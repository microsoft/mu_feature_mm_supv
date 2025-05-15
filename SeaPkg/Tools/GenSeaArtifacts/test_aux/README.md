# Test-Aux

This tool is used to quickly update and validate an auxiliary file by running it's validation tests locally.

Each compilation of the test-aux binary is associated with a single given compilation of the MmSupervisorCore and the
PeCoffValidationLib. This is done by reading the following environment variables during build:

`TEST_AUX_PECOFF_VALIDATION_LIB_DIR`: The directory containing the PeCoffValidationLib to link against
`TEST_AUX_MM_SUPERVISOR_CORE_PDB_PATH`: The exact path to the MmSupervisorCore.pdb
`TEST_AUX_MM_SUPERVISOR_CORE_EFI_PATH`: The exact path to the MmSupervisorCore.efi

The intent is that the executable is uploaded with all other build artifacts via the `GenSeaArtifacts` stuart plugin,
therefore compiling these directly into the binary makes the tool easier to use when the time comes. The tool has a
simple interface with the following two arguments:

1. `-a`, `--aux-config`: The path to the aux configuration file to use to generate the auxiliary file for testing.
2. `-c`, `--config`: The path to the configuration file containing key information dumped from a run log, that is
   necessary to properly test the aux file.

## Configuration

As mentioned above, the `-c`, `--config` argument is to pass in a configuration file that contains the information from
a run log of the given mm supervisor core.

### MmSupervisorBase

LoadAddress is the first configuration that is needed, which is a string hex representation of the address the mm
supervisor core was loaded to during the build.

`MmSupervisorBase = "0x&BDC0000"`

### MmSupervisor

MmSupervisorCore is a string dump of the entire post-execution MmSupervisorCore image. This is found in the build log
as a `DUMP_HEX` dump. This can be passed directly into the configuration file. The tool takes care of cleaning up the
data.

``` toml
MmSupervisor = '''
13:52:40.030 :     00000000: 4D 5A 00 00 00 00 00 00-00 00 00 00 00 00 00 00  *MZ..............*
13:52:40.030 :     00000010: 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  *................*
'''
```
