# Standalone MM

System Management Mode (SMM) architecturally presents a persistent threat to overall system integrity and hypervisor
security. Today, the majority of SMM software is written in [**Traditional MM**](TraditionalMm.md), which is prone to
manufacturer error resulting in costly security defects that diminish expensive investments made elsewhere in the system
software stack to improve ecosystem security and integrity (e.g. [HVCI](https://learn.microsoft.com/windows-hardware/drivers/bringup/device-guard-and-credential-guard)).

**Standalone MM** is a relatively new software model for MM code that revises the historical mode now called
"Traditional MM". Standalone MM applies learnings from software vulnerabilities and weaknesses in the Traditional MM
model to either prevent those vulnerabilities or greatly reduce the likelihood of them occurring. However, even the
Standalone MM design as defined in the specifications is not strict enough. This section will also describe the
general problems solved with the PI Specification definition of Standalone MM and additional issues that need to be
resolved outside the specification.

Standalone MM can largely be considered a more disciplined approach to software execution in MM. This discipline
contributes to reduced likelihood of security issues, increased portability, and more flexibility in how to launch the
MM environment.

## Beyond the PI Specification Standalone MM Definition

There are some best practices that are not technically required to implement Standalone MM, but we have found for
Standalone MM to maximize security value.

### Benefits of Early MM Launch

Standalone MM can be launched in PEI which is preferred but it can also be launched in DXE at a similar point in the boot
flow to Traditional MM to minimize deviation between the initialization point of the two modes.

A high-level proposed Standalone MM IPL process in PEI is described below.

1. Dispatch the Standalone MM PEI IPL in post-memory PEI.
2. In the entry point of the Standalone MM PEI IPL, verify system pre-requisites are satisfied to set up the MM foundation
   in MMRAM.
   - Example: the MM Control PPI and MM Access PPI are installed and sufficiently large MMRAM regions are reported.
   - Because in Standalone MM, the platform cannot provide information via DXE interfaces, it is expected a platform will
     have to provide data in HOBs that must be present when the Standalone MM PEI IPL is executed.
     - In general, this is considered a more ordered and structured approach to providing data into MM.
3. Check if the system PEI is 32-bit. If so, cache the system execution context and then switch to X64 mode to load a X64
   relay module (similar to CapsuleX64.inf).
   - The X64 relay module can execute the Standalone MM core entry point with a supplied HOB start address.
4. During the Standalone MM Foundation initialization, all Standalone MM drivers are loaded into MMRAM. No further drivers
   will be loaded from outside MMRAM during the boot.
   - To better organize this process and focus relevant module exposure to the corresponding dispatchers, all Standalone
     MM drivers can be consolidated in a single firmware volume.
5. After the Standalone MM Core Foundation is setup, the system will return to 32-bit mode restoring the cached context
   information, if applicable, and closing and locking all MMRAM regions.
6. The Standalone MM PEI IPL installs the MM Communication PPI for PEIM usage in the remainder of the PEI phase.
7. Once DXE is launched, the DXE MM Communication Protocol will be installed for DXE drivers to communicate with Standalone
   MM drivers.

Because MM is launching earlier and in a standalone environment, it is also recommended to apply system security locks
as early as possible by taking advantage of the earlier launch point.

### Benefits of Constraining Broad Memory Access

It is recommended that broad memory access be reduced in Standalone MM. This can be achieved by only allowing explicit
memory ranges accessible to MM outside of MMRAM. Instead of the traditional model in which MM code can access memory
buffers allocated prior to `SmmReadyToLock`, the `MmUnblockMemoryLib` API provides a mechanism for callers outside MM to
permit explicit ranges to be accessible. This greatly reduces the overall attack surface by limiting input buffers to
the MM environment largely to allowed comm buffers and the impact on the environment outside of MM in the case of a
confused deputy attack.

Access to common global structures outside MM like `gBS` and `gDS` from within MM code should never be allowed.
