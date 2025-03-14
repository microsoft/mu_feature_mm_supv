# Microsoft MM Supervisor and SMM Enhanced Attestation (SEA) Overview

This document provides an overview of the Microsoft SMM Supervisor and SMM Enhanced Attestation (SEA) feature. To
understand why these solutions exist, what they do, and how they work, some related concepts will be reviewed.

---

## Table of Contents

1. [System Management Mode (SMM)](#system-management-mode-smm)
2. [User / Supervisor Privilege Separation](#user--supervisor-privilege-separation)
3. [Hardware Resource Isolation](#hardware-resource-isolation)
4. [Chains of Trust and Dynamic Root of Trust](#chains-of-trust-and-dynamic-root-of-trust)
   1. [Chain of Trust](#chain-of-trust)
   2. [Root of Trust](#root-of-trust)
      1. [Dynamic Root of Trust for Measurement (D-RTM)](#dynamic-root-of-trust-for-measurement-d-rtm)
5. [SMM Enhanced Attestation (SEA)](#smm-enhanced-attestation-sea)
   1. [SEA on Intel Devices](#sea-on-intel-devices)
      1. [SEA Details on Intel Devices](#sea-details-on-intel-devices)
6. [Summary](#summary)

---

## System Management Mode (SMM)

System Management Mode (SMM) or Management Mode (MM) is a special-purpose operating mode in x86 architecture
with high execution privilege that is used to monitor and manage various system resources. MM code is often written
similarly to non-MM UEFI Code, built with the same toolset and included alongside non-MM UEFI code in the same firmware
image. However, MM code executes in a special region of meemory that is isolated from the rest of the system, and it is
not directly accessible to the operating system or other software running on the system. This region is called System
Management RAM (SMRAM) or Mangagement Mode RAM (MMRAM).

MM is entered by triggering a System Management Interrupt (SMI) also called a Management Mode Interrupt (MMI). The
MMI may be either triggered by software (synchronous) or a hardware (asynchronous) event. A MMI is a high priority,
non-maskable interrupt. On receipt of the interrupt, the processor saves the current state of the system and switches
to MM. Within MM, the code must set up its own execution environment such as applying an interupt descriptor table (IDT),
creating page tables, etc. It must also identify the source of the MMI to determine what MMI handler to invoke in
response.

Recently, there has been an effort to reduce and even eliminate the use of MM in modern systems. MM represents a large
attack surface because of its pervasiveness throughout the system lifetime. It is especially impactful if compromised
due to its ubiquity and system access privilege. A vulnerability in a given MM implementation could further be used to
compromise or circumvent OS protections such as Virtualization-based Security (VBS). Based on the current use cases
for MM and available alternatives, it is not possible to completely eliminate MM from modern systems.

MM code is simply software. Like all software, implementations vary across system vendors and a mix of common and
unique bugs exist across those implementations. Previous efforts to secure MM have focused on hardware locking and
simple software best practices that have left obvious gaps that continue to be exploited.

This document describes how the SMM Enhanced Attestation (SEA) feature is a key technology used to secure MM with the
open-source solutions in this repository.

### Software Models for Management Mode

While MM code can be written in any arbitrary way, there are two common software models for MM code in the industry
today that are defined in the [Platform Initialization (PI) specification](https://uefi.org/specifications) maintained
by the UEFI Forum.

- [Traditional MM](https://uefi.org/specs/PI/1.8/V4_Overview.html#initializing-management-mode-in-mm-traditional-mode)
- [Standalone MM](https://uefi.org/specs/PI/1.8/V4_Overview.html#initializing-management-mode-in-mm-standalonemode)

All solutions in this repository use Standalone MM. For more details about why Standalone MM is preferred over
Traditional MM, see [Traditional and Standalone MM](TraditionalAndStandaloneMm.md).

## User / Supervisor Privilege Separation

User / Supervisor Privilege Separation is a fundamental security principle that is used to protect system resources
from unauthorized access. In the context of x86 architecture, the processor has four privilege levels (rings) that
are used to control access to system resources. The highest privilege level is Ring 0 (Supervisor Mode), which is used
by the operating system kernel and other privileged software. The lowest privilege level is Ring 3 (User Mode), which is
used by user applications. The other two privilege levels are Ring 1 and Ring 2, which are not commonly used in modern
systems.

Within the isolated MM environment, it is important to distinguish between two types of MM code:

1. "MM Core Code" - This is the core MM code that is common and shared with minimal to no change between systems.
2. "MM System Code" - This is the system-specific MM code that is provided by the system vendor to handle system-wide
   functions like power management, system hardware control, or proprietary OEM-designed code.

The attack surface imposed by MM can be greatly reduced by introducing privilege separation to the MM environment with
a natural delineation between "MM Core Code" as *Supervisor Mode* code that manages the overall environment and
"MM System Code" that runs within that environment in *User Mode* to perform platform-specific tasks.

For example, this means that a MM driver written by a platform vendor would be executed in user mode. Due to the
restrictions of user mode, the driver must request access to system assets from the Supervisor allowing the Supervisor
to enforce access control policies over each such request.

It is critical to enforce this separation from the time of MM creation, so the MM environment is consistently secure
throughout its entire execution and its security is independent from the non-MM environment once it is active.

## Hardware Resource Isolation

By default, MM code has access to all system resources, no privilege separation is in place, and memory is accessible
up to 4GB.

Key system resources in x86 architecture include IO ports, Model Specific Registers (MSR), MMIO ranges, the CPU save
state area and allowed instructions within the *User Mode* MM environment. The code that runs in *Supervisor Mode* in
this repository, is called the "MM Supervisor". The configuration of allowed resources is defined by a
"MM Supervisor Policy". This policy is used to configure the exact details of what hardware resources to restrict,
and those exact details are subject to change per silicon generation. A policy can either define assume all resources
are allowed by default and restrict specific resources, or assume all resources are restricted by default and allow
specific resources. We recommend the latter approach as the resources accessed by MM for a given platform remain a
fixed set for the platform MM code coupled with its MM Supervisor Policy.

The policy is a contract between the platform that creates it, the MM Supervisor that enforces it, and the operating
system code that can audit and trust it.

## Chains of Trust and Dynamic Root of Trust

For an operating system to be convinced that MM is secure per the above principles, it must be able to **trust** that
the MM Supervisor is genuine so that it enforces the MM Supervisor Policy as expected. Furthermore, the MM Supervisor
Policy must be verified to be authentic and unaltered, so it is accurate per the manufacturer's intent. Then the
operating system can trust any assertions made about how the MM Supervisor has secured the MM environment.

### Chain of Trust

The initial firmware execution in a modern PC follows a boot process where an initial set of code loads other code,
and the level of functionality expands as the boot progresses. Each set of code verifies the next set of code forming
a chain of trust. When UEFI firmware gains control, it follows the Secure Boot standard of verifying software signature
to continue the chain of trust all the way to the operating system. Then, the Windows boot loader continues the chain
of trust with Trusted Boot, which verifies every other OS component in the startup process before it's loaded.

In general, attackers seek to gain control as early as possible in the boot process before security features and locks
that help protect the system are enabled. When the system is brought out of reset, the initial set of code executed must
be anchored in trust. The hardware verification technology that fulfills the role to perform this early code verification
is called the **root of trust**. While the exact details vary by hardware vendor, all roots of trust are typically rooted
in immutable hardware or ROMs in the SOC.

### Root of Trust

A *root of trust* established once and carried throughout a chain of trust involving subsequent components throughout
boot is called a *Static Root of Trust*. In contrast, a *Dynamic Root of Trust* only trusts a small portion of the
early chipset initialization firmware code at the beginning of boot, and a hardware agent is used to re-establish
trust dynamically later in boot. Therefore, the system can boot through a period of untrusted code but shortly
after dynamically launch into a trusted state by taking control of all CPUs and forcing them down a well-known and
measured path.

#### Dynamic Root of Trust for Measurement (D-RTM)

The firmware ecosystem contains hundreds of drivers written by different vendors. Manufacturers also differentiate
their devices with solutions that require custom firmware. During boot, multiple chains of trust are active. The
platform manufacturer will execute their custom firmware within the static root of trust established during reset.
Later in boot, the operating system will need to establish a new chain of trust, with minimal authorities, to ensure
that its operating environment is secure regardless of the static chain of trust active until that point.

A Root of Trust for Measurement (RTM) means that we leverage a chain of trust to bootstrap the process of building a
measurement chain in the Trusted Platform Module (TPM). This measurement chain can later be inspected for attestation
of what exactly executed on the system, but it is trusted because it originates from a root of trust. In the case of the
static and dynamic roots of trust, two sets of Platform Configuration Registers (PCRs) respectively store their
measurements - the S-RTM PCRs in PCR[0-15] and the D-RTM PCRs in PCR[17-22].

## SMM Enhanced Attestation (SEA)

Microsoft [Project Mu](https://microsoft.github.io/mu/) is an open-source firmware project that contains
[UEFI](https://uefi.org/) firmware code. The [MM Supervisor feature](https://github.com/microsoft/mu_feature_mm_supv/tree/HEAD/MmSupervisorPkg)
provides the firmware code for a Standalone MM core for the X64 architecture that applies CPU privilege level separation
(i.e. user and supervisor mode). The core “kernel” code executes at CPL0 while platform MM code executes at CPL3. The
MM Supervisor can enforce resource isolation for MSRs, I/O ports, memory regions (including SMM save state), and
instruction types as configured by a platform. Microsoft publishes a minimum set of resource constraints per its
Secured-core PC requirements. The MM Supervisor can achieve the highest level of Secured-core PC SMM isolation –
Level 30.

SMM Enhanced Attestation (SEA) is a feature that extends the MM Supervisor to provide a secure attestation mechanism
for the MM environment. SEA is what allows the operating system to trust that the MM Supervisor is genuine, unaltered,
and a trusted version so it can enforce the MM Supervisor Policy as expected. With this trust established, SEA enables
a system to meet the Microsoft Windows Secured-core PC requirements for MM security.

### SEA on Intel Devices

In Intel architecture, the dynamic chain of trust is initiated by leveraging Intel Trusted Execution Technology (TXT),
which begins the new chain of trust via execution of the `getsec` instruction. In this chain of trust, only two
authorities must be trusted and verified with a SEA solution: the CPU vendor (Intel) and the SEA/OS vendor (Microsoft).

Beginning with Intel Lunar Lake products ([Intel Core Ultra 7 Processor 256V example](https://www.intel.com/content/www/us/en/products/sku/240951/intel-core-ultra-5-processor-238v-8m-cache-up-to-4-70-ghz/specifications.html))
and later, Intel Trusted Execution Technology (TXT) is widely available across processor SKUs.

#### SEA Details on Intel Devices

Intel architecture supports a feature called SMI Transfer Monitor (STM) that was originally designed to use Intel
TXT and Intel Virtualization Technology (VT-x) to virtualize platform MMI handlers. Anyone can build an STM solution
and details to do so are documented in the [SMI Transfer Monitor (STM) Developer or User Guide](https://www.intel.com/content/www/us/en/content-details/671521/smi-transfer-monitor-stm-developer-or-user-guide.html).

MMRAM on Intel devices is mapped to a region called TSEG. Within TSEG, the STM resides in a region called MSEG. MSEG
has special chipset configuration registers such as `IA32_SMM_MONITOR_CTL.MSEG_BASE` that sets the lower bound of MSEG.

The STM guide defines a VMCALL style interface that can be implemented to facilitate interoperability with a MMI
handler. This further facilitates communication between a Measured Launch Envrionment (MLE) such as Windows and the
STM.

SEA builds upon the STM design to interact with the OS via a VMCALL interface. The SEA source code is entirely open-source,
but built into a binary with a STM header that is signed by Microsoft. A SEA solution includes the following software
notable components in addition to standard Intel TXT components:

1. MM Supervisor binary (built and signed by Microsoft)
2. MM Supervisor policy (created by the platform vendor)
3. SEA binary (built and signed by Microsoft)
4. SEA manifest (built and signed by Microsoft)

The MM Supervisor binary is included in the firmware ROM image and serves as the Standalone MM core that enforces the
MM Supervisor policy within the privilege-separated MM environment. The corresponding SEA binary is included in the
firmware ROM image. The SEA manifest that accompanies a given SEA binary has the signed hash for the SEA binary. Since
the manifest is signed by Microsoft, the authenticity and integrity of the SEA binary can be verified from the SEA
manifest. During boot, in the static chain of trust, non-MM firmware will verify the SEA binary and move it into MSEG,
also programming the relevant chipset registers to set up MSEG. Additional initialization is performed to enable TXT and
VT-x.

During early Windows OS boot, the OS will detect that Intel TXT technology is enabled and execute the `GETSEC[SENTER]`
instruction to start the D-RTM launch into the Measured Launch Environment (MLE). In this new chain of trust, the CPU
microcode, which is verified against a hardware fused key, will verify that the SINIT Intel Authenticated Code Module
(ACM) is signed by Intel. The SINIT ACM initializes the D-RTM PCRs by first extending the hash of the SINIT ACM. Other
SINIT ACM operations further extend the dynamic PCRs according to the sequence in
[Intel TXT Software Development Guide](https://cdrdv2-public.intel.com/315168/315168_TXT_MLE_DG_rev_017_4.pdf). Notably,
the SINIT ACM extends the hash of the content in MSEG (a STM or, in this case, SEA) to PCR[17].

The MLE discovers the SEA manifest placed in the UEFI configuration table to determine that SEA is present on this
system. The SEA manifest is verified against the Microsoft key. The SEA hash that was extended to PCR[17] is compared
against the hash in the verified SEA manifest. SEA can now be trusted. The MLE interacts with SEA via the VMCALL
interface to determine if the MM Supervisor can be trusted. The SEA binary will reconstruct the MM Supervisor image that
is loaded and active in TSEG such that it can be verified against the known hash in the SEA binary. It will also verify
that all of the mutable areas os the image such as global variables are set to allowed values. Now, the MM Supervisor
can be trusted. In turn, the MM Supervisor can be trusted to properly report the MM Supervisor Policy status to the
operating system so it can understand the security state of the MM environment and make decisions based on that state.

## Summary

SEA is an open source technology that completes an end-to-end story for securing the MM environment using the safer
Standalone MM architecture, with privilege separation, resource isolation, and a dynamic chain of trust. While the
SEA source code is generic and open-source, the SEA binary is signed by Microsoft to ensure its authenticity and
integrity across any devices within a given product generation. More details on signed SEA binaries will be made
available in the future.
