/** @file -- MmPolicyMeasurementLevels.h

SCPC SMM measurement levels based on policy reports.

Copyright (C) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef MM_POLICY_MEASUREMENT_LEVELS_H_
#define MM_POLICY_MEASUREMENT_LEVELS_H_

/*
MSRs level 20
  - Must ensure that SMM does NOT contain any mappings to the
    following Model Specific Registers:
      INTEL:
        - X86X_IA32_PMG_IO_CAPTURE_BASE
        - X86X_IA32_MSR_DS_AREA
        - X86X_IA32_MSR_PKG_HDC_CONFIG
        - X86X_IA32_MSR_PKG_HDC_RESIDENCY
        - X86X_IA32_MSR_PKG_HDC_SHALLOW_RESIDENCY
        - X86X_IA32_MSR_PKG_HDC_DEEP_RESIDENCY
        - X86X_IA32_MSR_WEIGHTED_CORE_CO
        - X86X_IA32_MSR_UNC_CBO_0_PERF_EVT_SEL0
        - X86X_IA32_MSR_UNC_CBO_0_PERF_EVT_SEL1
        - X86X_IA32_MSR_UNC_CBO_0_PERF_CTR0
        - X86X_IA32_MSR_UNC_CBO_0_PERF_CTR1
        - X86X_IA32_MSR_UNC_CBO_1_PERF_EVT_SEL0
        - X86X_IA32_MSR_UNC_CBO_1_PERF_EVT_SEL1
        - X86X_IA32_MSR_UNC_CBO_1_PERF_CTR0
        - X86X_IA32_MSR_UNC_CBO_1_PERF_CTR1
        - X86X_IA32_MSR_UNC_CBO_2_PERF_EVT_SEL0
        - X86X_IA32_MSR_UNC_CBO_2_PERF_EVT_SEL1
        - X86X_IA32_MSR_UNC_CBO_2_PERF_CTR0
        - X86X_IA32_MSR_UNC_CBO_2_PERF_CTR1
        - X86X_IA32_MSR_UNC_CBO_3_PERF_EVT_SEL0
        - X86X_IA32_MSR_UNC_CBO_3_PERF_EVT_SEL1
        - X86X_IA32_MSR_UNC_CBO_3_PERF_CTR0
        - X86X_IA32_MSR_UNC_CBO_3_PERF_CTR1
      AMD:
        - Core::X86::Msr::DBG_CTL_MSR
        - Core::X86::Msr::EFER
        - Core::X86::Msr::SYS_CFG
        - Core::X86::Msr::STAR
        - Core::X86::Msr::STAR64
        - Core::X86::Msr::STARCOMPAT
        - Core::X86::Msr::SYSCALL_FLAG_MASK
        - Core::X86::Msr::SMM_BASE
        - Core::X86::Msr::XSS
        - Core::X86::Msr::U_CET
        - Core::X86::Msr::S_CET
        - Core::X86::Msr::PL0Ssp
        - Core::X86::Msr::PL1Ssp
        - Core::X86::Msr::PL2Ssp
        - Core::X86::Msr::PL3Ssp
        - Core::X86::Msr::IstSspAddr
*/
CONST UINT64 SCPC_LVL20_MSR_INTEL[] = {
  228,      // X86X_IA32_PMG_IO_CAPTURE_BASE
  1536,     // X86X_IA32_MSR_DS_AREA
  1618,     // X86X_IA32_MSR_PKG_HDC_CONFIG
  1619,     // X86X_IA32_MSR_PKG_HDC_RESIDENCY
  1621,     // X86X_IA32_MSR_PKG_HDC_SHALLOW_RESIDENCY
  1622,     // X86X_IA32_MSR_PKG_HDC_DEEP_RESIDENCY
  1624,     // X86X_IA32_MSR_WEIGHTED_CORE_CO
  1792,     // X86X_IA32_MSR_UNC_CBO_0_PERF_EVT_SEL0
  1793,     // X86X_IA32_MSR_UNC_CBO_0_PERF_EVT_SEL1
  1798,     // X86X_IA32_MSR_UNC_CBO_0_PERF_CTR0
  1799,     // X86X_IA32_MSR_UNC_CBO_0_PERF_CTR1
  1808,     // X86X_IA32_MSR_UNC_CBO_1_PERF_EVT_SEL0
  1809,     // X86X_IA32_MSR_UNC_CBO_1_PERF_EVT_SEL1
  1814,     // X86X_IA32_MSR_UNC_CBO_1_PERF_CTR0
  1815,     // X86X_IA32_MSR_UNC_CBO_1_PERF_CTR1
  1824,     // X86X_IA32_MSR_UNC_CBO_2_PERF_EVT_SEL0
  1825,     // X86X_IA32_MSR_UNC_CBO_2_PERF_EVT_SEL1
  1830,     // X86X_IA32_MSR_UNC_CBO_2_PERF_CTR0
  1831,     // X86X_IA32_MSR_UNC_CBO_2_PERF_CTR1
  1840,     // X86X_IA32_MSR_UNC_CBO_3_PERF_EVT_SEL0
  1841,     // X86X_IA32_MSR_UNC_CBO_3_PERF_EVT_SEL1
  1846,     // X86X_IA32_MSR_UNC_CBO_3_PERF_CTR0
  1847      // X86X_IA32_MSR_UNC_CBO_3_PERF_CTR1
};

CONST UINT64 SCPC_LVL20_MSR_AMD[] = {
  0x000001D9,   // Core::X86::Msr::DBG_CTL_MSR
  0xC0000080,   // Core::X86::Msr::EFER
  0xC0010010,   // Core::X86::Msr::SYS_CFG
  0xC0000081,   // Core::X86::Msr::STAR
  0xC0000082,   // Core::X86::Msr::STAR64
  0xC0000083,   // Core::X86::Msr::STARCOMPAT
  0xC0000084,   // Core::X86::Msr::SYSCALL_FLAG_MASK
  0xC0010111,   // Core::X86::Msr::SMM_BASE
  0x00000DA0,   // Core::X86::Msr::XSS
  0x000006A0,   // Core::X86::Msr::U_CET
  0x000006A2,   // Core::X86::Msr::S_CET
  0x000006A4,   // Core::X86::Msr::PL0Ssp
  0x000006A5,   // Core::X86::Msr::PL1Ssp
  0x000006A6,   // Core::X86::Msr::PL2Ssp
  0x000006A7,   // Core::X86::Msr::PL3Ssp
  0x000006A8,   // Core::X86::Msr::IstSspAddr
};

/*
MSRs level 30
  - Recommended: Platforms should ensure that SMM does NOT contain any mappings
  to the following Model Specific Registers:
    - INTEL
        - IA32_RTIT_CTL
    - AMD
        - Core::X86::Msr::BT_CTL
        - Core::X86::Msr::DBG_CTL_MSR2
        - Core::X86::Msr::EXCP_BP_CTL
*/
CONST UINT64 SCPC_LVL30_MSR_INTEL[] = {
  0x570     // IA32_RTIT_CTL
};

CONST UINT64 SCPC_LVL30_MSR_AMD[] = {
  0xC0011010,   // Core::X86::Msr::BT_CTL
  0xC0011024,   // Core::X86::Msr::DBG_CTL_MSR2
  0xC0011018,   // Core::X86::Msr::EXCP_BP_CTL
};

typedef struct {
  UINT16  IoPortNumber;
  UINT16  IoWidth;
} IO_ENTRY;

CONST IO_ENTRY  SCPC_LVL20_IO[] = {
  {0xCF8, 4}, // CONFIG_ADDRESS - 4 bytes wide.
  {0xCFC, 4}  // CONFIG_DATA - 4 bytes wide.
};

#define SMM_POLICY_LEVEL_10     10
#define SMM_POLICY_LEVEL_20     20
#define SMM_POLICY_LEVEL_30     30

#define MAX_SUPPORTED_LEVEL     30

#endif // MM_POLICY_MEASUREMENT_LEVELS_H_
