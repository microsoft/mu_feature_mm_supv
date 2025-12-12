/** @file
SMM profile internal header file.

Copyright (c) 2012 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_PROFILE_INTERNAL_H_
#define _SMM_PROFILE_INTERNAL_H_

#include <Protocol/SmmReadyToLock.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/CpuLib.h>
#include <IndustryStandard/Acpi.h>
#include <Library/MmMemoryProtectionHobLib.h>         // MU_CHANGE

//
// This MACRO just enable unit test for the profile
// Please disable it.
//

#define IA32_PF_EC_US  (1u << 2)
#define IA32_PF_EC_ID  (1u << 4)

//
// CPU generic definition
//
#define   CPUID1_EDX_XD_SUPPORT  0x100000
#define   MSR_EFER               0xc0000080
#define   MSR_EFER_XD            0x800

#define   CPUID1_EDX_BTS_AVAILABLE  0x200000

extern UINTN              gSmiExceptionHandlers[];
extern BOOLEAN            mXdSupported;
X86_ASSEMBLY_PATCH_LABEL  gPatchXdSupported;
X86_ASSEMBLY_PATCH_LABEL  gPatchMsrIa32MiscEnableSupported;

//
// Internal functions
//

/**
  Page Fault handler for SMM use.

**/
VOID
SmiDefaultPFHandler (
  VOID
  );

#endif // _SMM_PROFILE_H_
