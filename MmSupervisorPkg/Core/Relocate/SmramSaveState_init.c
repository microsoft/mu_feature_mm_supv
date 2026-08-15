/** @file
Init-build specialization for the SMRAM Save State Map services.

Houses Init's variants of GetSmiHandlerSize and InstallSmiHandler plus the
Init-only LookupMmiEntryInFvHobs path and its supporting locals.  The
Core-side equivalents live in SmramSaveState_core.c; truly shared state
lives in SmramSaveState.c.

Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <SmmSecurePolicy.h>
#include <SeaResponder.h>

#include <Library/SmmCpuFeaturesLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/SysCallLib.h>
#include <Library/IhvSmmSaveStateSupervisionLib.h>

#include "Relocate.h"
#include "Mem/Mem.h"
#include "Services/MpService/MpService_init.h"
#include "MmSupervisorCore.h"

UINT8  mSmmSaveStateRegisterLma;

/**
  Get the size of the SMI Handler in bytes.

  @retval The size, in bytes, of the SMI Handler.

**/
UINTN
EFIAPI
GetSmiHandlerSize (
  VOID
  )
{
  UINTN  Size;

  Size = SmmCpuFeaturesGetSmiHandlerSize ();
  if (Size != 0) {
    return Size;
  }

  return 0;
}

/**
  Install the SMI handler for the CPU specified by CpuIndex.  This function
  is called by the CPU that was elected as monarch during System Management
  Mode initialization.

  @param[in] CpuIndex   The index of the CPU to install the custom SMI handler.
                        The value must be between 0 and the NumberOfCpus field
                        in the System Management System Table (SMST).
  @param[in] SmBase     The SMBASE address for the CPU specified by CpuIndex.
  @param[in] SmiStack   The stack to use when an SMI is processed by the
                        the CPU specified by CpuIndex.
  @param[in] StackSize  The size, in bytes, if the stack used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtBase    The base address of the GDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] GdtSize    The size, in bytes, of the GDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtBase    The base address of the IDT to use when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] IdtSize    The size, in bytes, of the IDT used when an SMI is
                        processed by the CPU specified by CpuIndex.
  @param[in] Cr3        The base address of the page tables to use when an SMI
                        is processed by the CPU specified by CpuIndex.
**/
VOID
EFIAPI
InstallSmiHandler (
  IN UINTN   CpuIndex,
  IN UINT32  SmBase,
  IN VOID    *SmiStack,
  IN UINTN   StackSize,
  IN UINTN   GdtBase,
  IN UINTN   GdtSize,
  IN UINTN   IdtBase,
  IN UINTN   IdtSize,
  IN UINT32  Cr3
  )
{
  if (SmmCpuFeaturesGetSmiHandlerSize () != 0) {
    //
    // Install SMI handler provided by library
    //
    SmmCpuFeaturesInstallSmiHandler (
      CpuIndex,
      SmBase,
      SmiStack,
      StackSize,
      GdtBase,
      GdtSize,
      IdtBase,
      IdtSize,
      Cr3
      );
    return;
  }

  PANIC ("InstallSmiHandler: No SMI handler available for this CPU");
}
