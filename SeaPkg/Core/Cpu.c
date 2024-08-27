/** @file
  STM library CPU function

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Stm.h"

#define IA32_EXT_XAPIC_BASE_MSR_INDEX  0x800
#define APIC_DEST_FIELD                (0 << 18)
#define APIC_ALL_EXCLUDING_SELF        (3 << 18)
#define APIC_SIPI                      (6 << 8)
#define APIC_INIT                      (5 << 8)
#define APIC_LEVEL_ASSERT              (1 << 14)
#define APIC_LEVEL_DEASSERT            (0 << 14)
#define APIC_BASE_ADDR_MASK            0xFFFFFF000
#define APIC_REGISTER_ICR_LOW_OFFSET   0x300
#define APIC_REGISTER_ICR_HIGH_OFFSET  0x310
#define APIC_REGISTER_APICID           0x20

/**

  This function return local APIC ID.

  @return Local APIC ID

**/
UINT32
ReadLocalApicId (
  VOID
  )
{
  UINT32  ApicId;
  UINT64  ApicBase;

  ApicBase = AsmReadMsr64 (IA32_APIC_BASE_MSR_INDEX);

  if ((ApicBase & IA32_APIC_X2_MODE) != 0) {
    return (UINT32)AsmReadMsr64 (IA32_EXT_XAPIC_BASE_MSR_INDEX + (APIC_REGISTER_APICID >> 4));
  } else {
    ApicBase = ApicBase & 0xFFFFFF000ull;
    ApicId   = MmioRead32 ((UINTN)ApicBase + APIC_REGISTER_APICID);
    return (UINT32)(ApicId >> 24);
  }
}

/**

  This function return if it is BSP.

  @retval TRUE  It is BSP
  @retval FALSE It is AP

**/
BOOLEAN
IsBsp (
  VOID
  )
{
  if (AsmReadMsr64 (IA32_APIC_BASE_MSR_INDEX) & IA32_APIC_BSP) {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**

  This function return if processor support XState.

  @retval TRUE XState is supported
  @retval FALSE XState is supported

**/
BOOLEAN
IsXStateSupported (
  VOID
  )
{
  UINT32  Eax;
  UINT32  Ebx;
  UINT32  Ecx;
  UINT32  Edx;

  AsmCpuid (
    CPUID_FEATURE_INFORMATION,
    &Eax,
    &Ebx,
    &Ecx,
    &Edx
    );
  if ((Ecx & BIT26) == 0) {
    return FALSE;
  } else {
    return TRUE;
  }
}

/**
  This function return XState size.
  @return XState size
**/
UINTN
CalculateXStateSize (
  VOID
  )
{
  UINT32  Eax;
  UINT32  Ebx;
  UINT32  Ecx;
  UINT32  Edx;

  if (!IsXStateSupported ()) {
    // It is FxState size
    return 512;
  }

  AsmCpuidEx (
    CPUID_PROCESSOR_EXTENDED_STATE_EMULATION,
    0x0,
    &Eax,
    &Ebx,
    &Ecx,
    &Edx
    );

  //
  // ECX: Maximum size (bytes) of the XSAVE/XRSTOR save area
  //      required by all supported features in the processor, i.e all the valid bit
  //      fields in XFEATURE_ENABLED_MASK. This includes the size needed for
  //      the XSAVE.HEADER.
  // We need 512 FPU/SSE SaveArea, for whole region.
  //
  return Ecx + sizeof (IA32_FX_BUFFER);
}
