/** @file
  Null instance of the SMRR Library

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi/UefiBaseType.h>

/**
  Disable SMRRs.

**/
VOID
EFIAPI
SmrrLibSmrrDisable (
  VOID
  )
{
  return;
}

/**
  Reenable SMRRs.

**/
VOID
EFIAPI
SmrrLibSmrrReenable (
  VOID
  )
{
  return;
}

/**
  SMRR configuration entry point for each CPU on SMM rendezvous.

  @param[in] CpuIndex  The index of the CPU that has entered SMM.  The value
                       must be between 0 and the NumberOfCpus field in the
                       System Management System Table (SMST).
**/
VOID
EFIAPI
SmrrLibRendezvousEntry (
  IN UINTN  CpuIndex
  )
{
  return;
}

/**
  Called by the monarch CPU after all CPUs have processed their first SMI and relocated
  SMBASE into a buffer in SMRAM.

**/
VOID
EFIAPI
SmrrLibInitAfterRelocation (
  VOID
  )
{
  return;
}

/**
  Called during the very first SMI to initialize SMRR configuration.

  @param[in]    SmrrBase   The base address of SMRR.
  @param[in]    SmrrSize   The size of SMRR.
  @param[in]    IsMonarch  TRUE if this CPU is the monarch.

**/
VOID
EFIAPI
SmrrLibInitializeOnFirstSmi (
  IN UINT32   SmrrBase,
  IN UINT32   SmrrSize,
  IN BOOLEAN  IsMonarch
  )
{
  return;
}

/**
  Called before the first SMI to initialize SMRR configuration.

**/
VOID
EFIAPI
SmrrLibInitialization (
  VOID
  )
{
  return;
}
