/** @file
  This library abstracts SMRR configuration in SMM.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SMRR_LIB_H_
#define SMRR_LIB_H_

/**
  Disable SMRRs.

**/
VOID
EFIAPI
SmmrLibSmmrDisable (
  VOID
  );

/**
  Reenable SMRRs.

**/
VOID
EFIAPI
SmmrLibSmmrReenable (
  VOID
  );

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
  );

/**
  Called by the monarch CPU after all CPUs have processed their first SMI and relocated
  SMBASE into a buffer in SMRAM.

**/
VOID
EFIAPI
SmrrLibInitAfterRelocation (
  VOID
  );

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
  );

/**
  Called before the first SMI to initialize SMRR configuration.

**/
VOID
EFIAPI
SmrrLibInitialization (
  VOID
  );

#endif
