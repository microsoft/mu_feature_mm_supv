/** @file
Provides services to access SMRAM Save State Map

This file holds only state shared between the Core and Init builds of the
SMRAM Save State logic.  The Core- and Init-specific bodies live in
SmramSaveState_core.c and SmramSaveState_init.c respectively.

Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>

///
/// The mode of the CPU at the time an SMI occurs.  This global is referenced
/// by SetupSmiEntryExit (in Relocate_core.c / Relocate_init.c) and by
/// MpService.c in both builds; it is defined here so a single storage instance
/// is linked into both DLLs.
///
UINT8  mSmmSaveStateRegisterLma;
