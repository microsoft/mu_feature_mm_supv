/** @file
SMM MP service implementation

This file is the shared placeholder for the SMM MP service implementation.
The Core- and Init-build bodies have substantial divergence (different
SMM_CPU_PRIVATE_DATA struct layouts, different MpService.h flavors, and
nine functions that exist only in the Core build), so for now the entire
implementation lives in MpService_core.c and MpService_init.c respectively.

A future slice may dedup the identical helpers between the two files once
the MpService.h header itself has been unified (see Slice 7e).

Copyright (c) 2009 - 2024, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/
