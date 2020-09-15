/** @file
  Provides function interface to perform syscall.

Copyright (C) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SYS_CALL_LIB__
#define __SYS_CALL_LIB__

#define CPL_BITMASK           (BIT1 | BIT0)
#define SYSCALL_REQUIRED_CPL  3

// ======================================================================================
//
// Define syscall method
//
// ======================================================================================
///
/// To keep the enum value consistant, please explicitly specify the value for each enum item;
/// if you add/remove/update any enum item, please also add/remove/update related information in SyscallIdNamePairs array
///
typedef enum {
  SMM_SC_RDMSR      = 0x0000,
  SMM_SC_WRMSR      = 0x0001,
  SMM_SC_CLI        = 0x0002,
  SMM_SC_IO_READ    = 0x0003,
  SMM_SC_IO_WRITE   = 0x0004,
  SMM_SC_WBINVD     = 0x0005,
  SMM_SC_HLT        = 0x0006,
  SMM_SC_SVST_READ  = 0x0007,
  SMM_SC_PROC_READ  = 0x0008,
  SMM_SC_PROC_WRITE = 0x0009,
  SMM_SC_LEGACY_MAX = 0xFFFF,
  // Below is for new supervisor interfaces only,
  // legacy supervisor should not write below this line
  SMM_REG_HDL_JMP     = 0x10000,
  SMM_INST_CONF_T     = 0x10001,
  SMM_ALOC_POOL       = 0x10002,
  SMM_FREE_POOL       = 0x10003,
  SMM_ALOC_PAGE       = 0x10004,
  SMM_FREE_PAGE       = 0x10005,
  SMM_START_AP_PROC   = 0x10006,
  SMM_REG_HNDL        = 0x10007,
  SMM_UNREG_HNDL      = 0x10018,
  SMM_SET_CPL3_TBL    = 0x10019,
  SMM_INST_PROT       = 0x1001A,
  SMM_QRY_HOB         = 0x1001B,
  SMM_ERR_RPT_JMP     = 0x1001C,
  SMM_MM_HDL_REG_1    = 0x1001D,
  SMM_MM_HDL_REG_2    = 0x1001E,
  SMM_MM_HDL_UNREG_1  = 0x1001F,
  SMM_MM_HDL_UNREG_2  = 0x10020,
  SMM_SC_SVST_READ_2  = 0x10021,
  SMM_MM_UNBLOCKED    = 0x10022,
  SMM_MM_IS_COMM_BUFF = 0x10023,
} SMM_SYS_CALL;

UINT64
EFIAPI
SysCall (
  UINTN  CallIndex,
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3
  );

/**
 Check if high privilege instruction need go through Syscall


 @param  NONE

 @return TRUE  Syscall required
 @return FALSE Syscall not required

**/
BOOLEAN
NeedSysCall (
  VOID
  );

#endif // !defined (__SYS_CALL_LIB__)
