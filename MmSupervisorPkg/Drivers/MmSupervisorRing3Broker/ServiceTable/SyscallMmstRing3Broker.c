/** @file

  Copyright (c), Microsoft Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Pi/PiMmCis.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/SysCallLib.h>

#include "MmSupervisorRing3Broker.h"

// TODO:
// // MP service
// .CpuSaveStateSize = NULL,                           // CpuSaveStateSize
// .CpuSaveState = NULL,                               // CpuSaveState
// .NumberOfTableEntries = 0,                          // NumberOfTableEntries
// .MmConfigurationTable = NULL,                       // MmConfigurationTable

// TODO: Support the input argument better
// TODO: Support pointer, by verifying user is not tampering supervisor region

EFI_STATUS
EFIAPI
SyscallMmInstallConfigurationTable (
  IN  CONST EFI_MM_SYSTEM_TABLE  *SystemTable,
  IN  CONST EFI_GUID             *Guid,
  IN  VOID                       *Table,
  IN  UINTN                      TableSize
  )
{
  SysCall (SMM_INST_CONF_T, (UINTN)Guid, (UINTN)Table, TableSize);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SyscallMmAllocatePages (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory
  )
{
  EFI_STATUS  Status;

  if (Memory == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  *Memory = SysCall (SMM_ALOC_PAGE, (UINTN)Type, (UINTN)MemoryType, NumberOfPages);
  if (*Memory == 0) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Status = EFI_SUCCESS;

Done:
  return Status;
}

EFI_STATUS
EFIAPI
SyscallMmFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages
  )
{
  SysCall (SMM_FREE_PAGE, (UINTN)Memory, NumberOfPages, 0);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SyscallMmStartupThisAp (
  IN EFI_AP_PROCEDURE  Procedure,
  IN UINTN             CpuNumber,
  IN OUT VOID          *ProcArguments OPTIONAL
  )
{
  SysCall (SMM_START_AP_PROC, (UINTN)Procedure, (UINTN)CpuNumber, (UINTN)ProcArguments);

  return EFI_SUCCESS;
}

// TODO: Hold off this one for now
// EFI_STATUS
// EFIAPI
// SyscallMmiManage (
//   IN CONST EFI_GUID  *HandlerType,
//   IN CONST VOID      *Context         OPTIONAL,
//   IN OUT VOID        *CommBuffer      OPTIONAL,
//   IN OUT UINTN       *CommBufferSize  OPTIONAL
//   );

EFI_STATUS
EFIAPI
SyscallMmiHandlerRegister (
  IN  EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN  CONST EFI_GUID              *HandlerType OPTIONAL,
  OUT EFI_HANDLE                  *DispatchHandle
  )
{
  EFI_STATUS  Status;

  if (DispatchHandle == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  *DispatchHandle = (EFI_HANDLE)SysCall (SMM_REG_HNDL, (UINTN)Handler, (UINTN)HandlerType, 0);
  Status          = EFI_SUCCESS;

Done:
  return Status;
}

EFI_STATUS
EFIAPI
SyscallMmiHandlerUnRegister (
  IN EFI_HANDLE  DispatchHandle
  )
{
  SysCall (SMM_UNREG_HNDL, (UINTN)DispatchHandle, 0, 0);

  return EFI_SUCCESS;
}
