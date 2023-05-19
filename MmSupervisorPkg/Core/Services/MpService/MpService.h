/** @file
SMM MP service implementation

Copyright (c) 2009 - 2022, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_CORE_MP_H_
#define _MM_CORE_MP_H_

#include <Protocol/MpService.h>
#include <Protocol/SmmConfiguration.h>

#include <Library/SynchronizationLib.h>

#define INVALID_APIC_ID  0xFFFFFFFFFFFFFFFFULL

//
// Wrapper used to convert EFI_AP_PROCEDURE2 and EFI_AP_PROCEDURE.
//
typedef struct {
  EFI_AP_PROCEDURE    Procedure;
  VOID                *ProcedureArgument;
  UINTN               CpuIndex;
} PROCEDURE_WRAPPER;

#define PROCEDURE_TOKEN_SIGNATURE  SIGNATURE_32 ('P', 'R', 'T', 'S')

typedef struct {
  UINTN              Signature;
  LIST_ENTRY         Link;

  SPIN_LOCK          *SpinLock;
  volatile UINT32    RunningApCount;
} PROCEDURE_TOKEN;

#define PROCEDURE_TOKEN_FROM_LINK(a)  CR (a, PROCEDURE_TOKEN, Link, PROCEDURE_TOKEN_SIGNATURE)

//
// Private structure for the SMM CPU module that is stored in DXE Runtime memory
// Contains the SMM Configuration Protocols that is produced.
// Contains a mix of DXE and SMM contents.  All the fields must be used properly.
//
#define SMM_CPU_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('s', 'c', 'p', 'u')

typedef struct {
  UINTN                             Signature;

  EFI_HANDLE                        SmmCpuHandle;

  EFI_PROCESSOR_INFORMATION         *ProcessorInfo;
  SMM_CPU_OPERATION                 *Operation;
  UINTN                             *CpuSaveStateSize;
  VOID                              **CpuSaveState;

  EFI_SMM_RESERVED_SMRAM_REGION     SmmReservedSmramRegion[1];
  EFI_SMM_ENTRY_CONTEXT             SmmCoreEntryContext;
  EFI_SMM_ENTRY_POINT               SmmCoreEntry;

  EFI_SMM_CONFIGURATION_PROTOCOL    SmmConfiguration;

  PROCEDURE_WRAPPER                 *ApWrapperFunc;
  LIST_ENTRY                        TokenList;
  LIST_ENTRY                        *FirstFreeToken;
} SMM_CPU_PRIVATE_DATA;

extern SMM_CPU_PRIVATE_DATA  *gSmmCpuPrivate;

///
/// The type of SMM CPU Information
///
typedef struct {
  SPIN_LOCK                     *Busy;
  volatile EFI_AP_PROCEDURE2    Procedure;
  volatile VOID                 *Parameter;
  volatile UINT32               *Run;
  volatile BOOLEAN              *Present;
  PROCEDURE_TOKEN               *Token;
  EFI_STATUS                    *Status;
} SMM_CPU_DATA_BLOCK;

typedef enum {
  SmmCpuSyncModeTradition,
  SmmCpuSyncModeRelaxedAp,
  SmmCpuSyncModeMax
} SMM_CPU_SYNC_MODE;

typedef struct {
  //
  // Pointer to an array. The array should be located immediately after this structure
  // so that UC cache-ability can be set together.
  //
  SMM_CPU_DATA_BLOCK            *CpuData;
  volatile UINT32               *Counter;
  volatile UINT32               BspIndex;
  volatile BOOLEAN              *InsideSmm;
  volatile BOOLEAN              *AllCpusInSync;
  volatile SMM_CPU_SYNC_MODE    EffectiveSyncMode;
  volatile BOOLEAN              SwitchBsp;
  volatile BOOLEAN              *CandidateBsp;
  volatile BOOLEAN              AllApArrivedWithException;
  EFI_AP_PROCEDURE              StartupProcedure;
  VOID                          *StartupProcArgs;
} SMM_DISPATCHER_MP_SYNC_DATA;

extern SMM_DISPATCHER_MP_SYNC_DATA  *mSmmMpSyncData;
extern UINT64                       gPhyMask;

/**
  Schedule a procedure to run on the specified CPU.

  @param   Procedure        The address of the procedure to run
  @param   CpuIndex         Target CPU number
  @param   ProcArguments    The parameter to pass to the procedure

  @retval   EFI_INVALID_PARAMETER    CpuNumber not valid
  @retval   EFI_INVALID_PARAMETER    CpuNumber specifying BSP
  @retval   EFI_INVALID_PARAMETER    The AP specified by CpuNumber did not enter SMM
  @retval   EFI_INVALID_PARAMETER    The AP specified by CpuNumber is busy
  @retval   EFI_SUCCESS - The procedure has been successfully scheduled

**/
EFI_STATUS
EFIAPI
SmmStartupThisAp (
  IN      EFI_AP_PROCEDURE  Procedure,
  IN      UINTN             CpuIndex,
  IN OUT  VOID              *ProcArguments OPTIONAL
  );

/**
  Schedule a procedure to run on the specified CPU in a blocking fashion.

  @param  Procedure                The address of the procedure to run
  @param  CpuIndex                 Target CPU Index
  @param  ProcArguments            The parameter to pass to the procedure

  @retval EFI_INVALID_PARAMETER    CpuNumber not valid
  @retval EFI_INVALID_PARAMETER    CpuNumber specifying BSP
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber did not enter SMM
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber is busy
  @retval EFI_SUCCESS              The procedure has been successfully scheduled

**/
EFI_STATUS
EFIAPI
SmmBlockingStartupThisAp (
  IN      EFI_AP_PROCEDURE  Procedure,
  IN      UINTN             CpuIndex,
  IN OUT  VOID              *ProcArguments OPTIONAL
  );

/**
  Create 4G PageTable in SMRAM.

  @param[in]      Is32BitPageTable Whether the page table is 32-bit PAE
  @return         PageTable Address

**/
UINT32
Gen4GPageTable (
  IN      BOOLEAN  Is32BitPageTable
  );

/**
  Initialize global data for MP synchronization.

  @param Stacks             Base address of SMI stack buffer for all processors.
  @param StackSize          Stack size for each processor in SMM.
  @param ShadowStackSize    Shadow Stack size for each processor in SMM.

**/
UINT32
InitializeMpServiceData (
  IN VOID   *Stacks,
  IN UINTN  StackSize,
  IN UINTN  ShadowStackSize
  );

/**
  Initialize Timer for SMM AP Sync.

**/
VOID
InitializeSmmTimer (
  VOID
  );

/**
  Start Timer for SMM AP Sync.

**/
UINT64
EFIAPI
StartSyncTimer (
  VOID
  );

/**
  Check if the SMM AP Sync timer is timeout.

  @param Timer  The start timer from the begin.

**/
BOOLEAN
EFIAPI
IsSyncTimerTimeout (
  IN      UINT64  Timer
  );

/**
  Initialize PackageBsp Info. Processor specified by mPackageFirstThreadIndex[PackageIndex]
  will do the package-scope register programming. Set default CpuIndex to (UINT32)-1, which
  means not specified yet.

**/
VOID
InitPackageFirstThreadIndexInfo (
  VOID
  );

/**
  Allocate buffer for SpinLock and Wrapper function buffer.

**/
VOID
InitializeDataForMmMp (
  VOID
  );

/**
  Insure when this function returns, no AP will execute normal mode code before entering SMM, except SMI disabled APs.
**/
VOID
SmmWaitForApArrival (
  VOID
  );

#endif //_MM_CORE_MP_H_
