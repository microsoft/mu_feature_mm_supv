/** @file
Agent Module to load other modules to deploy SMM Entry Vector for X86 CPU.

Copyright (c) 2009 - 2023, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _RELOCATE_H_
#define _RELOCATE_H_

#include <PiMm.h>

#include <Protocol/SmmConfiguration.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmReadyToLock.h>
#include <Protocol/SmmCpuService.h>
#include <Protocol/SmmMemoryAttribute.h>
#include <Protocol/MmMp.h>
#include <Protocol/SmmExceptionTestProtocol.h> // MS_CHANGE

#include <Guid/MemoryAttributesTable.h>
#include <Guid/MpInformation.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MemoryTypeInformation.h>
#include <Guid/SmmBaseHob.h>
#include <Guid/MpInformation2.h>

#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/MtrrLib.h>
#include <Library/SmmCpuPlatformHookLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/LocalApicLib.h>
#include <Library/CpuLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/SmmCpuFeaturesLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/RegisterCpuFeaturesLib.h>
#include <Library/PerformanceLib.h>
#include <Library/MmSaveStateLib.h>

#include <AcpiCpuData.h>
#include <CpuHotPlugData.h>

#include <Register/Intel/Cpuid.h>
#include <Register/Intel/Msr.h>
#include <Register/Amd/Msr.h>
#include <Register/Amd/Cpuid.h>

#include "CpuService.h"
#include "SmmProfile.h"
#include "SmmMpPerf.h"

//
// CET definition
//
#define CPUID_CET_SS   BIT7
#define CPUID_CET_IBT  BIT20

#define CR4_CET_ENABLE  BIT23

#define MSR_IA32_S_CET                     0x6A2
#define MSR_IA32_PL0_SSP                   0x6A4
#define MSR_IA32_INTERRUPT_SSP_TABLE_ADDR  0x6A8

typedef union {
  struct {
    // enable shadow stacks
    UINT32    SH_STK_ENP              : 1;
    // enable the WRSS{D,Q}W instructions.
    UINT32    WR_SHSTK_EN             : 1;
    // enable tracking of indirect call/jmp targets to be ENDBRANCH instruction.
    UINT32    ENDBR_EN                : 1;
    // enable legacy compatibility treatment for indirect call/jmp tracking.
    UINT32    LEG_IW_EN               : 1;
    // enable use of no-track prefix on indirect call/jmp.
    UINT32    NO_TRACK_EN             : 1;
    // disable suppression of CET indirect branch tracking on legacy compatibility.
    UINT32    SUPPRESS_DIS            : 1;
    UINT32    RSVD                    : 4;
    // indirect branch tracking is suppressed.
    // This bit can be written to 1 only if TRACKER is written as IDLE.
    UINT32    SUPPRESS                : 1;
    // Value of the endbranch state machine
    // Values: IDLE (0), WAIT_FOR_ENDBRANCH(1).
    UINT32    TRACKER                 : 1;
    // linear address of a bitmap in memory indicating valid
    // pages as target of CALL/JMP_indirect that do not land on ENDBRANCH when CET is enabled
    // and not suppressed. Valid when ENDBR_EN is 1. Must be machine canonical when written on
    // parts that support 64 bit mode. On parts that do not support 64 bit mode, the bits 63:32 are
    // reserved and must be 0. This value is extended by 12 bits at the low end to form the base address
    // (this automatically aligns the address on a 4K Byte boundary).
    UINT32    EB_LEG_BITMAP_BASE_low  : 12;
    UINT32    EB_LEG_BITMAP_BASE_high : 32;
  } Bits;
  UINT64    Uint64;
} MSR_IA32_CET;

//
// MSRs required for configuration of SMM Code Access Check
//
#define EFI_MSR_SMM_MCA_CAP       0x17D
#define  SMM_CODE_ACCESS_CHK_BIT  BIT58

#define  SMM_FEATURE_CONTROL_LOCK_BIT  BIT0
#define  SMM_CODE_CHK_EN_BIT           BIT2

//
// Size of Task-State Segment defined in IA32 Manual
//
#define TSS_SIZE             104
#define EXCEPTION_TSS_SIZE   (TSS_SIZE + 4)  // Add 4 bytes SSP
#define TSS_X64_IST1_OFFSET  36
#define TSS_IA32_CR3_OFFSET  28
#define TSS_IA32_ESP_OFFSET  56
#define TSS_IA32_SSP_OFFSET  104

#define CR0_WP  BIT16

//
// Code select value
//
#define PROTECT_MODE_CODE_SEGMENT  0x08
#define LONG_MODE_CODE_SEGMENT     0x38

#define EXCEPTION_VECTOR_NUMBER  0x20

extern CPU_HOT_PLUG_DATA   mCpuHotPlugData;
extern UINTN               mMaxNumberOfCpus;
extern UINTN               mNumberOfCpus;
extern EFI_MM_MP_PROTOCOL  mSmmMp;
extern UINT32              mSmmCr3;

///
/// The mode of the CPU at the time an SMI occurs
///
extern UINT8  mSmmSaveStateRegisterLma;

extern BOOLEAN  mSmmRebootOnException;                     // MS_CHANGE

//
// SMM CPU Protocol function prototypes.
//

/**
  Read information from the CPU save state.

  @param  This      EFI_SMM_CPU_PROTOCOL instance
  @param  Width     The number of bytes to read from the CPU save state.
  @param  Register  Specifies the CPU register to read form the save state.
  @param  CpuIndex  Specifies the zero-based index of the CPU save state
  @param  Buffer    Upon return, this holds the CPU register value read from the save state.

  @retval EFI_SUCCESS   The register was read from Save State
  @retval EFI_NOT_FOUND The register is not defined for the Save State of Processor
  @retval EFI_INVALID_PARAMETER   This or Buffer is NULL.

**/
EFI_STATUS
EFIAPI
SmmReadSaveState (
  IN CONST EFI_SMM_CPU_PROTOCOL   *This,
  IN UINTN                        Width,
  IN EFI_SMM_SAVE_STATE_REGISTER  Register,
  IN UINTN                        CpuIndex,
  OUT VOID                        *Buffer
  );

/**
  Initialize SMM environment.

**/
VOID
EFIAPI
InitializeSmm (
  VOID
  );

extern volatile  BOOLEAN  *mSmmInitialized;
extern UINT32             mBspApicId;

X86_ASSEMBLY_PATCH_LABEL  mPatchCetSupported;
extern BOOLEAN            mCetSupported;
extern BOOLEAN            m5LevelPagingNeeded;

/**
  Semaphore operation for all processor relocate SMMBase.
**/
VOID
EFIAPI
SmmRelocationSemaphoreComplete (
  VOID
  );

#define SMM_PSD_OFFSET  0xfb00

///
/// All global semaphores' pointer
///
typedef struct {
  volatile BOOLEAN    *InsideSmm;
  volatile BOOLEAN    *AllCpusInSync;
  SPIN_LOCK           *PFLock;
  SPIN_LOCK           *CodeAccessCheckLock;
} SMM_CPU_SEMAPHORE_GLOBAL;

///
/// All semaphores for each processor
///
typedef struct {
  SPIN_LOCK           *Busy;
  volatile BOOLEAN    *Present;
  SPIN_LOCK           *Token;
} SMM_CPU_SEMAPHORE_CPU;

///
/// All semaphores' information
///
typedef struct {
  SMM_CPU_SEMAPHORE_GLOBAL    SemaphoreGlobal;
  SMM_CPU_SEMAPHORE_CPU       SemaphoreCpu;
} SMM_CPU_SEMAPHORES;

extern IA32_DESCRIPTOR       gcSmiGdtr;
extern EFI_PHYSICAL_ADDRESS  mGdtBuffer;
extern UINTN                 mGdtBufferSize;
extern UINTN                 mGdtStepSize;
extern IA32_DESCRIPTOR       gcSmiIdtr;
extern VOID                  *gcSmiIdtrPtr;
extern UINTN                 mSmmStackArrayBase;
extern UINTN                 mSmmStackArrayEnd;
extern UINTN                 mSmmStackSize;
extern UINTN                 mSmmCpl3StackArrayBase;
#if FeaturePcdGet (PcdMmSupervisorTestEnable)
extern UINTN  mSmmCpl3StackArrayEnd;
#endif
extern SMM_CPU_SEMAPHORES    mSmmCpuSemaphores;
extern UINTN                 mSemaphoreSize;
extern SPIN_LOCK             *mPFLock;
extern SPIN_LOCK             *mConfigSmmCodeAccessCheckLock;
extern EFI_SMRAM_DESCRIPTOR  *mSmmCpuSmramRanges;
extern UINTN                 mSmmCpuSmramRangeCount;

/**
  Initialize IDT for SMM Stack Guard.

**/
VOID
EFIAPI
InitializeIDTSmmStackGuard (
  VOID
  );

/**
  Initialize IDT IST Field.

  @param[in]  ExceptionType       Exception type.
  @param[in]  Ist                 IST value.

**/
VOID
EFIAPI
InitializeIdtIst (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  IN UINT8               Ist
  );

/**
  Initialize Gdt for all processors.

  @param[in]   Cr3          CR3 value.
  @param[out]  GdtStepSize  The step size for GDT table.

  @return GdtBase for processor 0.
          GdtBase for processor X is: GdtBase + (GdtStepSize * X)
**/
VOID *
InitGdt (
  IN  UINTN  Cr3,
  OUT UINTN  *GdtStepSize
  );

/**

  Register the SMM Foundation entry point.

  @param          This              Pointer to EFI_SMM_CONFIGURATION_PROTOCOL instance
  @param          SmmEntryPoint     SMM Foundation EntryPoint

  @retval         EFI_SUCCESS       Successfully to register SMM foundation entry point

**/
EFI_STATUS
EFIAPI
RegisterSmmEntry (
  IN CONST EFI_SMM_CONFIGURATION_PROTOCOL  *This,
  IN EFI_SMM_ENTRY_POINT                   SmmEntryPoint
  );

/**
  Create PageTable for SMM use.

  @return     PageTable Address

**/
UINT32
SmmInitPageTable (
  VOID
  );

/**
  Initialize MP synchronization data.

**/
VOID
EFIAPI
InitializeMpSyncData (
  VOID
  );

/**

  Find out SMRAM information including SMRR base and SMRR size.

  @param          SmrrBase          SMRR base
  @param          SmrrSize          SMRR size

**/
VOID
FindSmramInfo (
  OUT UINT32  *SmrrBase,
  OUT UINT32  *SmrrSize
  );

/**
  Page Fault handler for SMM use.

  @param  InterruptType    Defines the type of interrupt or exception that
                           occurred on the processor.This parameter is processor architecture specific.
  @param  SystemContext    A pointer to the processor context when
                           the interrupt occurred on the processor.
**/
VOID
EFIAPI
SmiPFHandler (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  );

/**
  Initialize MSR spin lock by MSR index.

  @param  MsrIndex       MSR index value.

**/
VOID
InitMsrSpinLockByIndex (
  IN UINT32  MsrIndex
  );

/**
Configure SMM Code Access Check feature for all processors.
SMM Feature Control MSR will be locked after configuration.
**/
VOID
ConfigSmmCodeAccessCheck (
  VOID
  );

/**
  Get the size of the SMI Handler in bytes.

  @retval The size, in bytes, of the SMI Handler.

**/
UINTN
EFIAPI
GetSmiHandlerSize (
  VOID
  );

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
  );

/**
  Search module name by input IP address and output it.

  @param CallerIpAddress   Caller instruction pointer.

**/
VOID
DumpModuleInfoByIp (
  IN  UINTN  CallerIpAddress
  );

/**
  Return if the Address is forbidden as SMM communication buffer.

  @param[in] Address the address to be checked

  @return TRUE  The address is forbidden as SMM communication buffer.
  @return FALSE The address is allowed as SMM communication buffer.
**/
BOOLEAN
IsSmmCommBufferForbiddenAddress (
  IN UINT64  Address
  );

/**
  Initialize the shadow stack related data structure.

  @param CpuIndex     The index of CPU.
  @param ShadowStack  The bottom of the shadow stack for this CPU.
**/
VOID
InitShadowStack (
  IN UINTN  CpuIndex,
  IN VOID   *ShadowStack
  );

/**
  This function fixes up the address of the global variable or function
  referred in SmiEntry assembly files to be the absolute address.
**/
VOID
EFIAPI
PiSmmCpuSmiEntryFixupAddress (
  );

/**
  This function reads CR2 register when on-demand paging is enabled
  for 64 bit and no action for 32 bit.

  @param[out]  *Cr2  Pointer to variable to hold CR2 register value.
**/
VOID
SaveCr2 (
  OUT UINTN  *Cr2
  );

/**
  This function writes into CR2 register when on-demand paging is enabled
  for 64 bit and no action for 32 bit.

  @param[in]  Cr2  Value to write into CR2 register.
**/
VOID
RestoreCr2 (
  IN UINTN  Cr2
  );

/**
  Schedule a procedure to run on the specified CPU.

  @param[in]       Procedure                The address of the procedure to run
  @param[in]       CpuIndex                 Target CPU Index
  @param[in,out]   ProcArguments            The parameter to pass to the procedure
  @param[in,out]   Token                    This is an optional parameter that allows the caller to execute the
                                            procedure in a blocking or non-blocking fashion. If it is NULL the
                                            call is blocking, and the call will not return until the AP has
                                            completed the procedure. If the token is not NULL, the call will
                                            return immediately. The caller can check whether the procedure has
                                            completed with CheckOnProcedure or WaitForProcedure.
  @param[in]       TimeoutInMicroseconds    Indicates the time limit in microseconds for the APs to finish
                                            execution of Procedure, either for blocking or non-blocking mode.
                                            Zero means infinity. If the timeout expires before all APs return
                                            from Procedure, then Procedure on the failed APs is terminated. If
                                            the timeout expires in blocking mode, the call returns EFI_TIMEOUT.
                                            If the timeout expires in non-blocking mode, the timeout determined
                                            can be through CheckOnProcedure or WaitForProcedure.
                                            Note that timeout support is optional. Whether an implementation
                                            supports this feature can be determined via the Attributes data
                                            member.
  @param[in,out]   CpuStatus                This optional pointer may be used to get the status code returned
                                            by Procedure when it completes execution on the target AP, or with
                                            EFI_TIMEOUT if the Procedure fails to complete within the optional
                                            timeout. The implementation will update this variable with
                                            EFI_NOT_READY prior to starting Procedure on the target AP.

  @retval EFI_INVALID_PARAMETER    CpuNumber not valid
  @retval EFI_INVALID_PARAMETER    CpuNumber specifying BSP
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber did not enter SMM
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber is busy
  @retval EFI_SUCCESS              The procedure has been successfully scheduled

**/
EFI_STATUS
InternalSmmStartupThisAp (
  IN      EFI_AP_PROCEDURE2  Procedure,
  IN      UINTN              CpuIndex,
  IN OUT  VOID               *ProcArguments OPTIONAL,
  IN OUT  MM_COMPLETION      *Token,
  IN      UINTN              TimeoutInMicroseconds,
  IN OUT  EFI_STATUS         *CpuStatus
  );

/**
  Checks whether the input token is the current used token.

  @param[in]  Token      This parameter describes the token that was passed into DispatchProcedure or
                         BroadcastProcedure.

  @retval TRUE           The input token is the current used token.
  @retval FALSE          The input token is not the current used token.
**/
BOOLEAN
IsTokenInUse (
  IN SPIN_LOCK  *Token
  );

/**
  Checks status of specified AP.

  This function checks whether the specified AP has finished the task assigned
  by StartupThisAP(), and whether timeout expires.

  @param[in]  Token             This parameter describes the token that was passed into DispatchProcedure or
                                BroadcastProcedure.

  @retval EFI_SUCCESS           Specified AP has finished task assigned by StartupThisAPs().
  @retval EFI_NOT_READY         Specified AP has not finished task and timeout has not expired.
**/
EFI_STATUS
IsApReady (
  IN SPIN_LOCK  *Token
  );

/**
  Check whether it is an present AP.

  @param   CpuIndex      The AP index which calls this function.

  @retval  TRUE           It's a present AP.
  @retval  TRUE           This is not an AP or it is not present.

**/
BOOLEAN
IsPresentAp (
  IN UINTN  CpuIndex
  );

/**
  Worker function to execute a caller provided function on all enabled APs.

  @param[in]     Procedure               A pointer to the function to be run on
                                         enabled APs of the system.
  @param[in]     TimeoutInMicroseconds   Indicates the time limit in microseconds for
                                         APs to return from Procedure, either for
                                         blocking or non-blocking mode.
  @param[in,out] ProcedureArguments      The parameter passed into Procedure for
                                         all APs.
  @param[in,out] Token                   This is an optional parameter that allows the caller to execute the
                                         procedure in a blocking or non-blocking fashion. If it is NULL the
                                         call is blocking, and the call will not return until the AP has
                                         completed the procedure. If the token is not NULL, the call will
                                         return immediately. The caller can check whether the procedure has
                                         completed with CheckOnProcedure or WaitForProcedure.
  @param[in,out] CPUStatus               This optional pointer may be used to get the status code returned
                                         by Procedure when it completes execution on the target AP, or with
                                         EFI_TIMEOUT if the Procedure fails to complete within the optional
                                         timeout. The implementation will update this variable with
                                         EFI_NOT_READY prior to starting Procedure on the target AP.

  @retval EFI_SUCCESS             In blocking mode, all APs have finished before
                                  the timeout expired.
  @retval EFI_SUCCESS             In non-blocking mode, function has been dispatched
                                  to all enabled APs.
  @retval others                  Failed to Startup all APs.

**/
EFI_STATUS
InternalSmmStartupAllAPs (
  IN       EFI_AP_PROCEDURE2  Procedure,
  IN       UINTN              TimeoutInMicroseconds,
  IN OUT   VOID               *ProcedureArguments OPTIONAL,
  IN OUT   MM_COMPLETION      *Token,
  IN OUT   EFI_STATUS         *CPUStatus
  );

/**

  Register the SMM Foundation entry point.

  @param[in]      Procedure            A pointer to the code stream to be run on the designated target AP
                                       of the system. Type EFI_AP_PROCEDURE is defined below in Volume 2
                                       with the related definitions of
                                       EFI_MP_SERVICES_PROTOCOL.StartupAllAPs.
                                       If caller may pass a value of NULL to deregister any existing
                                       startup procedure.
  @param[in,out]  ProcedureArguments   Allows the caller to pass a list of parameters to the code that is
                                       run by the AP. It is an optional common mailbox between APs and
                                       the caller to share information

  @retval EFI_SUCCESS                  The Procedure has been set successfully.
  @retval EFI_INVALID_PARAMETER        The Procedure is NULL but ProcedureArguments not NULL.

**/
EFI_STATUS
RegisterStartupProcedure (
  IN     EFI_AP_PROCEDURE  Procedure,
  IN OUT VOID              *ProcedureArguments OPTIONAL
  );

/**
  Return whether access to non-SMRAM is restricted.

  @retval TRUE  Access to non-SMRAM is restricted.
  @retval FALSE Access to non-SMRAM is not restricted.
**/
BOOLEAN
IsRestrictedMemoryAccess (
  VOID
  );

/**
  FlushTlb on current processor.

  @param[in,out] Buffer  Pointer to private data buffer.
**/
VOID
EFIAPI
FlushTlbOnCurrentProcessor (
  IN OUT VOID  *Buffer
  );

/**
  SMM Ready To Lock event notification handler.

  This function collects all SMM image information and build SmiHandleProfile database,
  and register SmiHandlerProfile SMI handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
SmmReadyToLockInSmiHandlerProfile (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  );

/**
  This function is called by SyscallDispatcher to process user request on registering
  a child SMI handler from user space.

  @param SyscallIndex         The syscall index requested by the user. Supervisor uses it
                              to validate internal request state machine.
  @param UserMmCpuProtocol    User MM CPU protocol instance used for basic sanity check.
  @param Arg2                 When the SyscallIndex is SMM_SC_SVST_READ, this argument
                              contains Register to be read. When index is SMM_SC_SVST_READ_2,
                              this argument is width of buffer to be read in bytes.
  @param Arg3                 When the SyscallIndex is SMM_SC_SVST_READ, this is the CpuIndex
                              to be read from save state buffer. When SyscallIndex
                              is SMM_SC_SVST_READ_2, this represents the user buffer to hold
                              return data. Caller should validate the incoming buffer before
                              invoking this interface.

  @retval EFI_SUCCESS           The information is recorded.
  @retval EFI_UNSUPPORTED       This feature is not enabled.
  @retval EFI_INVALID_PARAMETER Unrecognized syscall index is passed in.
  @retval EFI_NOT_STARTED       User handler holder status does not meet expected state.
  @retval Others                Other errors returned from SmiHandlerProfileRegisterHandler.
**/
EFI_STATUS
ProcessUserSaveStateAccess (
  IN UINTN                SyscallIndex,
  IN EFI_MM_CPU_PROTOCOL  *UserMmCpuProtocol,
  IN UINT64               Arg2,
  IN UINT64               Arg3
  );

/**
  Function to perform post relocation logic before handing back to the IPL.

**/
VOID
PostRelocationRun (
  VOID
  );

#endif
