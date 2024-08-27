/** @file
  STM header file

  Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _STM_H_
#define _STM_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/PciLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/DebugLib.h>
#include <Library/StmPlatformLib.h>
#include <Library/StmLib.h>
#include <Library/MemoryAllocationLib.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h>
#include <IndustryStandard/Pci.h>
#include <Protocol/DebugSupport.h>
#include <Register/StmApi.h>
#include <Register/Intel/StmApiInternal.h>
#include "CpuDef.h"

//
// Definition help catch error at build time.
//
#define C_ASSERT(e)  typedef char ___C_ASSERT___[e?1:-1]
// #define SIZE_OF_FIELD(TYPE, Field) (sizeof(((TYPE *)0)->Field))

//
// Below code is from Uefi.h
//

//
// The EFI memory allocation functions work in units of EFI_PAGEs that are
// 4K. This should in no way be confused with the page size of the processor.
// An EFI_PAGE is just the quanta of memory in EFI.
//
#define STM_PAGE_SIZE   0x1000
#define STM_PAGE_MASK   0xFFF
#define STM_PAGE_SHIFT  12

#define STM_SIZE_TO_PAGES(a)  (((a) >> STM_PAGE_SHIFT) + (((a) & STM_PAGE_MASK) ? 1 : 0))

#define STM_PAGES_TO_SIZE(a)  ( (a) << STM_PAGE_SHIFT)

#define PCI_EXPRESS_ADDRESS(Bus, Device, Function, Offset) \
  (((Offset) & 0xfff) | (((Function) & 0x07) << 12) | (((Device) & 0x1f) << 15) | (((Bus) & 0xff) << 20))

#pragma pack (push, 1)

typedef struct {
  UINT64    VmcsPhysPointer; // bits 11:0 are reserved and must be 0
  UINT32    DomainType         : 4;
  UINT32    XStatePolicy       : 2;
  UINT32    DegradationPolicy  : 4;
  UINT32    Reserved1          : 22; // Must be 0
  UINT32    DegradedDomainType : 4;
  UINT32    Reserved2          : 28; // Must be 0
  UINT32    Type;                    // Occupied, Empty, LastOne
} VMCS_RECORD_STRUCTURE;
#define VMCS_RECORD_EMPTY     0
#define VMCS_RECORD_OCCUPIED  1
#define VMCS_RECORD_LAST      0xFFFFFFFF

typedef struct {
  SPIN_LOCK    EventLogLock;
  UINT32       State;                // EvtInvalid/EvtLogStarted/EvtLogStopped
  UINT32       EventEnableBitmap;
  UINT32       EventSerialNumber;
  UINT32       PageCount;
  UINT64       *Pages;
} MLE_EVENT_LOG_STRUCTURE;

typedef struct {
  STM_RSC    *Base;
  UINTN      UsedSize;
  UINTN      Pages;
} MLE_PROTECTED_RESOURCE_STRUCTURE;

#define STM_PERF_DATA_ENTRY_TOKEN_LENGTH_MAX  16

typedef struct {
  UINT64    StartTimeStamp;
  UINT64    EndTimeStamp;
  UINT64    DeltaOfTimeStamp;
  UINT32    CpuIndex;
  UINT32    Reason;
  CHAR8     Token[STM_PERF_DATA_ENTRY_TOKEN_LENGTH_MAX];
  CHAR8     StartDescription[STM_PERF_DATA_ENTRY_TOKEN_LENGTH_MAX];
  CHAR8     EndDescription[STM_PERF_DATA_ENTRY_TOKEN_LENGTH_MAX];
} STM_PERF_DATA_ENTRY;

typedef struct {
  UINT64       Address;
  UINT32       TotalSize;
  UINT32       EntryCount;
  SPIN_LOCK    PerfLock;
} STM_PERF_DATA;

#define MAX_VARIABLE_MTRR_NUMBER  32

typedef struct {
  UINT64    MtrrCap;
  UINT64    MtrrDefType;
  UINT64    FixedMtrr[11];
  UINT64    VariableMtrrBase[MAX_VARIABLE_MTRR_NUMBER];
  UINT64    VariableMtrrMask[MAX_VARIABLE_MTRR_NUMBER];
  UINT64    SmrrBase;
  UINT64    SmrrMask;
} MRTT_INFO;

typedef enum {
  EptPageAttributeSet,
  EptPageAttributeAnd,
  EptPageAttributeOr,
  EptPageAttributeMax
} EPT_PAGE_ATTRIBUTE_SETTING;

// 0x20 entry is enough, because interrupt is always disabled.
#define STM_MAX_IDT_NUM  0x20

#pragma pack (pop)

/**

  This function relocate this STM image.

  @param IsTeardown  If the relocation is for teardown.
                     FALSE means relocation for setup.
                     TRUE  means relocation for teardown.

**/
VOID
RelocateStmImage (
  IN BOOLEAN  IsTeardown
  );

/**

  This function return local APIC ID.

  @return Local APIC ID

**/
UINT32
ReadLocalApicId (
  VOID
  );

/**

  This function return if it is BSP.

  @retval TRUE  It is BSP
  @retval FALSE It is AP

**/
BOOLEAN
IsBsp (
  VOID
  );

/**

  This function return if processor support XState.

  @retval TRUE XState is supported
  @retval FALSE XState is supported

**/
BOOLEAN
IsXStateSupported (
  VOID
  );

/**
  This function retrieves the attributes of the memory region specified by
  BaseAddress and Length. If different attributes are got from different part
  of the memory region, EFI_NO_MAPPING will be returned.

  @param  PageTableBase     The base address of the page table.
  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        Pointer to attributes returned.

  @retval EFI_SUCCESS           The attributes got for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes is NULL.
                                Length is larger than MAX_INT64. // MU_CHANGE: Avoid Length overflow for INT64
  @retval EFI_NO_MAPPING        Attributes are not consistent cross the memory
                                region.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
SmmGetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  PageTableBase,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  OUT UINT64                *Attributes
  );

/**

  Initialize external vector table pointer.

  @param IdtGate  IDT gate descriptor

**/
VOID
InitializeExternalVectorTablePtr (
  IN IA32_IDT_GATE_DESCRIPTOR  *IdtGate
  );

/**

  This function return 4K page aligned VMCS size.

  @return 4K page aligned VMCS size

**/
UINT32
GetVmcsSize (
  VOID
  );

/**

  This function return if Senter executed.

  @retval TRUE  Senter executed
  @retval FALSE Sexit not executed

**/
BOOLEAN
IsSentryEnabled (
  VOID
  );

/**
  Creates a record for the beginning of a performance measurement.

  Creates a record that contains the CpuIndex and Token.
  This function reads the current time stamp and adds that time stamp value to the record as the start time.

  @param  CpuIndex                Index of CPU.
  @param  Reason                  Reason of this measurement.
  @param  Token                   Pointer to a Null-terminated ASCII string
                                  that identifies the component being measured.
  @param  Description             Pointer to a Null-terminated ASCII string
                                  that describe this measurement.

  @retval RETURN_SUCCESS          The start of the measurement was recorded.
  @retval RETURN_OUT_OF_RESOURCES There are not enough resources to record the measurement.

**/
RETURN_STATUS
EFIAPI
StmStartPerformanceMeasurement (
  IN UINT32       CpuIndex,
  IN UINT32       Reason,
  IN CONST CHAR8  *Token,
  IN CONST CHAR8  *Description OPTIONAL
  );

/**
  Fills in the end time of a performance measurement.

  Looks up the last record that matches CpuIndex and Token.
  If the record can not be found then return RETURN_NOT_FOUND.
  If the record is found then TimeStamp is added to the record as the end time.
  If this function is called multiple times for the same record, then the end time is overwritten.

  @param  CpuIndex                Index of CPU.
  @param  Token                   Pointer to a Null-terminated ASCII string
                                  that identifies the component being measured.
  @param  Description             Pointer to a Null-terminated ASCII string
                                  that describe this measurement.

  @retval RETURN_SUCCESS          The end of  the measurement was recorded.
  @retval RETURN_NOT_FOUND        The specified measurement record could not be found.

**/
RETURN_STATUS
EFIAPI
StmEndPerformanceMeasurement (
  IN UINT32       CpuIndex,
  IN CONST CHAR8  *Token,
  IN CONST CHAR8  *Description OPTIONAL
  );

/**
  Returns TRUE if the performance measurement macros are enabled.

  This function returns TRUE if the PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of
  PcdPerformanceLibraryPropertyMask is set.  Otherwise FALSE is returned.

  @retval TRUE                    The PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of
                                  PcdPerformanceLibraryPropertyMask is set.
  @retval FALSE                   The PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of
                                  PcdPerformanceLibraryPropertyMask is clear.

**/
BOOLEAN
EFIAPI
StmPerformanceMeasurementEnabled (
  VOID
  );

/**
  Initialize STM performance measurement.

  @retval RETURN_SUCCESS          Initialize measurement successfully.
  @retval RETURN_OUT_OF_RESOURCES  No enough resource to hold STM PERF data.

**/
RETURN_STATUS
EFIAPI
StmInitPerformanceMeasurement (
  VOID
  );

/**
  Dump STM performance measurement.

  @retval RETURN_SUCCESS          Dump measurement successfully.
  @retval RETURN_NOT_FOUND        No STM PERF data.

**/
RETURN_STATUS
EFIAPI
StmDumpPerformanceMeasurement (
  VOID
  );

/**
  Macro that calls StmDumpPerformanceMeasurement().

  If the PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of PcdPerformanceLibraryPropertyMask is set,
  then StmDumpPerformanceMeasurement() is called.

**/
#define STM_PERF_DUMP                                  \
  do {                                                 \
    if (StmPerformanceMeasurementEnabled ()) {         \
      StmDumpPerformanceMeasurement ();                \
    }                                                  \
  } while (FALSE)

/**
  Macro that calls StmInitPerformanceMeasurement().

  If the PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of PcdPerformanceLibraryPropertyMask is set,
  then StmInitPerformanceMeasurement() is called.

**/
#define STM_PERF_INIT                                  \
  do {                                                 \
    if (StmPerformanceMeasurementEnabled ()) {         \
      StmInitPerformanceMeasurement ();                \
    }                                                  \
  } while (FALSE)

/**
  Macro that calls EndPerformanceMeasurement().

  If the PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of PcdPerformanceLibraryPropertyMask is set,
  then EndPerformanceMeasurement() is called.

**/
#define STM_PERF_END(CpuIndex, Name, Description)                   \
  do {                                                              \
    if (StmPerformanceMeasurementEnabled ()) {                      \
      StmEndPerformanceMeasurement (CpuIndex, Name, Description);   \
    }                                                               \
  } while (FALSE)

/**
  Macro that calls StartPerformanceMeasurement().

  If the PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED bit of PcdPerformanceLibraryPropertyMask is set,
  then StartPerformanceMeasurement() is called.

**/
#define STM_PERF_START(CpuIndex, Reason, Name, Description)                 \
  do {                                                                      \
    if (StmPerformanceMeasurementEnabled ()) {                              \
      StmStartPerformanceMeasurement (CpuIndex, Reason, Name, Description); \
    }                                                                       \
  } while (FALSE)

#define STM_DATA_OFFSET  0x1000
#define STM_GDT_OFFSET   STM_DATA_OFFSET
#define STM_CODE_OFFSET  STM_DATA_OFFSET + 0x1000

#define SMM_TXTPSD_OFFSET     0xfb00
#define SMM_CPU_STATE_OFFSET  0xfc00

// __declspec (align(0x10))
typedef struct _SEA_GUEST_CONTEXT_PER_CPU {
  X86_REGISTER             Register;
  IA32_DESCRIPTOR          Gdtr;
  IA32_DESCRIPTOR          Idtr;
  UINTN                    Cr0;
  UINTN                    Cr3;
  UINTN                    Cr4;
  UINTN                    Stack;
  UINT64                   Efer;
  BOOLEAN                  UnrestrictedGuest;
  UINTN                    XStateBuffer;

  // For CPU support Save State in MSR, we need a place holder to save it in memory in advanced.
  // The reason is that when we switch to SMM guest, we lose the context in SMI guest.
  STM_SMM_CPU_STATE        *SmmCpuState;

  VM_EXIT_INFO_BASIC       InfoBasic;            // hold info since we need that when return to SMI guest.
  VM_EXIT_QUALIFICATION    Qualification;        // hold info since we need that when return to SMI guest.
  UINT32                   VmExitInstructionLength;
  BOOLEAN                  Launched;
  BOOLEAN                  Active;               // For SMM VMCS only, controlled by StartStmVMCALL
  UINT64                   Vmcs;
  UINT32                   GuestMsrEntryCount;
  UINT64                   GuestMsrEntryAddress;

 #if defined (MDE_CPU_X64)
  // Need check alignment here because we need use FXSAVE/FXRESTORE buffer
  UINT32                   Reserved;
 #endif
} SEA_GUEST_CONTEXT_PER_CPU;

#if defined (MDE_CPU_X64)
// Need check alignment here because we need use FXSAVE/FXRESTORE buffer
C_ASSERT ((sizeof (SEA_GUEST_CONTEXT_PER_CPU) & 0xF) == 0);
#endif

typedef struct _SEA_GUEST_CONTEXT_COMMON {
  EPT_POINTER                  EptPointer;
  UINTN                        CompatiblePageTable;
  UINTN                        CompatiblePaePageTable;
  UINT64                       MsrBitmap;
  UINT64                       IoBitmapA;
  UINT64                       IoBitmapB;
  UINT32                       Vmid;
  UINTN                        ZeroXStateBuffer;
  //
  // BiosHwResourceRequirementsPtr: This is back up of BIOS resource - no ResourceListContinuation
  //
  UINT64                       BiosHwResourceRequirementsPtr;
  SEA_GUEST_CONTEXT_PER_CPU    *GuestContextPerCpu;
} SEA_GUEST_CONTEXT_COMMON;

typedef struct _SEA_HOST_CONTEXT_PER_CPU {
  UINT32                          Index;
  UINT32                          ApicId;
  UINTN                           Stack;
  UINT32                          Smbase;
  TXT_PROCESSOR_SMM_DESCRIPTOR    *TxtProcessorSmmDescriptor;
  UINT32                          HostMsrEntryCount;
  UINT64                          HostMsrEntryAddress;

  // JumpBuffer for Setup/TearDown
  BOOLEAN                         JumpBufferValid;
  BASE_LIBRARY_JUMP_BUFFER        JumpBuffer;
} SEA_HOST_CONTEXT_PER_CPU;

typedef struct _SEA_HOST_CONTEXT_COMMON {
  SPIN_LOCK                           DebugLock;
  SPIN_LOCK                           MemoryLock;
  SPIN_LOCK                           SmiVmcallLock;
  SPIN_LOCK                           ResponderLock;
  UINT32                              CpuNum;
  UINT32                              JoinedCpuNum;
  UINTN                               PageTable;
  IA32_DESCRIPTOR                     Gdtr;
  IA32_DESCRIPTOR                     Idtr;
  UINT64                              HeapBottom;
  UINT64                              HeapTop;
  UINT8                               PhysicalAddressBits;
  UINT64                              MaximumSupportAddress;
  UINT32                              TotalNumberProcessors;
  STM_HEADER                          *StmHeader;
  UINTN                               StmSize;
  UINT64                              TsegBase;
  UINT64                              TsegLength;

  UINT64                              AcpiRsdp;

  //
  // Log
  //
  MLE_EVENT_LOG_STRUCTURE             EventLog;

  //
  // ProtectedResource: This is back up of MLE resource - no ResourceListContinuation
  //
  MLE_PROTECTED_RESOURCE_STRUCTURE    MleProtectedResource;
  //
  // ProtectedTrappedIoResource: This is cache for TrappedIoResource in MLE resource
  // For performance consideration only, because TrappedIoResource will be referred in each SMI.
  //
  MLE_PROTECTED_RESOURCE_STRUCTURE    MleProtectedTrappedIoResource;

  //
  // TrustedRegionResource: This is MLE trusted region resource - no ResourceListContinuation
  // TrustedRegionResource will be referred in software SMI only.
  //
  MLE_PROTECTED_RESOURCE_STRUCTURE    MleTrustedRegionResource;

  //
  // Performance measurement
  //
  STM_PERF_DATA                       PerfData;

  SEA_HOST_CONTEXT_PER_CPU            *HostContextPerCpu;
} SEA_HOST_CONTEXT_COMMON;

extern SEA_HOST_CONTEXT_COMMON   mHostContextCommon;
extern SEA_GUEST_CONTEXT_COMMON  mGuestContextCommonNormal;

/**

  This function return XState size.

  @return XState size

**/
UINTN
CalculateXStateSize (
  VOID
  );

#endif
