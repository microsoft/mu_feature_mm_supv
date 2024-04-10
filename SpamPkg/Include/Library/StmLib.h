/** @file
  STM library header file

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _STM_LIB_H_
#define _STM_LIB_H_

#include "Library/Vmx.h"
#include "Library/Smx.h"

// It must be 64-byte aligned
typedef struct {
  // IA32_FX_BUFFER
  UINT8    Buffer[512];
  // Header
  UINT8    Header[64];
  // Ext_Save_Area_2
  // Ext_Save_Area_3
  // ......
  // Ext_Save_Area_63
} IA32_X_BUFFER;

/**

  This function save XState.

  @param Mask   XState save mask
  @param Buffer XState buffer

**/
VOID
AsmXSave (
  IN  UINT64         Mask,
  OUT IA32_X_BUFFER  *Buffer
  );

/**

  This function restore XState.

  @param Mask   XState restore mask
  @param Buffer XState buffer

**/
VOID
AsmXRestore (
  IN UINT64         Mask,
  IN IA32_X_BUFFER  *Buffer
  );

/**

  This function LOCK test and set bit, and return orginal bit.

  @param BitIndex  Bit index
  @param Address   Bit string address

  @return Original bit value

**/
UINT32
AsmTestAndSet (
  IN UINT32  BitIndex,
  IN VOID    *Address
  );

/**

  This function LOCK test and reset (clear) bit, and return orginal bit.

  @param BitIndex  Bit index
  @param Address   Bit string address

  @return Original bit value

**/
UINT32
AsmTestAndReset (
  IN UINT32  BitIndex,
  IN VOID    *Address
  );

//
// SMX Related Functions
//

/**

  This function read TXT public space.

  @param Offset TXT public space register

  @return TXT public space data

**/
UINT32
TxtPubRead32 (
  IN UINTN  Offset
  );

/**

  This function write TXT public space.

  @param Offset TXT public space register
  @param Data   TXT public space data

**/
VOID
TxtPubWrite32 (
  IN UINTN   Offset,
  IN UINT32  Data
  );

/**

  This function read TXT public space.

  @param Offset TXT public space register

  @return TXT public space data

**/
UINT64
TxtPubRead64 (
  IN UINTN  Offset
  );

/**

  This function write TXT public space.

  @param Offset TXT public space register
  @param Data   TXT public space data

**/
VOID
TxtPubWrite64 (
  IN UINTN   Offset,
  IN UINT64  Data
  );

/**

  This function read TXT private space.

  @param Offset TXT private space register

  @return TXT private space data

**/
UINT32
TxtPriRead32 (
  IN UINTN  Offset
  );

/**

  This function write TXT private space.

  @param Offset TXT private space register
  @param Data   TXT private space data

**/
VOID
TxtPriWrite32 (
  IN UINTN   Offset,
  IN UINT32  Data
  );

/**

  This function read TXT private space.

  @param Offset TXT private space register

  @return TXT private space data

**/
UINT64
TxtPriRead64 (
  IN UINTN  Offset
  );

/**

  This function write TXT private space.

  @param Offset TXT private space register
  @param Data   TXT private space data

**/
VOID
TxtPriWrite64 (
  IN UINTN   Offset,
  IN UINT64  Data
  );

/**

  This function open locality2.

**/
VOID
OpenLocality2 (
  VOID
  );

/**

  This function close locality2.

**/
VOID
CloseLocality2 (
  VOID
  );

/**

  This function open locality1.

**/
VOID
OpenLocality1 (
  VOID
  );

/**

  This function close locality1.

**/
VOID
CloseLocality1 (
  VOID
  );

/**

  This function set secrets.

**/
VOID
SetSecrets (
  VOID
  );

/**

  This function set no-secrets.

**/
VOID
SetNoSecrets (
  VOID
  );

/**

  This function unlock memory configuration.

**/
VOID
UnlockMemConfig (
  VOID
  );

/**

  This function close private.

**/
VOID
ClosePrivate (
  VOID
  );

/**

  This function return TXT heap.

  @return TXT heap

**/
VOID *
GetTxtHeap (
  VOID
  );

/**

  This function return TXT heap size.

  @return TXT heap size

**/
UINTN
GetTxtHeapSize (
  VOID
  );

/**

  This function return TXT BiosToOs region.

  @return TXT BiosToOs region

**/
TXT_BIOS_TO_OS_DATA *
GetTxtBiosToOsData (
  VOID
  );

/**

  This function return TXT OsToMle region.

  @return TXT OsToMle region

**/
VOID *
GetTxtOsToMleData (
  VOID
  );

/**

  This function return TXT OsToSinit region.

  @return TXT OsToSinit region

**/
TXT_OS_TO_SINIT_DATA *
GetTxtOsToSinitData (
  VOID
  );

/**

  This function return TXT SinitToMle region.

  @return TXT SinitToMle region

**/
TXT_SINIT_TO_MLE_DATA *
GetTxtSinitToMleData (
  VOID
  );

/**

  This function return TXT Heap occupied size.

  @return TXT Heap occupied size

**/
UINTN
GetTxtHeapOccupiedSize (
  VOID
  );

//
// VMX Related Functions
//

/**

  This function read UINT16 data from VMCS region.

  @param Index VMCS region index

  @return VMCS region value

**/
UINT16
VmRead16 (
  IN UINT32  Index
  );

/**

  This function read UINT32 data from VMCS region.

  @param Index VMCS region index

  @return VMCS region value

**/
UINT32
VmRead32 (
  IN UINT32  Index
  );

/**

  This function read UINT64 data from VMCS region.

  @param Index VMCS region index

  @return VMCS region value

**/
UINT64
VmRead64 (
  IN UINT32  Index
  );

/**

  This function read UINTN data from VMCS region.

  @param Index VMCS region index

  @return VMCS region value

**/
UINTN
VmReadN (
  IN UINT32  Index
  );

/**

  This function write UINN16 data to VMCS region.

  @param Index VMCS region index
  @param Data  VMCS region value

**/
VOID
VmWrite16 (
  IN UINT32  Index,
  IN UINT16  Data
  );

/**

  This function write UINN32 data to VMCS region.

  @param Index VMCS region index
  @param Data  VMCS region value

**/
VOID
VmWrite32 (
  IN UINT32  Index,
  IN UINT32  Data
  );

/**

  This function write UINN64 data to VMCS region.

  @param Index VMCS region index
  @param Data  VMCS region value

**/
VOID
VmWrite64 (
  IN UINT32  Index,
  IN UINT64  Data
  );

/**

  This function write UINTN data to VMCS region.

  @param Index VMCS region index
  @param Data  VMCS region value

**/
VOID
VmWriteN (
  IN UINT32  Index,
  IN UINTN   Data
  );

/**

  This function enter VMX.

  @param Vmcs  VMCS pointer

  @return RFLAGS if VmxOn fail

**/
UINTN
AsmVmxOn (
  IN UINT64  *Vmcs
  );

/**

  This function leave VMX.

  @return RFLAGS if VmxOff fail

**/
UINTN
AsmVmxOff (
  VOID
  );

/**

  This function clear VMCS.

  @param Vmcs  VMCS pointer

  @return RFLAGS if VmClear fail

**/
UINTN
AsmVmClear (
  IN UINT64  *Vmcs
  );

/**

  This function store VMCS.

  @param Vmcs  VMCS pointer

  @return RFLAGS if VmPtrStore fail

**/
UINTN
AsmVmPtrStore (
  IN UINT64  *Vmcs
  );

/**

  This function load VMCS.

  @param Vmcs  VMCS pointer

  @return RFLAGS if VmPtrLoad fail

**/
UINTN
AsmVmPtrLoad (
  IN UINT64  *Vmcs
  );

/**

  This function launch VM.

  @param Register  General purpose register set

  @return RFLAGS if VmLaunch fail

**/
UINTN
AsmVmLaunch (
  IN X86_REGISTER  *Register
  );

/**

  This function resume to VM.

  @param Register  General purpose register set

  @return RFLAGS if VmResume fail

**/
UINTN
AsmVmResume (
  IN X86_REGISTER  *Register
  );

/**

  This function read VMCS region.

  @param Index VMCS region index
  @param Data  VMCS region value

  @return RFLAGS if VmRead fail

**/
UINTN
AsmVmRead (
  IN UINT32  Index,
  OUT UINTN  *Data
  );

/**

  This function write VMCS region.

  @param Index VMCS region index
  @param Data  VMCS region value

  @return RFLAGS if VmWrite fail

**/
UINTN
AsmVmWrite (
  IN UINT32  Index,
  IN UINTN   Data
  );

typedef struct {
  UINT64    Lo;
  UINT64    Hi;
} UINT_128;

#define  INVEPT_TYPE_SINGLE_CONTEXT_INVALIDATION  1
#define  INVEPT_TYPE_GLOBAL_INVALIDATION          2

/**

  This function invalidate EPT TLB.

  @param Type  INVEPT type
  @param Addr  INVEPT desciptor

  @return RFLAGS if InvEpt fail

**/
UINTN
AsmInvEpt (
  IN UINTN     Type,
  IN UINT_128  *Addr
  );

#define  INVVPID_TYPE_INDIVIDUAL_ADDRESS_INVALIDATION                           1
#define  INVVPID_TYPE_SINGLE_CONTEXT_INVALIDATION                               2
#define  INVVPID_TYPE_ALL_CONTEXTS_INVALIDATION                                 3
#define  INVVPID_TYPE_SINGLE_CONTEXT_INVALIDATION_RETAINING_GLOBAL_TRANSLATION  4

/**

  This function invalidate VPID.

  @param Type  INVVPID type
  @param Addr  INVVPID desciptor

  @return RFLAGS if InvVpid fail

**/
UINTN
AsmInvVpid (
  IN UINTN     Type,
  IN UINT_128  *Addr
  );

/**

  This function invoke VMCALL with context.

  @param Eax   EAX register
  @param Ebx   EBX register
  @param Ecx   ECX register
  @param Edx   EDX register

  @return EAX register

**/
UINT32
AsmVmCall (
  IN UINT32  Eax,
  IN UINT32  Ebx,
  IN UINT32  Ecx,
  IN UINT32  Edx
  );

#endif
