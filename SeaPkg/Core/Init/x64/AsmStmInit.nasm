;------------------------------------------------------------------------------
;
; Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
; This program and the accompanying materials
; are licensed and made available under the terms and conditions of the BSD License
; which accompanies this distribution.  The full text of the license may be found at
; http://opensource.org/licenses/bsd-license.php.
;
; THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
; WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;
; Module Name:
;
;    AsmStmInit.nasm
;
;------------------------------------------------------------------------------

%include "Nasm.inc"

extern ASM_PFX(SeaVmcallDispatcher)

global ASM_PFX(mSerializationLock)
global ASM_PFX(_ModuleEntryPoint)

SEA_API_GET_CAPABILITIES  EQU 00010101h
SEA_API_GET_RESOURCES     EQU 00010102h

STM_STACK_SIZE                EQU 08000h

IA32_APIC_BASE_MSR_INDEX EQU  0x1b
APIC_REGISTER_APICID     EQU  0x20

MAX_PROCESSORS EQU 1024

SECTION .data

mSerializationLock dq 0 ; 0 means lock is free

ScratchSpaceRcx   dq 0 ; Use it as an extra register.
ScratchSpaceRdx   dq 0 ; Use it as an extra register.

;
; assign unique RSP for each processor
;
; |----------------StackTable---------------|
; | 0x0000000000000000 | 0x0000000000000001 |
; | 0x0000000000000044 | 0xFFFFFFFF00000000 |
; | 0xFFFFFFFF00000000 | 0xFFFFFFFF00000000 |
;
; The corresponding RSP for each APIC ID will be
; (index of this ID entry in StackTable) * STM_STACK_SIZE
;
; | Unassigned |
; +------------+
; | Stack      |
; +------------+<-RSP for APIC ID 0x44
; | Stack      |
; +------------+<-RSP for APIC ID 0x1
; | Stack      |
; +------------+<-RSP for APIC ID 0x0
; | Heap       |

StackTable        times MAX_PROCESSORS dq 0xFFFFFFFF00000000 ; Table to track the stack for each processor.
                                                  ; This support up to MAX_PROCESSORS processors.

DEFAULT REL
SECTION .text

%macro ATOMIC_LOCATE_STACK    0
  mov rax, 1
.try_get_lock:
  xchg rax, qword [mSerializationLock]  ; Atomically swap value in rax with lock
  test rax, rax     ; Check if lock was zero
  jnz .try_get_lock             ; If not zero, lock is already held, retry

  ; safe zone, try to locate the stack for this processor
  xchg rdx, qword [ScratchSpaceRdx]
  xchg rcx, qword [ScratchSpaceRcx]

  ; begin with getting the apic id
  mov rcx, IA32_APIC_BASE_MSR_INDEX
  rdmsr
  shl     rdx, 0x20
  or      rax, rdx
  ; see if IA32_APIC_X2_MODE is set
  bt      rax, 10
  jnc     .LNoX2Mode
  ; if set, read apic id from x2apic id MSR
  mov     rcx, 0x802
  rdmsr
  mov     edx, eax
  jmp     .FoundApiId

.LNoX2Mode:
  mov     rcx, 0xFFFFFF000
  and     rax, rcx
  add     rax, APIC_REGISTER_APICID
  ; read apic id from ApicBase + APIC_REGISTER_APICID
  mov     edx, [rax]
  shr     edx, 24

.FoundApiId:
  ; edx = LocalApicId
  mov     rcx, 0xFFFFFFFF
  and     rdx, rcx
  ; now we have the apic id in edx, loop through the stack table to find the stack
  lea rax, [StackTable]
  ; we want to find a match in the apic id, the upper 32 bits are initialized to 0xFFFFFFFF
  .LFindStack:
    ; rcx = StackTable[?].ApicId
    mov rcx, [rax]
    ; rcx == LocalApicId?
    cmp rcx, rdx
    je .LUseThisStack
    ; rcx emtpy?
    cmp ecx, 0
    jne .LNextEntry
    shr rcx, 0x20
    cmp ecx, 0xFFFFFFFF
    je .LPopEmptyEntry

  .LNextEntry:
    add rax, 8
    ; check if rax is out of range
    lea rcx, [StackTable]
    add rcx, MAX_PROCESSORS * 8
    cmp rax, rcx
    jl .LFindStack
    ; no stack found, and out of range. f***, i am dead...
    jmp DeadLoop

  .LPopEmptyEntry:
    mov [rax], rdx

  .LUseThisStack:
    lea rcx, [StackTable]
    sub rcx, rax
    neg rcx
    shr rcx, 3
    ; rax = rsp + STM_STACK_SIZE * rcx
    imul rcx, rcx, STM_STACK_SIZE
    lea rax, [rsp + rcx]
    mov rsp, rax

    ; now restore rcx and rdx, thank you...
    xchg rdx, qword [ScratchSpaceRdx]
    xchg rcx, qword [ScratchSpaceRcx]

  add  rsp, STM_STACK_SIZE                ; Move stack pointer to the bottom of the stack
%endmacro

;------------------------------------------------------------------------------
; VOID
; _ModuleEntryPoint (
;   VOID
;   )
_ModuleEntryPoint:
  cmp eax, SEA_API_GET_CAPABILITIES ; for get capabilities
  jz  GoGetCapabilities
  cmp eax, SEA_API_GET_RESOURCES ; for get resources
  jz  GoGetResources
  jmp DeadLoop

GoGetCapabilities:
  ; try to locate stack before jump to C code
  ATOMIC_LOCATE_STACK
  ;
  ; Jump to C code
  ;
  sub rsp, 512
  fxsave  [rsp]
  push r15
  push r14
  push r13
  push r12
  push r11
  push r10
  push r9
  push r8
  push rdi
  push rsi
  push rbp
  push rsp ; should be rsp
  push rbx
  push rdx
  push rcx
  mov  eax, SEA_API_GET_CAPABILITIES
  push rax
  mov  rcx, rsp ; parameter
  sub  rsp, 20h
  call SeaVmcallDispatcher
  add  rsp, 20h
  ; should never get here
  jmp  DeadLoop

GoGetResources:
  ; try to locate stack before jump to C code
  ATOMIC_LOCATE_STACK
  ;
  ; Jump to C code
  ;
  sub rsp, 512
  fxsave  [rsp]
  push r15
  push r14
  push r13
  push r12
  push r11
  push r10
  push r9
  push r8
  push rdi
  push rsi
  push rbp
  push rsp ; should be rsp
  push rbx
  push rdx
  push rcx
  mov  eax, SEA_API_GET_RESOURCES
  push rax
  mov  rcx, rsp ; parameter
  sub  rsp, 20h
  call SeaVmcallDispatcher
  add  rsp, 20h
  ; should never get here
DeadLoop:
  jmp DeadLoop
