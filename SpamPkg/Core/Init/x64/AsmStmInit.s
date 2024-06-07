#------------------------------------------------------------------------------
#
# Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
# This program and the accompanying materials
# are licensed and made available under the terms and conditions of the BSD License
# which accompanies this distribution.  The full text of the license may be found at
# http://opensource.org/licenses/bsd-license.php.
#
# THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#
# Module Name:
#
#   AsmStmInit.s
#
#------------------------------------------------------------------------------

ASM_GLOBAL ASM_PFX(InitializeSmmMonitor)
ASM_GLOBAL ASM_PFX(_ModuleEntryPoint)

.equ SEA_API_GET_CAPABILITIES,  0x00010101
.equ SEA_API_GET_RESOURCES,     0x00010102

.equ STM_STACK_SIZE,                0x020000

#------------------------------------------------------------------------------
# VOID
# AsmInitializeSmmMonitor (
#   VOID
#   )
ASM_PFX(_ModuleEntryPoint):
  cmpl $SEA_API_GET_CAPABILITIES, %eax # for BSP
  jz  GoCapabilities
  cmpl $SEA_API_GET_RESOURCES, %eax # for AP
  jz  GoResource
  jmp DeadLoop

GoCapabilities:
  # Assume ThisOffset is 0
  # ESP is pointer to stack bottom, NOT top
  movl $STM_STACK_SIZE, %eax     # eax = STM_STACK_SIZE, 
  lock xaddl %eax, (%esp)        # eax = ThisOffset, ThisOffset += STM_STACK_SIZE (LOCK instruction)
  addl $STM_STACK_SIZE, %eax     # eax = ThisOffset + STM_STACK_SIZE
  addl %eax, %esp                # esp += ThisOffset + STM_STACK_SIZE

  #
  # Jump to C code
  #
  push %r15
  push %r14
  push %r13
  push %r12
  push %r11
  push %r10
  push %r9
  push %r8
  push %rdi
  push %rsi
  push %rbp
  push %rbp # should be rsp
  push %rbx
  push %rdx
  push %rcx
  movl $SEA_API_GET_CAPABILITIES, %eax
  push %rax
  movq %rsp, %rcx # parameter
  subq $0x20, %rsp
  call ASM_PFX(InitializeSmmMonitor)
  addq $0x20, %rsp
  # should never get here
  jmp  DeadLoop

GoAp:
  #
  # assign unique ESP for each processor
  #
# |------------|<-ESP (PerProc)
# | Reg        |
# |------------|
# | Stack      |
# |------------|
# | ThisOffset |
# +------------+<-ESP (Common)
# | Heap       |

  # Assume ThisOffset is 0
  # ESP is pointer to stack bottom, NOT top
  movl $STM_STACK_SIZE, %eax      # eax = STM_STACK_SIZE, 
  lock xaddl %eax, (%esp)         # eax = ThisOffset, ThisOffset += STM_STACK_SIZE (LOCK instruction)
  addl $STM_STACK_SIZE, %eax      # eax = ThisOffset + STM_STACK_SIZE
  addl %eax, %esp                 # esp += ThisOffset + STM_STACK_SIZE

  #
  # Jump to C code
  #
  push %r15
  push %r14
  push %r13
  push %r12
  push %r11
  push %r10
  push %r9
  push %r8
  push %rdi
  push %rsi
  push %rbp
  push %rbp # should be rsp
  push %rbx
  push %rdx
  push %rcx
  movl $SEA_API_GET_RESOURCES, %eax
  push %rax
  movq %rsp, %rcx # parameter
  subq $0x20, %rsp
  call ASM_PFX(SeaGetResources)
  addq $0x20, %rsp
  # should never get here
DeadLoop:
  jmp .

