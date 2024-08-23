/** @file
  STM API definition

  Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef STM_API_INTERNAL_H_
#define STM_API_INTERNAL_H_

// definition in STM spec

#define STM_SPEC_VERSION_MAJOR  1
#define STM_SPEC_VERSION_MINOR  0

#pragma pack (push, 1)

typedef struct _STM_SMM_CPU_STATE {
  UINT8     Reserved1[0x1d0];                           // fc00h
  UINT32    GdtBaseHiDword;                             // fdd0h : NO
  UINT32    LdtBaseHiDword;                             // fdd4h : NO
  UINT32    IdtBaseHiDword;                             // fdd8h : NO
  UINT8     Reserved2[0x4];                             // fddch
  UINT64    IoRdi;                                      // fde0h : NO - restricted
  UINT64    IoEip;                                      // fde8h : YES
  UINT64    IoRcx;                                      // fdf0h : NO - restricted
  UINT64    IoRsi;                                      // fdf8h : NO - restricted
  UINT8     Reserved3[0x40];                            // fe00h
  UINT32    Cr4;                                        // fe40h : NO
  UINT8     Reserved4[0x48];                            // fe44h
  UINT32    GdtBaseLoDword;                             // fe8ch : NO
  UINT32    GdtLimit;                                   // fe90h : NO - RESTRICTED
  UINT32    IdtBaseLoDword;                             // fe94h : NO
  UINT32    IdtLimit;                                   // fe98h : NO - RESTRICTED
  UINT32    LdtBaseLoDword;                             // fe9ch : NO
  UINT32    LdtLimit;                                   // fea0h : NO - RESTRICTED
  UINT32    LdtInfo;                                    // fea4h : NO - RESTRICTED
  UINT8     Reserved5[0x30];                            // fea8h
  UINT64    Eptp;                                       // fed8h : NO
  UINT32    EnabledEPT;                                 // fee0h : NO
  UINT8     Reserved6[0x14];                            // fee4h
  UINT32    Smbase;                                     // fef8h : YES - NO for STM
  UINT32    SMMRevId;                                   // fefch : NO
  UINT16    IORestart;                                  // ff00h : YES
  UINT16    AutoHALTRestart;                            // ff02h : YES
  UINT8     Reserved7[0x18];                            // ff04h
  UINT64    R15;                                        // ff1ch : YES
  UINT64    R14;                                        // ff24h : YES
  UINT64    R13;                                        // ff2ch : YES
  UINT64    R12;                                        // ff34h : YES
  UINT64    R11;                                        // ff3ch : YES
  UINT64    R10;                                        // ff44h : YES
  UINT64    R9;                                         // ff4ch : YES
  UINT64    R8;                                         // ff54h : YES
  UINT64    Rax;                                        // ff5ch : YES
  UINT64    Rcx;                                        // ff64h : YES
  UINT64    Rdx;                                        // ff6ch : YES
  UINT64    Rbx;                                        // ff74h : YES
  UINT64    Rsp;                                        // ff7ch : YES
  UINT64    Rbp;                                        // ff84h : YES
  UINT64    Rsi;                                        // ff8ch : YES
  UINT64    Rdi;                                        // ff94h : YES
  UINT64    IOMemAddr;                                  // ff9ch : NO
  UINT32    IOMisc;                                     // ffa4h : NO
  UINT32    Es;                                         // ffa8h : NO
  UINT32    Cs;                                         // ffach : NO
  UINT32    Ss;                                         // ffb0h : NO
  UINT32    Ds;                                         // ffb4h : NO
  UINT32    Fs;                                         // ffb8h : NO
  UINT32    Gs;                                         // ffbch : NO
  UINT32    Ldtr;                                       // ffc0h : NO
  UINT32    Tr;                                         // ffc4h : NO
  UINT64    Dr7;                                        // ffc8h : NO
  UINT64    Dr6;                                        // ffd0h : NO
  UINT64    Rip;                                        // ffd8h : YES
  UINT64    Ia32Efer;                                   // ffe0h : YES - NO for STM
  UINT64    Rflags;                                     // ffe8h : YES
  UINT64    Cr3;                                        // fff0h : NO
  UINT64    Cr0;                                        // fff8h : NO
} STM_SMM_CPU_STATE;

#pragma pack (pop)

#endif // STM_API_INTERNAL_H_
