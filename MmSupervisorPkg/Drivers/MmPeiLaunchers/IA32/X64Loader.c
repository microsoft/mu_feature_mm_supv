/** @file
  The X64 entrypoint is used to process MM core in long mode.

Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>

#include <Ppi/LoadFile.h>
#include <Guid/CapsuleVendor.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PerformanceLib.h> // MU_CHANGE: MM_SUPV: Added performance data points

#include "Common/CommonHeader.h"
#include "IA32/X64Loader.h"

// Reused this data structure locally
typedef EFI_CAPSULE_LONG_MODE_BUFFER EFI_MM_IPL_LONG_MODE_BUFFER;

//
// Global Descriptor Table (GDT)
//
GLOBAL_REMOVE_IF_UNREFERENCED IA32_SEGMENT_DESCRIPTOR  mGdtEntries[] = {
  /* selector { Global Segment Descriptor                              } */
  /* 0x00 */ {
    { 0,      0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0, 0 }
  },                                                                      // null descriptor
  /* 0x08 */ {
    { 0xffff, 0, 0, 0x3, 1, 0, 1, 0xf, 0, 0, 1, 1, 0 }
  },                                                                      // linear data segment descriptor
  /* 0x10 */ {
    { 0xffff, 0, 0, 0xf, 1, 0, 1, 0xf, 0, 0, 1, 1, 0 }
  },                                                                      // linear code segment descriptor
  /* 0x18 */ {
    { 0xffff, 0, 0, 0x3, 1, 0, 1, 0xf, 0, 0, 1, 1, 0 }
  },                                                                      // system data segment descriptor
  /* 0x20 */ {
    { 0xffff, 0, 0, 0xb, 1, 0, 1, 0xf, 0, 0, 1, 1, 0 }
  },                                                                      // system code segment descriptor
  /* 0x28 */ {
    { 0,      0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0, 0 }
  },                                                                      // spare segment descriptor
  /* 0x30 */ {
    { 0xffff, 0, 0, 0x3, 1, 0, 1, 0xf, 0, 0, 1, 1, 0 }
  },                                                                      // system data segment descriptor
  /* 0x38 */ {
    { 0xffff, 0, 0, 0xb, 1, 0, 1, 0xf, 0, 1, 0, 1, 0 }
  },                                                                      // system code segment descriptor
  /* 0x40 */ {
    { 0,      0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0, 0 }
  },                                                                      // spare segment descriptor
};

//
// IA32 Gdt register
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST IA32_DESCRIPTOR  mGdt = {
  sizeof (mGdtEntries) - 1,
  (UINTN)mGdtEntries
};

/**
  The function will check if 1G page is supported.

  @retval TRUE   1G page is supported.
  @retval FALSE  1G page is not supported.

**/
BOOLEAN
IsPage1GSupport (
  VOID
  )
{
  UINT32   RegEax;
  UINT32   RegEdx;
  BOOLEAN  Page1GSupport;

  Page1GSupport = FALSE;
  if (PcdGetBool (PcdUse1GPageTable)) {
    AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
    if (RegEax >= 0x80000001) {
      AsmCpuid (0x80000001, NULL, NULL, NULL, &RegEdx);
      if ((RegEdx & BIT26) != 0) {
        Page1GSupport = TRUE;
      }
    }
  }

  return Page1GSupport;
}

/**
  Calculate the total size of page table.

  @param[in] Page1GSupport      1G page support or not.

  @return The size of page table.

**/
UINTN
CalculatePageTableSize (
  IN BOOLEAN  Page1GSupport
  )
{
  UINTN   ExtraPageTablePages;
  UINTN   TotalPagesNum;
  UINT8   PhysicalAddressBits;
  UINT32  NumberOfPml4EntriesNeeded;
  UINT32  NumberOfPdpEntriesNeeded;

  //
  // Create 4G page table by default,
  // and let PF handler to handle > 4G request.
  //
  PhysicalAddressBits = 32;
  ExtraPageTablePages = EXTRA_PAGE_TABLE_PAGES;

  //
  // Calculate the table entries needed.
  //
  if (PhysicalAddressBits <= 39 ) {
    NumberOfPml4EntriesNeeded = 1;
    NumberOfPdpEntriesNeeded  = (UINT32)LShiftU64 (1, (PhysicalAddressBits - 30));
  } else {
    NumberOfPml4EntriesNeeded = (UINT32)LShiftU64 (1, (PhysicalAddressBits - 39));
    NumberOfPdpEntriesNeeded  = 512;
  }

  if (!Page1GSupport) {
    TotalPagesNum = (NumberOfPdpEntriesNeeded + 1) * NumberOfPml4EntriesNeeded + 1;
  } else {
    TotalPagesNum = NumberOfPml4EntriesNeeded + 1;
  }

  TotalPagesNum += ExtraPageTablePages;

  return EFI_PAGES_TO_SIZE (TotalPagesNum);
}

/**
  Allocates and fills in the Page Directory and Page Table Entries to
  establish a 4G page table.

  @param[in] PageTablesAddress  The base address of page table.
  @param[in] Page1GSupport      1G page support or not.

**/
VOID
Create4GPageTables (
  IN EFI_PHYSICAL_ADDRESS  PageTablesAddress,
  IN BOOLEAN               Page1GSupport
  )
{
  UINT8                           PhysicalAddressBits;
  EFI_PHYSICAL_ADDRESS            PageAddress;
  UINTN                           IndexOfPml4Entries;
  UINTN                           IndexOfPdpEntries;
  UINTN                           IndexOfPageDirectoryEntries;
  UINT32                          NumberOfPml4EntriesNeeded;
  UINT32                          NumberOfPdpEntriesNeeded;
  PAGE_MAP_AND_DIRECTORY_POINTER  *PageMapLevel4Entry;
  PAGE_MAP_AND_DIRECTORY_POINTER  *PageMap;
  PAGE_MAP_AND_DIRECTORY_POINTER  *PageDirectoryPointerEntry;
  PAGE_TABLE_ENTRY                *PageDirectoryEntry;
  UINTN                           BigPageAddress;
  PAGE_TABLE_1G_ENTRY             *PageDirectory1GEntry;
  UINT64                          AddressEncMask;

  //
  // Make sure AddressEncMask is contained to smallest supported address field.
  //
  AddressEncMask = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask) & PAGING_1G_ADDRESS_MASK_64;

  //
  // Create 4G page table by default,
  // and let PF handler to handle > 4G request.
  //
  PhysicalAddressBits = 32;

  //
  // Calculate the table entries needed.
  //
  if (PhysicalAddressBits <= 39 ) {
    NumberOfPml4EntriesNeeded = 1;
    NumberOfPdpEntriesNeeded  = (UINT32)LShiftU64 (1, (PhysicalAddressBits - 30));
  } else {
    NumberOfPml4EntriesNeeded = (UINT32)LShiftU64 (1, (PhysicalAddressBits - 39));
    NumberOfPdpEntriesNeeded  = 512;
  }

  //
  // Pre-allocate big pages to avoid later allocations.
  //
  BigPageAddress = (UINTN)PageTablesAddress;

  //
  // By architecture only one PageMapLevel4 exists - so lets allocate storage for it.
  //
  PageMap         = (VOID *)BigPageAddress;
  BigPageAddress += SIZE_4KB;

  PageMapLevel4Entry = PageMap;
  PageAddress        = 0;
  for (IndexOfPml4Entries = 0; IndexOfPml4Entries < NumberOfPml4EntriesNeeded; IndexOfPml4Entries++, PageMapLevel4Entry++) {
    //
    // Each PML4 entry points to a page of Page Directory Pointer entires.
    // So lets allocate space for them and fill them in in the IndexOfPdpEntries loop.
    //
    PageDirectoryPointerEntry = (VOID *)BigPageAddress;
    BigPageAddress           += SIZE_4KB;

    //
    // Make a PML4 Entry
    //
    PageMapLevel4Entry->Uint64         = (UINT64)(UINTN)PageDirectoryPointerEntry | AddressEncMask;
    PageMapLevel4Entry->Bits.ReadWrite = 1;
    PageMapLevel4Entry->Bits.Present   = 1;

    if (Page1GSupport) {
      PageDirectory1GEntry = (VOID *)PageDirectoryPointerEntry;

      for (IndexOfPageDirectoryEntries = 0; IndexOfPageDirectoryEntries < 512; IndexOfPageDirectoryEntries++, PageDirectory1GEntry++, PageAddress += SIZE_1GB) {
        //
        // Fill in the Page Directory entries
        //
        PageDirectory1GEntry->Uint64         = (UINT64)PageAddress | AddressEncMask;
        PageDirectory1GEntry->Bits.ReadWrite = 1;
        PageDirectory1GEntry->Bits.Present   = 1;
        PageDirectory1GEntry->Bits.MustBe1   = 1;
      }
    } else {
      for (IndexOfPdpEntries = 0; IndexOfPdpEntries < NumberOfPdpEntriesNeeded; IndexOfPdpEntries++, PageDirectoryPointerEntry++) {
        //
        // Each Directory Pointer entries points to a page of Page Directory entires.
        // So allocate space for them and fill them in in the IndexOfPageDirectoryEntries loop.
        //
        PageDirectoryEntry = (VOID *)BigPageAddress;
        BigPageAddress    += SIZE_4KB;

        //
        // Fill in a Page Directory Pointer Entries
        //
        PageDirectoryPointerEntry->Uint64         = (UINT64)(UINTN)PageDirectoryEntry | AddressEncMask;
        PageDirectoryPointerEntry->Bits.ReadWrite = 1;
        PageDirectoryPointerEntry->Bits.Present   = 1;

        for (IndexOfPageDirectoryEntries = 0; IndexOfPageDirectoryEntries < 512; IndexOfPageDirectoryEntries++, PageDirectoryEntry++, PageAddress += SIZE_2MB) {
          //
          // Fill in the Page Directory entries
          //
          PageDirectoryEntry->Uint64         = (UINT64)PageAddress | AddressEncMask;
          PageDirectoryEntry->Bits.ReadWrite = 1;
          PageDirectoryEntry->Bits.Present   = 1;
          PageDirectoryEntry->Bits.MustBe1   = 1;
        }
      }

      for ( ; IndexOfPdpEntries < 512; IndexOfPdpEntries++, PageDirectoryPointerEntry++) {
        ZeroMem (
          PageDirectoryPointerEntry,
          sizeof (PAGE_MAP_AND_DIRECTORY_POINTER)
          );
      }
    }
  }

  //
  // For the PML4 entries we are not using fill in a null entry.
  //
  for ( ; IndexOfPml4Entries < 512; IndexOfPml4Entries++, PageMapLevel4Entry++) {
    ZeroMem (
      PageMapLevel4Entry,
      sizeof (PAGE_MAP_AND_DIRECTORY_POINTER)
      );
  }
}

/**
  Return function from long mode to 32-bit mode.

  @param  EntrypointContext  Context for mode switching
  @param  ReturnContext      Context for mode switching

**/
VOID
ReturnFunction (
  SWITCH_32_TO_64_CONTEXT  *EntrypointContext,
  SWITCH_64_TO_32_CONTEXT  *ReturnContext
  )
{
  // MU_CHANGE: Save and Restore more Control Registers and interrupt states
  //
  // Restore original CR3
  //
  AsmWriteCr3 (ReturnContext->ReturnCr3);

  //
  // Restore original CR4
  //
  AsmWriteCr4 (ReturnContext->ReturnCr4);

  //
  // Restore original CR0
  //
  AsmWriteCr0 (ReturnContext->ReturnCr0);

  //
  // Restore original GDT
  //
  AsmWriteGdtr (&ReturnContext->Gdtr);

  //
  // Restore original Interrupt State
  //
  SetInterruptState ((BOOLEAN)ReturnContext->InterruptState);

  //
  // return to original caller
  //
  LongJump ((BASE_LIBRARY_JUMP_BUFFER  *)(UINTN)EntrypointContext->JumpBuffer, 1);

  //
  // never be here
  //
  ASSERT (FALSE);
}

/**
  Thunk function from 32-bit protection mode to long mode.

  @param  PageTableAddress  Page table base address
  @param  Context           Context for mode switching
  @param  ReturnContext     Context for mode switching

  @retval EFI_SUCCESS  Function successfully executed.

**/
EFI_STATUS
Thunk32To64 (
  EFI_PHYSICAL_ADDRESS     PageTableAddress,
  SWITCH_32_TO_64_CONTEXT  *Context,
  SWITCH_64_TO_32_CONTEXT  *ReturnContext
  )
{
  UINTN       SetJumpFlag;
  EFI_STATUS  Status;

  //
  // Save return address, LongJump will return here then
  //
  SetJumpFlag = SetJump ((BASE_LIBRARY_JUMP_BUFFER  *)(UINTN)Context->JumpBuffer);

  if (SetJumpFlag == 0) {
    //
    // Build 4G Page Tables.
    //
    Create4GPageTables (PageTableAddress, Context->Page1GSupport);

    //
    // Create 64-bit GDT
    //
    AsmWriteGdtr (&mGdt);

    //
    // Disable paging
    //
    AsmWriteCr0 (ReturnContext->ReturnCr0 & (~BIT31));

    //
    // Write CR3
    //
    AsmWriteCr3 ((UINTN)PageTableAddress);

    DEBUG ((
      DEBUG_INFO,
      "%a() Stack Base: 0x%lx, Stack Size: 0x%lx\n",
      __FUNCTION__,
      Context->StackBufferBase,
      Context->StackBufferLength
      ));

    //
    // Transfer to long mode
    //
    AsmEnablePaging64 (
      0x38,
      (UINT64)Context->EntryPoint,
      (UINT64)(UINTN)Context,
      (UINT64)(UINTN)ReturnContext,
      Context->StackBufferBase + Context->StackBufferLength
      );
  }

  //
  // Convert to 32-bit Status and return
  //
  Status = EFI_SUCCESS;
  if ((UINTN)ReturnContext->ReturnStatus != 0) {
    Status = ENCODE_ERROR ((UINTN)ReturnContext->ReturnStatus);
  }

  return Status;
}

/**
  If in 32 bit protection mode, and relay image is of X64, switch to long mode.

  @param  LongModeBuffer            The context of long mode.
  @param  RelayEntry                Entry of relay image.

  @retval EFI_SUCCESS               Successfully switched to long mode and execute relay.
  @retval Others                    Failed to execute relay in long mode.

**/
EFI_STATUS
ModeSwitch (
  IN EFI_MM_IPL_LONG_MODE_BUFFER  *LongModeBuffer,
  IN RELAY_ENTRY                  RelayEntry,
  IN EFI_PHYSICAL_ADDRESS         MmCoreEntryPointAddr,
  IN EFI_PHYSICAL_ADDRESS         HobStartAddr
  )
{
  EFI_STATUS                Status;
  SWITCH_32_TO_64_CONTEXT   Context;
  SWITCH_64_TO_32_CONTEXT   ReturnContext;
  BASE_LIBRARY_JUMP_BUFFER  JumpBuffer;
  EFI_PHYSICAL_ADDRESS      ReservedRangeBase;
  EFI_PHYSICAL_ADDRESS      ReservedRangeEnd;
  BOOLEAN                   Page1GSupport;
  UINTN                     TotalPageTableSize;

  ZeroMem (&Context, sizeof (SWITCH_32_TO_64_CONTEXT));
  ZeroMem (&ReturnContext, sizeof (SWITCH_64_TO_32_CONTEXT));

  Page1GSupport      = IsPage1GSupport ();
  TotalPageTableSize = CalculatePageTableSize (Page1GSupport);

  //
  // Merge memory range reserved for stack and page table
  //
  if (LongModeBuffer->StackBaseAddress < LongModeBuffer->PageTableAddress) {
    ReservedRangeBase = LongModeBuffer->StackBaseAddress;
    ReservedRangeEnd  = LongModeBuffer->PageTableAddress + TotalPageTableSize;
  } else {
    ReservedRangeBase = LongModeBuffer->PageTableAddress;
    ReservedRangeEnd  = LongModeBuffer->StackBaseAddress + LongModeBuffer->StackSize;
  }

  // MU_CHANGE: Updated routine to validate parameters applicable to MM PEI IPL
  //
  // Check if memory range reserved is overlap with MM Core and Hob data.
  //
  if ((ReservedRangeBase <= MmCoreEntryPointAddr) && (ReservedRangeEnd > MmCoreEntryPointAddr)) {
    DEBUG ((DEBUG_ERROR, "Memory of MM core overlaps with reserved memory!\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  if ((ReservedRangeBase <= HobStartAddr) && (ReservedRangeEnd > HobStartAddr)) {
    DEBUG ((DEBUG_ERROR, "Memory of Hobs overlap with reserved memory!\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Initialize context jumping to 64-bit environment
  //
  Context.JumpBuffer           = (EFI_PHYSICAL_ADDRESS)(UINTN)&JumpBuffer;
  Context.StackBufferBase      = LongModeBuffer->StackBaseAddress;
  Context.StackBufferLength    = LongModeBuffer->StackSize;
  Context.EntryPoint           = (EFI_PHYSICAL_ADDRESS)(UINTN)RelayEntry;
  Context.MmCoreEntryPointAddr = MmCoreEntryPointAddr;
  Context.HobStartAddr         = HobStartAddr;
  Context.Page1GSupport        = Page1GSupport;
  Context.AddressEncMask       = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask) & PAGING_1G_ADDRESS_MASK_64;

  //
  // Prepare data for return back
  //
  ReturnContext.ReturnCs         = 0x10;
  ReturnContext.ReturnEntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)ReturnFunction;
  //
  // Will save the return status returned by MM core.
  //
  ReturnContext.ReturnStatus = 0;

  //
  // Save original GDT
  //
  AsmReadGdtr ((IA32_DESCRIPTOR *)&ReturnContext.Gdtr);

  // MU_CHANGE: Saves more contexts for later restore. This is especially needed when
  // current environment already had paging enabled.
  //
  // Save original CR3
  //
  ReturnContext.ReturnCr3 = AsmReadCr3 ();

  //
  // Save original CR0
  //
  ReturnContext.ReturnCr0 = AsmReadCr0 ();

  //
  // Save original CR4
  //
  ReturnContext.ReturnCr4 = AsmReadCr4 ();

  //
  // Save original Interrupt State
  //
  ReturnContext.InterruptState = GetInterruptState ();

  Status = Thunk32To64 (LongModeBuffer->PageTableAddress, &Context, &ReturnContext);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Executing MM foundation has failed - %r!\n", __FUNCTION__, Status));
  }

  // MU_CHANGE: These ranges are zeroed and freed after usage
  //
  // For what is worth, clear the stack and page table we have just been through
  //
  ZeroMem ((VOID *)(UINTN)LongModeBuffer->StackBaseAddress, (UINTN)LongModeBuffer->StackSize);
  FreePages ((VOID *)(UINTN)LongModeBuffer->StackBaseAddress, (UINTN)EFI_SIZE_TO_PAGES (LongModeBuffer->StackSize));

  ZeroMem ((VOID *)(UINTN)LongModeBuffer->PageTableAddress, TotalPageTableSize);
  FreeAlignedPages ((VOID *)(UINTN)LongModeBuffer->PageTableAddress, EFI_SIZE_TO_PAGES (TotalPageTableSize));

  return Status;
}

/**
  Locates the relay image entry point, and detects its machine type.

  @param RelayImageEntryPoint      Pointer to relay image entry point for output.
  @param RelayImageMachineType     Pointer to machine type of relay image.

  @retval EFI_SUCCESS     Relay image successfully located.
  @retval Others          Failed to locate the relay image.

**/
EFI_STATUS
FindMmIplX64RelayImage (
  OUT EFI_PHYSICAL_ADDRESS  *RelayImageEntryPoint,
  OUT UINT16                *RelayImageMachineType
  )
{
  EFI_STATUS             Status;
  UINTN                  Instance;
  EFI_PEI_LOAD_FILE_PPI  *LoadFile;
  EFI_PEI_FV_HANDLE      VolumeHandle;
  EFI_PEI_FILE_HANDLE    FileHandle;
  EFI_PHYSICAL_ADDRESS   RelayImageAddress;
  UINT64                 RelayImageSize;
  UINT32                 AuthenticationState;

  Instance = 0;

  while (TRUE) {
    Status = PeiServicesFfsFindNextVolume (Instance++, &VolumeHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = PeiServicesFfsFindFileByName (PcdGetPtr (PcdMmIplX64RelayFile), VolumeHandle, &FileHandle);
    if (!EFI_ERROR (Status)) {
      Status = PeiServicesLocatePpi (&gEfiPeiLoadFilePpiGuid, 0, NULL, (VOID **)&LoadFile);
      ASSERT_EFI_ERROR (Status);

      Status = LoadFile->LoadFile (
                           LoadFile,
                           FileHandle,
                           &RelayImageAddress,
                           &RelayImageSize,
                           RelayImageEntryPoint,
                           &AuthenticationState
                           );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "Unable to find PE32 section in MmIplRelayX64 image ffs %r!\n", Status));
        return Status;
      }

      *RelayImageMachineType = PeCoffLoaderGetMachineType ((VOID *)(UINTN)RelayImageAddress);
      break;
    } else {
      continue;
    }
  }

  return Status;
}

/**
  Gets the reserved long mode buffer.

  @param  LongModeBuffer  Pointer to the long mode buffer for output.

  @retval EFI_SUCCESS     Long mode buffer successfully retrieved.
  @retval Others          Variable storing long mode buffer not found.

**/
EFI_STATUS
GetLongModeContext (
  OUT EFI_MM_IPL_LONG_MODE_BUFFER  *LongModeBuffer
  )
{
  UINTN  TotalPageTableSize;
  UINTN  TotalPagesNum;

  if (LongModeBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // MU_CHANGE: Allocate needed stack and page table buffer here
  TotalPageTableSize = CalculatePageTableSize (IsPage1GSupport ());
  TotalPagesNum      = EFI_SIZE_TO_PAGES (TotalPageTableSize);
  DEBUG ((DEBUG_INFO, "%a TotalPagesNum - 0x%x pages\n", __FUNCTION__, TotalPagesNum));

  LongModeBuffer->PageTableAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocateAlignedReservedPages (TotalPagesNum, EFI_PAGE_SIZE);
  if (NULL == (VOID *)(UINTN)LongModeBuffer->PageTableAddress) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem ((VOID *)(UINTN)LongModeBuffer->PageTableAddress, TotalPageTableSize);

  //
  // Allocate stack
  //
  LongModeBuffer->StackSize        = PcdGet32 (PcdPeiMmInitLongModeStackSize);
  LongModeBuffer->StackBaseAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocateReservedPages (EFI_SIZE_TO_PAGES (PcdGet32 (PcdPeiMmInitLongModeStackSize)));
  if (NULL == (VOID *)(UINTN)LongModeBuffer->StackBaseAddress) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem ((VOID *)(UINTN)LongModeBuffer->StackBaseAddress, (UINTN)LongModeBuffer->StackSize);

  return EFI_SUCCESS;
}

/**
  Locates the X64Relay image entry point, and execute it in long mode.

  @param[in]  MmEntryPoint    Pointer to MM core image entrypoint.
  @param[in]  HobStart        Pointer to the start of HOBs in non-MM environment.

  @retval EFI_SUCCESS     MM foundation is set successfully.
  @retval EFI_NOT_FOUND   Failed to locate the X64Relay image.
  @retval Others          Other failures returned from MM Core or during long mode bootstrap.

 **/
EFI_STATUS
SetMmFoundationInX64Relay (
  IN  STANDALONE_MM_FOUNDATION_ENTRY_POINT  MmEntryPoint,
  IN  VOID                                  *HobStart
  )
{
  EFI_STATUS                   Status;
  UINT16                       RelayImageMachineType;
  EFI_PHYSICAL_ADDRESS         RelayImageEntryPoint;
  RELAY_ENTRY                  RelayEntry;
  EFI_MM_IPL_LONG_MODE_BUFFER  LongModeBuffer;

  if (FeaturePcdGet (PcdDxeIplSwitchToLongMode)) {
    //
    // This section is in large from CapsulePei module
    // Switch to 64-bit mode to process MM foundation when:
    // 1. When DXE phase is 64-bit
    // 2. When the buffer for 64-bit transition exists
    // 3. When Pei MM IPL X64 Relay image is built in BIOS image
    //
    DEBUG ((DEBUG_INFO, "%a Need to do mode switch!\n", __FUNCTION__));
    Status = GetLongModeContext (&LongModeBuffer);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Fail to find the variable for long mode context!\n"));
      goto Exit;
    }

    DEBUG ((DEBUG_INFO, "%a Find the X64 relay driver from available FVs!\n", __FUNCTION__));
    // MU_CHANGE: MM_SUPV: Added performance data points for looking up IPL relay module
    PERF_INMODULE_BEGIN ("Locate X64 relay module");
    Status = FindMmIplX64RelayImage (&RelayImageEntryPoint, &RelayImageMachineType);
    PERF_INMODULE_END ("Locate X64 relay module");
    if ((EFI_ERROR (Status)) || (RelayImageMachineType != EFI_IMAGE_MACHINE_X64)) {
      DEBUG ((DEBUG_ERROR, "Fail to find MmIplPeiX64 module in FV!\n"));
      Status = EFI_NOT_FOUND;
      goto Exit;
    }

    if (RelayImageEntryPoint == 0) {
      DEBUG ((DEBUG_ERROR, "Did not find any X64 relay driver!\n"));
      Status = EFI_NOT_FOUND;
      goto Exit;
    }

    DEBUG ((DEBUG_INFO, "%a About to do mode switching!\n", __FUNCTION__));
    RelayEntry = (RELAY_ENTRY)(UINTN)RelayImageEntryPoint;
    // MU_CHANGE: MM_SUPV: Added performance data points for initializing MM core
    PERF_INMODULE_BEGIN ("Switch to X64 to initialize MM foundation");
    Status = ModeSwitch (
               &LongModeBuffer,
               RelayEntry,
               (EFI_PHYSICAL_ADDRESS)(UINTN)MmEntryPoint,
               (EFI_PHYSICAL_ADDRESS)(UINTN)HobStart
               );
    PERF_INMODULE_END ("Switch to X64 to initialize MM foundation");
  } else {
    //
    // MM foundation is processed in IA32 mode, not supported
    //
    DEBUG ((DEBUG_ERROR, "%a PcdDxeIplSwitchToLongMode is FALSE, system should not need to switch mode (X64) to launch MM!\n", __FUNCTION__));
    ASSERT (FALSE);
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

Exit:
  return Status;
}
