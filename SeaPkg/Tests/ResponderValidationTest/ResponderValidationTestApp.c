/** @file -- MmPagingAuditApp.c
This user-facing application collects information from the SMM page tables and
writes it to files.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <SeaResponder.h>
#include <SmmSecurePolicy.h>
#include <Register/StmApi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/StmLib.h>

#define GET_MEMORY_MAP_RETRIES  1000

// STATIC EFI_EVENT  mExitBootServicesEvent       = NULL;
EFI_HANDLE        gTestImageHandle = NULL;
VOID              *TestVmxOnBuffer = NULL;
VOID              *TestVmcsBuffer = NULL;
VOID              *TestCommBuffer = NULL;

/**

  This function return 4K page aligned VMCS size.

  @return 4K page aligned VMCS size

**/
UINT32
GetVmcsSize (
  VOID
  )
{
  UINT64  Data64;
  UINT32  VmcsSize;

  Data64   = AsmReadMsr64 (IA32_VMX_BASIC_MSR_INDEX);
  VmcsSize = (UINT32)(RShiftU64 (Data64, 32) & 0xFFFF);
  VmcsSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (VmcsSize));

  return VmcsSize;
}

/**
  This helper function actually sends the requested communication
  to the SMM driver.

  @retval     EFI_SUCCESS                  Communication was successful.
  @retval     EFI_ABORTED                  Some error occurred.
  @retval     EFI_BUFFER_TOO_SMALL         Buffer size smaller than minimal requirement.

**/
STATIC
VOID
EFIAPI
InvokeVmcalls (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  IA32_CR4 Cr4;
  UINT64  u64;
  UINT32 Ret;
  VM_EXIT_CONTROLS    VmExitCtrls;
  VM_ENTRY_CONTROLS   VmEntryCtrls;
  IA32_VMX_BASIC_MSR  VmxBasicMsr;

  Print (L"%a - Enable VMX...\n", __func__);
  Cr4.UintN = AsmReadCr4 ();
  Cr4.Bits.VMXE = TRUE;
  AsmWriteCr4 (Cr4.UintN);
  Print (L"%a - VMX enabled!\n", __func__);

  VmxBasicMsr.Uint64 = AsmReadMsr64 (IA32_VMX_BASIC_MSR_INDEX);
  Print (L"%a - IA32_VMX_BASIC_MSR = 0x%lx\n", __func__, VmxBasicMsr.Uint64);

  ZeroMem (TestVmxOnBuffer, EFI_PAGES_TO_SIZE (4));
  *(UINT32*)TestVmxOnBuffer = VmxBasicMsr.Bits.RevisionIdentifier;
  *(UINT32*)TestVmcsBuffer = VmxBasicMsr.Bits.RevisionIdentifier;

  Print (L"%a - Enter VMX root mode...\n", __func__);
  Ret = AsmVmxOn ((UINT64*)&TestVmxOnBuffer);
  Print (L"%a - VMX root mode entered! - 0x%lx\n", __func__, Ret);

  Print (L"CR0: %x\n", AsmReadCr0());
  Print (L"CR4: %x\n", AsmReadCr4());

  Print (L"Clear VMCS buffer...\n");
  AsmVmClear ((UINT64*)&TestVmcsBuffer);
  Print (L"%a - Vmcs buffer cleared!\n", __func__);

  Print (L"Load VMCS buffer for this core...\n");
  AsmVmPtrLoad ((UINT64*)&TestVmcsBuffer);
  Print (L"%a - VMCS buffer loaded!\n", __func__);

  u64 = AsmReadMsr64 (IA32_VMX_EXIT_CTLS_MSR_INDEX);
  VmExitCtrls.Uint32 = (UINT32)u64 & (UINT32)RShiftU64 (u64, 32);
  Print (L"%a - VmxExitCtrls = 0x%x\n", __func__, VmExitCtrls.Uint32);

  VmExitCtrls.Bits.SaveIA32_EFER = TRUE;
  VmExitCtrls.Bits.Ia32eHost = TRUE;
  VmWrite32 (VMCS_32_CONTROL_VMEXIT_CONTROLS_INDEX, VmExitCtrls.Uint32);

  u64 = AsmReadMsr64 (IA32_VMX_ENTRY_CTLS_MSR_INDEX);
  VmEntryCtrls.Uint32 = (UINT32)u64 & (UINT32)RShiftU64 (u64, 32);
  Print (L"%a - VmEntryCtrls = 0x%lx\n", __func__, VmEntryCtrls.Uint32);

  VmEntryCtrls.Bits.LoadIA32_EFER = TRUE;
  VmEntryCtrls.Bits.Ia32eGuest = TRUE;
  VmWrite32 (VMCS_32_CONTROL_VMENTRY_CONTROLS_INDEX, VmEntryCtrls.Uint32);

  Print (L"%a - VMCS controls set!\n", __func__);

  // Ready to get capabilities from SEA through VMCALL
  Print (L"%a - Getting capabilities from SEA...\n", __func__);
  ZeroMem (TestCommBuffer, EFI_PAGE_SIZE);
  Ret = AsmVmCall (SEA_API_GET_CAPABILITIES, (UINT32)(UINTN)TestCommBuffer, 0, 1);
  Print (L"%a - Getting capabilities completed - 0x%x!\n", __func__, Ret);

  if (Ret != STM_SUCCESS) {
    Print (L"ERROR - AsmVmCall returned %r\n", Ret);
    return;
  }

  Print (L"%a - Getting resources from SEA...\n", __func__);
  ZeroMem (TestCommBuffer, EFI_PAGE_SIZE);
  Ret = AsmVmCall (SEA_API_GET_RESOURCES, 0, 0, 0);
  Print (L"%a - Getting resources completed - 0x%x!\n", __func__, Ret);

  if (Ret != ERROR_STM_BUFFER_TOO_SMALL) {
    Print (L"ERROR - AsmVmCall returned %r\n", Ret);
    return;
  }

  Print (L"%a - Getting resources with buffer size %d...\n", __func__, EFI_PAGE_SIZE);
  ZeroMem (TestCommBuffer, EFI_PAGE_SIZE);
  Ret = AsmVmCall (SEA_API_GET_RESOURCES, (UINT32)(UINTN)TestCommBuffer, 0, 1);
  Print (L"%a - BSP getting resources completed - 0x%x!\n", __func__, Ret);

  if (Ret != STM_SUCCESS) {
    Print (L"ERROR - AsmVmCall returned %r\n", Ret);
    return;
  }
} // InvokeVmcalls()

/**
  ResponderValidationTestAppEntry

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point executed successfully.
  @retval other           Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
ResponderValidationTestAppEntry (
  IN     EFI_HANDLE        ImageHandle,
  IN     EFI_SYSTEM_TABLE  *SystemTable
  )
{
  Print (L"%a the app's up!\n", __func__);

  //
  // Get the EFI memory map.
  //
  // UINTN                  Retry  = 0;
  // EFI_MEMORY_DESCRIPTOR  *EfiMemoryMap = NULL;
  // UINTN                  EfiMemoryMapSize;
  EFI_STATUS             Status = EFI_SUCCESS;
  // UINTN                  EfiMapKey;
  // UINTN                  EfiDescriptorSize;
  // UINT32                 EfiDescriptorVersion;

  TestVmxOnBuffer = AllocateAlignedPages (4, EFI_PAGE_SIZE);
  if (TestVmxOnBuffer == NULL) {
    Print (L"ERROR - Failed to allocate VMXON buffer!\n");
    FreePool (TestVmxOnBuffer);
    return EFI_OUT_OF_RESOURCES;
  }

  TestVmcsBuffer = TestVmxOnBuffer + EFI_PAGES_TO_SIZE (2);

  TestCommBuffer = AllocatePages (1);
  if (TestCommBuffer == NULL) {
    Print (L"ERROR - Failed to allocate communication buffer!\n");
    FreePool (TestVmxOnBuffer);
    return EFI_OUT_OF_RESOURCES;
  }

  InvokeVmcalls (NULL, NULL);

  // // Install EBS callback handler
  // Status = gBS->CreateEventEx (
  //       EVT_NOTIFY_SIGNAL,
  //       (TPL_APPLICATION + 1),
  //       InvokeVmcalls,
  //       gImageHandle,
  //       &gEfiEventExitBootServicesGuid,
  //       &mExitBootServicesEvent
  //       );

  // do {
  //   if (EfiMemoryMap != NULL) {
  //     FreePool (EfiMemoryMap);
  //   }

  //   EfiMemoryMapSize = 0;
  //   EfiMemoryMap     = NULL;
  //   Status           = gBS->GetMemoryMap (
  //                             &EfiMemoryMapSize,
  //                             EfiMemoryMap,
  //                             &EfiMapKey,
  //                             &EfiDescriptorSize,
  //                             &EfiDescriptorVersion
  //                             );
  //   if ((Status != EFI_BUFFER_TOO_SMALL) || !EfiMemoryMapSize) {
  //     Print (L"GetMemoryMap Error %r\n", Status);
  //     return EFI_BAD_BUFFER_SIZE;
  //   }

  //   EfiMemoryMapSize += EfiMemoryMapSize + 64 * EfiDescriptorSize;
  //   EfiMemoryMap      = AllocateZeroPool (EfiMemoryMapSize);
  //   if (EfiMemoryMap == NULL) {
  //     return EFI_OUT_OF_RESOURCES;
  //   }

  //   Status = gBS->GetMemoryMap (
  //                   &EfiMemoryMapSize,
  //                   EfiMemoryMap,
  //                   &EfiMapKey,
  //                   &EfiDescriptorSize,
  //                   &EfiDescriptorVersion
  //                   );
  //   if (EFI_ERROR (Status)) {
  //     Print (L"GetMemoryMap Error %r\n", Status);
  //     return Status;
  //   }

  //   //
  //   // Create exit boot services event
  //   //
  //   // Print (L"Calling ExitBootServices - Retry = %d\n", Retry);
  //   Status = gBS->ExitBootServices (
  //                   gTestImageHandle,
  //                   EfiMapKey
  //                   );
  // } while (EFI_ERROR (Status) && Retry++ < GET_MEMORY_MAP_RETRIES);

  if (EFI_ERROR (Status)) {
    Print (L"ERROR - Exit Boot Services returned %r\n", Status);
  }

  // Should not be here!!!
  Print (L"%a the app's done!\n", __func__);

  return EFI_SUCCESS;
} // ResponderValidationTestAppEntry()
