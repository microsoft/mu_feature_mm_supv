/** @file
Implementation of SMM policy related routine.

Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <SmmSecurePolicy.h>

#include <Register/ArchitecturalMsr.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SecurePolicyLib.h>

#define PAGING_4K_ADDRESS_MASK_64  0x000FFFFFFFFFF000ull
#define PAGING_2M_ADDRESS_MASK_64  0x000FFFFFFFE00000ull
#define PAGING_1G_ADDRESS_MASK_64  0x000FFFFFC0000000ull

#define MEM_DESC_UNINIT_BASEADDR  0xDEADBEEF

#pragma pack(1)

//
// Page Table Entry 4KB
//
typedef union {
  struct {
    UINT64    Present              : 1;  // 0 = Not present in memory, 1 = Present in memory
    UINT64    ReadWrite            : 1;  // 0 = Read-Only, 1= Read/Write
    UINT64    UserSupervisor       : 1;  // 0 = Supervisor, 1=User
    UINT64    WriteThrough         : 1;  // 0 = Write-Back caching, 1=Write-Through caching
    UINT64    CacheDisabled        : 1;  // 0 = Cached, 1=Non-Cached
    UINT64    Accessed             : 1;  // 0 = Not accessed, 1 = Accessed (set by CPU)
    UINT64    Dirty                : 1;  // 0 = Not Dirty, 1 = written by processor on access to page
    UINT64    PS                   : 1;  // In PDPE, PDE present PS bit, can be used determine if it is 1G or 2M page
    UINT64    Global               : 1;  // 0 = Not global page, 1 = global page TLB not cleared on CR3 write
    UINT64    Available            : 3;  // Available for use by system software
    UINT64    PageTableBaseAddress : 40; // Page Table Base Address
    UINT64    AvailableHigh        : 11; // Available for use by system software
    UINT64    Nx                   : 1;  // 0 = Execute Code, 1 = No Code Execution
  } Bits;
  UINT64    Uint64;
} PAGE_TABLE_ENTRY;

#pragma pack()

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This buffer is not part of MMRAM.
  @retval FALSE This buffer is from MMRAM.
**/
BOOLEAN
EFIAPI
IsBufferInsideMmram (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  );

/**
  Update the policy memory description.
**/
STATIC
VOID
UpdateMemoryDesc (
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  **pMemoryPolicy,
  UINT32                                      *pMemoryPolicyCount,
  UINT32                                      MemoryAttr,
  UINT64                                      PageTableBaseAddress,
  UINT64                                      Size
  )
{
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemoryPolicy;

  MemoryPolicy = *pMemoryPolicy;
  // DEBUG ((DEBUG_INFO, "UpdateMemoryDesc %x %x \n", MemoryPolicy, pMemoryPolicyCount));
  // This is the 1st record
  if (MemoryPolicy->BaseAddress == MEM_DESC_UNINIT_BASEADDR) {
    MemoryPolicy->BaseAddress   = PageTableBaseAddress;
    MemoryPolicy->Size          = Size;
    MemoryPolicy->MemAttributes = MemoryAttr;
    MemoryPolicy->Reserved      = 0;
  } else {
    // Check if the continual address of Current memory policy
    if ((PageTableBaseAddress == MemoryPolicy->BaseAddress + MemoryPolicy->Size) &&
        (MemoryAttr == MemoryPolicy->MemAttributes))
    {
      MemoryPolicy->Size += Size;
    } else {
      MemoryPolicy++;
      MemoryPolicy->BaseAddress   = PageTableBaseAddress;
      MemoryPolicy->Size          = Size;
      MemoryPolicy->MemAttributes = MemoryAttr;
      MemoryPolicy->Reserved      = 0;
      *pMemoryPolicyCount        += 1;
      *pMemoryPolicy              = MemoryPolicy;
    }
  }
}

// comment to disable debug print
// #define PAGE_TBL_PRINT_EN

#ifdef PAGE_TBL_PRINT_EN
#define PAGE_TBL_PRINT(Expression)  DEBUG (Expression)
#else
#define PAGE_TBL_PRINT(Expression)
#endif

/*
  Generate Memory policy DENIAL DESCRIPTORs by traverse pagetables
  Shadow current pagetable if IsShadow set
  if input Cr3 is zero, check the real HW register

  @retval EFI_SUCCESS           Execute operation successfully
  @retval EFI_OUT_OF_RESOURCES  MemoryPolicySize is too small to hold all memory policy
  @retval EFI_UNSUPPORTED       Current register setting doesn't support page mode, if input CR3 is no-zero
*/
STATIC
EFI_STATUS
GenMemPolicyAndShadowPageTable (
  IN       UINT64  Cr3,
  IN OUT   VOID    *MemoryPolicyPtr,
  IN       UINTN   MemoryPolicySize,
  IN OUT   UINT32  *MemoryPolicyCount
  )
{
  MSR_IA32_EFER_REGISTER                      MsrEfer;
  IA32_CR0                                    Cr0;
  UINT64                                      PML4Base;
  UINT32                                      i, j, k, l;
  PAGE_TABLE_ENTRY                            *PML4Table;
  PAGE_TABLE_ENTRY                            *PDPETable;
  PAGE_TABLE_ENTRY                            *PDETable;
  PAGE_TABLE_ENTRY                            *PTETable;
  UINT64                                      PageTableBaseAddress;
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemoryPolicy;
  UINT32                                      PML4MemoryAttr;
  UINT32                                      PDPEMemoryAttr;
  UINT32                                      PDEMemoryAttr;
  UINT32                                      MemoryAttr;
  UINTN                                       L4PageNum;
  UINTN                                       L3PageNum;
  UINTN                                       L2PageNum;
  UINTN                                       L1PageNum;
  UINTN                                       MemPolicyBoundary;

  MemPolicyBoundary         = (UINTN)MemoryPolicyPtr + MemoryPolicySize;
  *MemoryPolicyCount        = 1;
  L4PageNum                 = 0;
  L3PageNum                 = 0;
  L2PageNum                 = 0;
  L1PageNum                 = 0;
  MemoryPolicy              = MemoryPolicyPtr;
  MemoryPolicy->BaseAddress = MEM_DESC_UNINIT_BASEADDR;

  DEBUG ((DEBUG_INFO, "GenMemPolicyAndShadowPageTable, MemoryPolicyPtr:%lx, MemoryPolicySize:%lx\n", (UINTN)MemoryPolicyPtr, MemoryPolicySize));
  // Code to traverse SMM page table to generate SMM policy structure
  if (Cr3 == 0) {
    // Only support long page table
    // Check if long mode
    MsrEfer.Uint64 = AsmReadMsr64 (MSR_IA32_EFER);
    DEBUG ((DEBUG_INFO, "EFER.NXE = %x\n", MsrEfer.Bits.NXE));
    if ((MsrEfer.Bits.LME == 0) || (MsrEfer.Bits.LMA == 0)) {
      DEBUG ((DEBUG_ERROR, "EFER.LMA ==0 || EFER.LME == 0, exit\n"));
      return EFI_UNSUPPORTED;
    }

    // Check if Page enabled
    Cr0.UintN = AsmReadCr0 ();
    if (Cr0.Bits.PG == 0) {
      DEBUG ((DEBUG_ERROR, "Cr0.Bits.PG == 0, exit\n"));
      return EFI_UNSUPPORTED;
    }

    // Assuming CR0.WP enabled
    if (Cr0.Bits.WP == 0) {
      DEBUG ((DEBUG_ERROR, "Cr0.Bits.WP == 0, exit\n"));
      return EFI_UNSUPPORTED;
    }

    // Get PML4 base from CR3 register
    PML4Base = AsmReadCr3 () & 0x000FFFFFFFFFF000ull;
  } else {
    // Get PML4 base from input
    PML4Base = Cr3 & 0x000FFFFFFFFFF000ull;
  }

  DEBUG ((DEBUG_INFO, "PML4Base = 0x%x\n", PML4Base));
  PML4Table = (PAGE_TABLE_ENTRY *)PML4Base;
  L4PageNum++;
  // Loop 512 PML4 entries
  for (i = 0; i < 512; i++) {
    PAGE_TBL_PRINT ((DEBUG_INFO, "PML4[%d] = 0x%Lx \n", i, PML4Table[i].Uint64));
    // If present not set, skip this page table entry
    if (PML4Table[i].Bits.Present == 0) {
      continue;
    }

    PAGE_TBL_PRINT (
      (DEBUG_INFO, "P:%x R/W:%x U/S:%x PWT:%x PCD:%x A:%x D:%x PS:%x G:%x NX:%x\n", \
       PML4Table[i].Bits.Present, \
       PML4Table[i].Bits.ReadWrite, \
       PML4Table[i].Bits.UserSupervisor, \
       PML4Table[i].Bits.WriteThrough, \
       PML4Table[i].Bits.CacheDisabled, \
       PML4Table[i].Bits.Accessed, \
       PML4Table[i].Bits.Dirty, \
       PML4Table[i].Bits.PS, \
       PML4Table[i].Bits.Global, \
       PML4Table[i].Bits.Nx
      )
      );
    PML4MemoryAttr = 0;
    if (PML4Table[i].Bits.ReadWrite == 1) {
      PML4MemoryAttr |= (SECURE_POLICY_RESOURCE_ATTR_WRITE | SECURE_POLICY_RESOURCE_ATTR_READ);
    } else {
      PML4MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_READ;
    }

    if (PML4Table[i].Bits.Nx == 0) {
      PML4MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
    }

    PDPETable = (PAGE_TABLE_ENTRY *)(PML4Table[i].Uint64 & 0x000FFFFFFFFFF000ull);
    L3PageNum++;
    // Loop 512 PDPE entries
    for (j = 0; j < 512; j++) {
      // If present not set, skip this page table entry
      if (PDPETable[j].Bits.Present == 0) {
        continue;
      }

      PAGE_TBL_PRINT ((DEBUG_INFO, "\tPDPE[%d] = 0x%x ", j, PDPETable[j].Uint64));
      PAGE_TBL_PRINT (
        (DEBUG_INFO, "P:%x R/W:%x U/S:%x PWT:%x PCD:%x A:%x D:%x PS:%x G:%x NX:%x\n", \
         PDPETable[j].Bits.Present, \
         PDPETable[j].Bits.ReadWrite, \
         PDPETable[j].Bits.UserSupervisor, \
         PDPETable[j].Bits.WriteThrough, \
         PDPETable[j].Bits.CacheDisabled, \
         PDPETable[j].Bits.Accessed, \
         PDPETable[j].Bits.Dirty, \
         PDPETable[j].Bits.PS, \
         PDPETable[j].Bits.Global, \
         PDPETable[j].Bits.Nx \
        )
        );
      PDPEMemoryAttr = 0;
      if (PDPETable[j].Bits.ReadWrite == 1) {
        PDPEMemoryAttr |= (SECURE_POLICY_RESOURCE_ATTR_WRITE | SECURE_POLICY_RESOURCE_ATTR_READ);
      } else {
        PDPEMemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_READ;
      }

      if (PDPETable[j].Bits.Nx == 0) {
        PDPEMemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
      }

      // PS resent in the lowest level of the page-translation
      if (PDPETable[j].Bits.PS == 1) {
        // 1G Table reached
        PageTableBaseAddress = PDPETable[j].Uint64 & PAGING_1G_ADDRESS_MASK_64;
        if (PDPETable[j].Bits.UserSupervisor == 0) {
          DEBUG ((DEBUG_VERBOSE, "CPL0 ADDR[%lx-%lx]\n", PageTableBaseAddress, PageTableBaseAddress+ 0x40000000ull -1));
        }

        PAGE_TBL_PRINT ((DEBUG_INFO, "ADDR[%lx-%lx]", PageTableBaseAddress, PageTableBaseAddress+ 0x40000000ull -1));
        PAGE_TBL_PRINT (
          (DEBUG_INFO, "P:%x R/W:%x U/S:%x PWT:%x PCD:%x A:%x D:%x PS:%x G:%x NX:%x\n", \
           PDPETable[j].Bits.Present, \
           PDPETable[j].Bits.ReadWrite, \
           PDPETable[j].Bits.UserSupervisor, \
           PDPETable[j].Bits.WriteThrough, \
           PDPETable[j].Bits.CacheDisabled, \
           PDPETable[j].Bits.Accessed, \
           PDPETable[j].Bits.Dirty, \
           PDPETable[j].Bits.PS, \
           PDPETable[j].Bits.Global, \
           PDPETable[j].Bits.Nx \
          )
          );
        if (IsBufferInsideMmram (PageTableBaseAddress, 0x40000000ull)) {
          // Do not report if this region is fully inside MMRAM, meaning we still report the page if the page is at the limbo
          continue;
        }

        // Set to R/W, execute enable as default
        MemoryAttr = 0;
        if (PDPETable[j].Bits.Present == 1) {
          MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
          MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_READ;
          MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_WRITE;
        }

        // For new struct, upper table R/W allowance can be inherited
        MemoryAttr &= PDPEMemoryAttr;
        MemoryAttr &= PML4MemoryAttr;
        UpdateMemoryDesc (&MemoryPolicy, MemoryPolicyCount, MemoryAttr, PageTableBaseAddress, 0x40000000ull);
        ASSERT ((UINTN)MemoryPolicy < MemPolicyBoundary);
        if ((UINTN)MemoryPolicy >= MemPolicyBoundary) {
          return EFI_OUT_OF_RESOURCES;
        }

        continue;
      }

      PDETable = (PAGE_TABLE_ENTRY *)(PDPETable[j].Uint64 & 0x000FFFFFFFFFF000ull);
      L2PageNum++;
      // Loop 512 PDE entries
      for (k = 0; k < 512; k++) {
        // If present not set, skip this page table entry
        if (PDETable[k].Bits.Present == 0) {
          continue;
        }

        PAGE_TBL_PRINT ((DEBUG_INFO, "\t\tPDE[%d] = 0x%x ", k, PDETable[k].Uint64));
        PAGE_TBL_PRINT (
          (DEBUG_INFO, "P:%x R/W:%x U/S:%x PWT:%x PCD:%x A:%x D:%x PS:%x G:%x NX:%x\n", \
           PDETable[k].Bits.Present, \
           PDETable[k].Bits.ReadWrite, \
           PDETable[k].Bits.UserSupervisor, \
           PDETable[k].Bits.WriteThrough, \
           PDETable[k].Bits.CacheDisabled, \
           PDETable[k].Bits.Accessed, \
           PDETable[k].Bits.Dirty, \
           PDETable[k].Bits.PS, \
           PDETable[k].Bits.Global, \
           PDETable[k].Bits.Nx
          )
          );
        PDEMemoryAttr = 0;
        if (PDETable[k].Bits.ReadWrite == 1) {
          PDEMemoryAttr |= (SECURE_POLICY_RESOURCE_ATTR_WRITE | SECURE_POLICY_RESOURCE_ATTR_READ);
        } else {
          PDEMemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_READ;
        }

        if (PDETable[k].Bits.Nx == 0) {
          PDEMemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
        }

        // PS resent in the lowest level of the page-translation
        if (PDETable[k].Bits.PS == 1) {
          // 2M Table reached
          PageTableBaseAddress = PDETable[k].Uint64 & PAGING_2M_ADDRESS_MASK_64;
          if (PDETable[k].Bits.UserSupervisor == 0) {
            DEBUG ((DEBUG_VERBOSE, "CPL0 ADDR[%lx-%lx]\n", PageTableBaseAddress, PageTableBaseAddress+ 0x200000ull -1));
          }

          PAGE_TBL_PRINT ((DEBUG_INFO, "ADDR[%lx-%lx]", PageTableBaseAddress, PageTableBaseAddress+ 0x200000ull - 1));
          PAGE_TBL_PRINT (
            (DEBUG_INFO, "P:%x R/W:%x U/S:%x PWT:%x PCD:%x A:%x D:%x PS:%x G:%x NX:%x\n", \
             PDETable[k].Bits.Present, \
             PDETable[k].Bits.ReadWrite, \
             PDETable[k].Bits.UserSupervisor, \
             PDETable[k].Bits.WriteThrough, \
             PDETable[k].Bits.CacheDisabled, \
             PDETable[k].Bits.Accessed, \
             PDETable[k].Bits.Dirty, \
             PDETable[k].Bits.PS, \
             PDETable[k].Bits.Global, \
             PDETable[k].Bits.Nx
            )
            );
          if (IsBufferInsideMmram (PageTableBaseAddress, 0x200000ull)) {
            // Do not report if this region is fully inside MMRAM, meaning we still report the page if the page is at the limbo
            continue;
          }

          // Set to R/W, execute enable as default
          MemoryAttr = 0;
          if (PDETable[k].Bits.Present == 1) {
            MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
            MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_READ;
            MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_WRITE;
          }

          // For new struct, upper table R/W allowance can be inherited
          MemoryAttr &= PDEMemoryAttr;
          MemoryAttr &= PDPEMemoryAttr;
          MemoryAttr &= PML4MemoryAttr;
          UpdateMemoryDesc (&MemoryPolicy, MemoryPolicyCount, MemoryAttr, PageTableBaseAddress, 0x200000ull);
          ASSERT ((UINTN)MemoryPolicy < MemPolicyBoundary);
          if ((UINTN)MemoryPolicy >= MemPolicyBoundary) {
            return EFI_OUT_OF_RESOURCES;
          }

          continue;
        }

        L1PageNum++;
        PTETable = (PAGE_TABLE_ENTRY *)(PDETable[k].Uint64 & 0x000FFFFFFFFFF000ull);
        // Loop 512 PTE entries
        for (l = 0; l < 512; l++) {
          // If present not set, skip this page table entry
          if (PTETable[l].Bits.Present == 0) {
            continue;
          }

          // 4K Table reached
          PageTableBaseAddress = PTETable[l].Uint64 & PAGING_4K_ADDRESS_MASK_64;
          if (PTETable[l].Bits.UserSupervisor == 0) {
            DEBUG ((DEBUG_VERBOSE, "CPL0 ADDR[%lx-%lx]\n", PageTableBaseAddress, PageTableBaseAddress+ 0x1000ull -1));
          }

          PAGE_TBL_PRINT ((DEBUG_INFO, "ADDR[%lx-%lx]", PageTableBaseAddress, PageTableBaseAddress+ 0x1000ull -1));
          PAGE_TBL_PRINT (
            (DEBUG_INFO, "P:%x R/W:%x U/S:%x PWT:%x PCD:%x A:%x D:%x G:%x NX:%x\n", \
             PTETable[l].Bits.Present, \
             PTETable[l].Bits.ReadWrite, \
             PTETable[l].Bits.UserSupervisor, \
             PTETable[l].Bits.WriteThrough, \
             PTETable[l].Bits.CacheDisabled, \
             PTETable[l].Bits.Accessed, \
             PTETable[l].Bits.Dirty, \
             PTETable[l].Bits.Global, \
             PTETable[l].Bits.Nx
            )
            );
          if (IsBufferInsideMmram (PageTableBaseAddress, 0x1000ull)) {
            // Do not report if this region is fully inside MMRAM, meaning we still report the page if the page is at the limbo
            continue;
          }

          // Set to R/W, execute enable as default
          MemoryAttr = 0;
          if (PTETable[l].Bits.ReadWrite == 1) {
            MemoryAttr |= (SECURE_POLICY_RESOURCE_ATTR_WRITE | SECURE_POLICY_RESOURCE_ATTR_READ);
          } else {
            MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_READ;
          }

          if (PTETable[l].Bits.Present == 1) {
            if (PTETable[l].Bits.Nx == 0) {
              MemoryAttr |= SECURE_POLICY_RESOURCE_ATTR_EXECUTE;
            }
          } else {
            MemoryAttr = 0;
          }

          // For new struct, upper table R/W allowance can be inherited
          MemoryAttr &= PDEMemoryAttr;
          MemoryAttr &= PDPEMemoryAttr;
          MemoryAttr &= PML4MemoryAttr;
          UpdateMemoryDesc (&MemoryPolicy, MemoryPolicyCount, MemoryAttr, PageTableBaseAddress, 0x1000ull);
          ASSERT ((UINTN)MemoryPolicy < MemPolicyBoundary);
          if ((UINTN)MemoryPolicy >= MemPolicyBoundary) {
            return EFI_OUT_OF_RESOURCES;
          }
        } // for (l = 0; l < 512; l++)
      } // for (k = 0; k < 512; k++)
    }
  }

  DEBUG ((DEBUG_INFO, "== L4PageNum: %d, L3PageNum: %d, L2PageNum: %d, L1PageNum: %d ==\n", L4PageNum, L3PageNum, L2PageNum, L1PageNum));

  return EFI_SUCCESS;
}

/**
  Dump a single memory policy data.
**/
VOID
EFIAPI
DumpMemPolicyEntry (
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemoryPolicy
  )
{
  if (MemoryPolicy == NULL) {
    DEBUG ((DEBUG_INFO, "%a Received null input pointer!\n", __func__));
    ASSERT (FALSE);
    return;
  }

  DEBUG ((
    DEBUG_INFO,
    "V1.0 MEM: [%lx-%lx] %a %a %a\n", \
    MemoryPolicy->BaseAddress, \
    MemoryPolicy->BaseAddress + MemoryPolicy->Size -1, \
    (MemoryPolicy->MemAttributes & SECURE_POLICY_RESOURCE_ATTR_READ) ? "R" : ".", \
    (MemoryPolicy->MemAttributes & SECURE_POLICY_RESOURCE_ATTR_WRITE) ? "W" : ".", \
    (MemoryPolicy->MemAttributes & SECURE_POLICY_RESOURCE_ATTR_EXECUTE) ? "X" : "."
    ));
}

/**
  Helper function that populates memory policy on demands.

  @param[in] SmmPolicyBuffer   Input buffer points to the entire v1.0 policy.
  @param[in] MaxPolicySize     Maximum size of the policy buffer.
  @param[in] Cr3               CR3 value to be converted, if input is zero, check the real HW register.

  @param[in] CpuIndex Logical number assigned to CPU.
**/
EFI_STATUS
EFIAPI
PopulateMemoryPolicyEntries (
  IN  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyBuffer,
  IN  UINT64                            MaxPolicySize,
  IN  UINT64                            Cr3
  )
{
  SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0  *MemoryPolicy;
  SMM_SUPV_POLICY_ROOT_V1                     *PolicyRoot;
  UINTN                                       MemoryPolicySize;
  UINTN                                       i;
  EFI_STATUS                                  Status;

  if (SmmPolicyBuffer == NULL) {
    Status = EFI_INVALID_PARAMETER;
    DEBUG ((DEBUG_ERROR, "%a Incoming policy buffer is null pointer.\n", __func__));
    goto Exit;
  }

  // IO and MSR policies are populated during report DRTM info time,
  // Here just append MemPolicy to the end of static table.
  PolicyRoot = (SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmPolicyBuffer + SmmPolicyBuffer->PolicyRootOffset);
  for (i = 0; i < SmmPolicyBuffer->PolicyRootCount; i++) {
    if (PolicyRoot[i].Type == SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM) {
      PolicyRoot = PolicyRoot + i;
      break;
    }
  }

  if (i >= SmmPolicyBuffer->PolicyRootCount) {
    // TODO: Do we want to add handling here?
    // Something is wrong, there is not placeholder left for memory type, do not want to handle it...
    DEBUG ((DEBUG_ERROR, "%a Incoming policy buffer does not contain memory type policy root.\n", __func__));
    Status = EFI_NOT_FOUND;
    goto Exit;
  }

  // Init PolicyRoot->Offset field
  PolicyRoot->AccessAttr = SMM_SUPV_ACCESS_ATTR_ALLOW;
  if (PolicyRoot->Offset == 0) {
    // Only populate the offset if not already set
    PolicyRoot->Offset = SmmPolicyBuffer->Size;
  }

  PolicyRoot->PolicyRootSize = sizeof (SMM_SUPV_POLICY_ROOT_V1);
  // This is not needed with our check above
  // PolicyRoot->Type = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM;
  PolicyRoot->Version = 1;
  MemoryPolicy        = (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0 *)((UINTN)SmmPolicyBuffer + PolicyRoot->Offset);
  MemoryPolicySize    = MaxPolicySize - PolicyRoot->Offset - 1;
  // Generate Policy of current Pagetable
  Status = GenMemPolicyAndShadowPageTable (Cr3, MemoryPolicy, MemoryPolicySize, &PolicyRoot->Count);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Fail to GenMemPolicyAndShadowPageTable for non-legacy structures %r\n", __func__, Status));
    goto Exit;
  }

  SmmPolicyBuffer->Size = PolicyRoot->Offset + (sizeof (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0) * PolicyRoot->Count);

  SmmPolicyBuffer->MemoryPolicyCount = 0;

Exit:
  return Status;
}

/**
  Compare two policies with a given type.

  @param  SmmPolicyData1    The first data to compare.
  @param  SmmPolicyData2    The second data to compare.
  @param  PolicyType        The type of policy to compare.

  @retval FALSE       If two memory policy not identical.

**/
BOOLEAN
EFIAPI
ComparePolicyWithType (
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyData1,
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyData2,
  UINT32                            PolicyType
  )
{
  UINTN                    MemoryPolicySize;
  UINT8                    *SmmPolicy1  = NULL;
  UINT8                    *SmmPolicy2  = NULL;
  SMM_SUPV_POLICY_ROOT_V1  *PolicyRoot1 = NULL;
  SMM_SUPV_POLICY_ROOT_V1  *PolicyRoot2 = NULL;
  UINTN                    i;

  if ((SmmPolicyData1 == NULL) || (SmmPolicyData2 == NULL)) {
    return FALSE;
  }

  // Locate memory descriptors first
  for (i = 0; i < SmmPolicyData1->PolicyRootCount; i++) {
    PolicyRoot1 = &((SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmPolicyData1 + SmmPolicyData1->PolicyRootOffset))[i];
    if (PolicyRoot1->Type == PolicyType) {
      // Here we found it
      SmmPolicy1 = (UINT8 *)SmmPolicyData1 + PolicyRoot1->Offset;
      break;
    }
  }

  for (i = 0; i < SmmPolicyData2->PolicyRootCount; i++) {
    PolicyRoot2 = &((SMM_SUPV_POLICY_ROOT_V1 *)((UINTN)SmmPolicyData2 + SmmPolicyData2->PolicyRootOffset))[i];
    if (PolicyRoot2->Type == PolicyType) {
      // Here we found it
      SmmPolicy2 = (UINT8 *)SmmPolicyData2 + PolicyRoot2->Offset;
      break;
    }
  }

  if ((SmmPolicy1 == NULL) || (SmmPolicy2 == NULL) ||
      (PolicyRoot1 == NULL) || (PolicyRoot2 == NULL) ||
      (PolicyRoot1->Version != PolicyRoot2->Version) ||
      (PolicyRoot1->PolicyRootSize != PolicyRoot2->PolicyRootSize) ||
      (PolicyRoot1->AccessAttr != PolicyRoot2->AccessAttr) ||
      (PolicyRoot1->Count != PolicyRoot2->Count))
  {
    return FALSE;
  }

  MemoryPolicySize = sizeof (SMM_SUPV_SECURE_POLICY_MEM_DESCRIPTOR_V1_0) * PolicyRoot1->Count;
  SmmPolicy1       = (UINT8 *)SmmPolicyData1 + PolicyRoot1->Offset;
  SmmPolicy2       = (UINT8 *)SmmPolicyData2 + PolicyRoot2->Offset;
  if (CompareMem (SmmPolicy1, SmmPolicy2, MemoryPolicySize) == 0) {
    return TRUE;
  }

  return FALSE;
}

/**
  Compare memory policy in two SmmPolicy.

  @param  SmmPolicyData1    The first data to compare.
  @param  SmmPolicyData2    The second data to compare.

  @retval FALSE       If two memory policy not identical.

**/
BOOLEAN
EFIAPI
CompareMemoryPolicy (
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyData1,
  SMM_SUPV_SECURE_POLICY_DATA_V1_0  *SmmPolicyData2
  )
{
  return ComparePolicyWithType (SmmPolicyData1, SmmPolicyData2, SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM);
}

/**
  Prepare a snapshot of memory policy, this will be compared against the one generated when requested.

  @param[in] MemPolicySnapshot  The buffer to hold the snapshot of memory policy, should be at least the
                                size of MEM_POLICY_SNAPSHOT_SIZE.

  @retval EFI_SUCCESS               The security policy is successfully gathered.
  @retval EFI_NOT_STARTED           No memory policy snapshot buffer prepared.
  @retval Errors                    Other error during populating memory errors.
**/
EFI_STATUS
EFIAPI
PrepareMemPolicySnapshot (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  *MemPolicySnapshot
  )
{
  SMM_SUPV_POLICY_ROOT_V1  *PolicyRoot;
  EFI_STATUS               Status;

  if (MemPolicySnapshot == NULL) {
    Status = EFI_NOT_STARTED;
    goto Done;
  }

  // Use SmmTempPolicyData as temp buffer to hold memory policy data
  ZeroMem (MemPolicySnapshot, MEM_POLICY_SNAPSHOT_SIZE);

  // First, we populate the bare minimal content for policy root as a kick starter
  PolicyRoot                          = (SMM_SUPV_POLICY_ROOT_V1 *)(MemPolicySnapshot + 1);
  MemPolicySnapshot->PolicyRootCount  = 1;
  MemPolicySnapshot->PolicyRootOffset = (UINT32)((UINTN)PolicyRoot - (UINTN)MemPolicySnapshot);
  MemPolicySnapshot->Size             = MemPolicySnapshot->PolicyRootOffset + sizeof (SMM_SUPV_POLICY_ROOT_V1);
  PolicyRoot->Type                    = SMM_SUPV_SECURE_POLICY_DESCRIPTOR_TYPE_MEM;

  // Then leave the heavy lifting job to the library
  Status = PopulateMemoryPolicyEntries (MemPolicySnapshot, MEM_POLICY_SNAPSHOT_SIZE, 0);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a Fail to PopulateMemoryPolicyEntries %r\n", __func__, Status));
  }

Done:
  return Status;
}

/**
  Allocate a static buffer for taking snapshot of memory policy when we lock down page table.

  @retval EFI_SUCCESS               Buffer is allocated properly.
  @retval EFI_OUT_OF_RESOURCES      Cannot allocate enough resources for snapshot.
**/
EFI_STATUS
EFIAPI
AllocateMemForPolicySnapshot (
  IN SMM_SUPV_SECURE_POLICY_DATA_V1_0  **MemPolicySnapshot
  )
{
  *MemPolicySnapshot = AllocatePages (EFI_SIZE_TO_PAGES (MEM_POLICY_SNAPSHOT_SIZE));
  if (*MemPolicySnapshot == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}
