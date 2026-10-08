# HOB Construction for Rust Supervisor Initialization

The C initialization module prepares the MM environment for a separately built Rust supervisor and user runtime.
Its output is a Hand-Off Block (HOB) list describing the loaded modules, their dependencies, initialization resources,
and the MMRAM allocation state. The runtime must consume this description without reallocating memory still in use.

This document describes the producer implemented in this repository. It does not describe the legacy C supervisor's
runtime HOB handling or guarantee how an external runtime validates these records.

## Implementation map

| Component | Responsibility |
| --- | --- |
| [MmSupervisorInit.c](../../Core/MmSupervisorInit.c) | Orchestrates discovery, loading, HOB construction, memory protection, and runtime handoff. |
| [DispatcherInit.c](../../Core/Dispatcher/DispatcherInit.c) | Records discovered drivers and their DEPEX, then loads drivers without dispatching them. |
| [SupvInitHobs.c](../../Core/Hob/SupvInitHobs.c) | Copies retained input HOBs and creates the runtime handoff records. |
| [SupvInitHobs.h](../../Core/Hob/SupvInitHobs.h) | Defines the builder state and construction APIs. |
| [PassDown.h](../../Include/Guid/PassDown.h) | Defines the revision'd initialization-resource payload. |
| [DepexStruc.h](../../Include/Guid/DepexStruc.h) | Defines the per-driver dependency-expression payload. |
| [MmSupervisorPkg.dec](../../MmSupervisorPkg.dec) | Declares the GUIDs identifying the new records and runtime modules. |

## Construction sequence

`MmSupervisorMain` performs the following steps in order:

| Step | Operation | HOB-related effect |
| --- | --- | --- |
| 1 | Initialize MMRAM ranges and library constructors | Establishes the allocator and the inbound HOB list. |
| 2 | Discover modules in FV HOBs | Loads the supervisor and user runtime images; records other MM drivers and their DEPEX. |
| 3 | `SupvInitHobsInit` | Allocates the output region, copies retained input HOBs, and publishes its base address. |
| 4 | `SetupSmiEntryExit` | Allocates CPU resources and installs entry stubs containing the output HOB-list address. |
| 5 | `MmLoadButNotDispatch` | Loads the discovered drivers, making their allocation and entry-point information available. |
| 6 | `SupvInitHobsAddModuleAllocations` | Appends runtime/driver allocation records and per-driver DEPEX records. |
| 7 | Prepare communication buffers and initialize policy | Establishes resources needed by the handoff and runtime. |
| 8 | `SupvInitHobsAddPassDown` | Appends pointers and sizes describing initialization resources. |
| 9 | `LockMmCoreBeforeExit` | Applies initial protections and performs the remaining initialization allocations. |
| 10 | `SupvInitHobsAddMmramDescriptors` | Serializes the final MMRAM allocation map. |
| 11 | `SupvInitHobsFinalize` | Appends the end-of-HOB-list marker. |
| 12 | `PostRelocationRun` | Triggers the first MMI initialization flow. |

There are two distinct ordering requirements:

- **Stable address early:** Entry installation embeds `mMmHobStart`, so the allocation must exist before that step.
  The list is not yet complete when its address is published.
- **Final contents late:** The MMRAM map must describe allocations made by driver loading, CPU setup, policy setup,
  HOB allocation itself, and memory protection. Its final serialization therefore follows the lock step.

The external runtime must not consume a partially constructed list. Initialization allocations must not invalidate
the final memory-map snapshot after it has been serialized.

## Builder state and layout

`MM_SUPV_INIT_HOB_BUILDER` tracks:

| Field | Meaning during construction |
| --- | --- |
| `Base` | Start of the allocated output region. |
| `Cursor` | Address at which the next HOB will be written. |
| `Remaining` | Bytes still available after `Cursor`. |

After initialization and successful appends:

```text
used bytes = Cursor - Base
used bytes + Remaining = mMmHobSize
Base = mMmHobStart
```

Every record is padded to an 8-byte boundary. The region is page-aligned and allocated through
`MmAllocateSupervisorPages` as `EfiRuntimeServicesData`.

The resulting list has this shape:

```text
Retained inbound HOBs, without MMRAM hobs, in their original order
Supervisor runtime module-allocation HOB
User runtime module-allocation HOB
For each discovered MM driver:
    Module-allocation HOB
    DEPEX GUID HOB
Pass-down GUID HOB
Regenerated MMRAM-descriptor GUID HOB
End-of-HOB-list marker
Unused allocation capacity, not additional HOBs
```

`mMmHobSize` is the allocation capacity, not the populated list length. Finalization reports the used and spare sizes
in the debug log; it does not shrink the allocation.

### Retained and replaced inbound HOBs

The outgoing list is not a verbatim copy of the inbound list. The builder leaves the original list unchanged and
copies its records into a new allocation, excluding:

- GUID HOBs named `gEfiMmPeiMmramMemoryReserveGuid`.
- GUID HOBs named `gEfiSmmSmramMemoryGuid`.
- The original end-of-HOB-list marker.

Both incoming MMRAM descriptor forms are omitted from the outgoing list. After initialization allocations are complete,
`SupvInitHobsAddMmramDescriptors` replaces them with one newly generated `gEfiSmmSmramMemoryGuid` HOB containing the
final descriptors. These are derived from `gMemoryMap` and the platform MMRAM boundaries in `mMmramRanges`, so the
runtime receives the post-initialization allocation state rather than the IPL's earlier snapshot.

The end-of-HOB-list marker is also newly generated, after all output records have been appended.

Only the retained inbound records are copied byte-for-byte. For those records, the builder does not deep-copy
referenced resources or rebase embedded addresses. In particular, if the inbound list contains a HOB handoff
information table (PHIT), its memory-boundary and end-of-list fields are copied unchanged. That is separate from
rebuilding the MMRAM descriptor HOB: regenerating the MMRAM map does not update the PHIT. Consumers must distinguish
such retained metadata from the actual bounds and termination of the new list.

### Module-allocation records

Each generated module record uses `EFI_HOB_MEMORY_ALLOCATION_MODULE`, with HOB type
`EFI_HOB_TYPE_MEMORY_ALLOCATION`. It is **not** a GUID-extension HOB.

| Field | Producer value |
| --- | --- |
| `MemoryAllocationHeader.Name` | `gMmSupervisorHobMemoryAllocModuleGuid`, identifying this allocation-record convention. |
| `MemoryBaseAddress` | The loaded driver's `ImageBuffer`, which is the allocation base. |
| `MemoryLength` | `NumberOfPage` converted to bytes. |
| `MemoryType` | `EfiReservedMemoryType`. |
| `ModuleName` | `gMmSupervisorCoreGuid`, `gMmSupervisorUserGuid`, or the discovered driver's file GUID. |
| `EntryPoint` | The relocated image entry point. |

The allocation length includes the loader's reserved pages; it is not the raw PE/COFF file length.
The supervisor and user runtime entries must already be valid before this step.

### Driver DEPEX records

Each discovered MM driver receives a GUID-extension HOB named `gMmSupervisorDepexHobGuid`, following its allocation
record. The supervisor and user runtime entries do not receive these generated DEPEX HOBs.

The packed payload is `MM_SUPV_DEPEX_HOB_DATA`:

| Payload offset | Field | Meaning |
| --- | --- | --- |
| 0 | `Name` | 16-byte driver GUID, matching the module record's `ModuleName`. |
| 16 | `Length` | 64-bit byte length of the dependency expression. |
| 24 | `Data` | `Length` bytes of DEPEX data, followed by any HOB-alignment padding. |

Padding is not part of `Length`. A zero-length dependency expression still produces a record.
The initialization module transports the expression; it does not dispatch drivers according to that expression.

### Pass-down record

The GUID-extension HOB named `gMmSupervisorPassDownHobGuid` carries `MM_SUPV_PASS_DOWN_HOB_DATA`.
The current revision is **2**, and the packed payload is **64 bytes**.

| Payload offset | Field | Meaning |
| --- | --- | --- |
| 0 | `Revision` | 32-bit `MM_SUPV_PASS_DOWN_HOB_REVISION`. |
| 4 | `Reserved` | 32-bit zero. |
| 8 | `MmSupervisorCpl3StackBase` | Address of the CPL3 stack array. |
| 16 | `MmSupervisorCpl3PerCoreStackSize` | Stack stride/size for each CPU. |
| 24 | `SmBase` | Address of the per-CPU SMBASE array, not a single CPU's SMBASE value. |
| 32 | `MmInitializedBuffer` | Address of the per-CPU initialization flags. |
| 40 | `MmSupvFirmwarePolicyBuffer` | Address of the copied firmware policy. |
| 48 | `MmSupvFirmwarePolicyBufferSize` | Policy size in bytes. |
| 56 | `MmiEntrypointSize` | Size returned by `GetSmiHandlerSize`. |

All fields after `Reserved` are 64-bit. The structure contains no CPU count; consumers must use the accompanying
CPU-information contract when interpreting the arrays and stack layout.

These are references to existing allocations, not inline copies or a transfer of ownership that permits freeing them.
The producer and separately built consumer must agree on packing, field widths, revision, and resource lifetime.

### Final MMRAM descriptors

`PrepareRuntimeMmramHob` creates one GUID-extension HOB named `gEfiSmmSmramMemoryGuid`, carrying an
`EFI_SMRAM_HOB_DESCRIPTOR_BLOCK`.

The serialization uses two sources:

- `mMmramRanges`: the platform-provided MMRAM boundaries, privately copied and sorted during initialization.
- `gMemoryMap`: the allocator's current allocation map.

The helper sorts the allocation map by address, counts descriptors, reserves the record, and then repeats the same
walk to write them. The count and write passes must observe the same map and must not allocate memory.

During the walk:

1. Allocation-map entries are clipped to each MMRAM range's boundaries.
2. A merged entry spanning adjacent MMRAM ranges is emitted in pieces rather than extending a descriptor
   past a boundary.
3. `EfiRuntimeServicesCode` and `EfiRuntimeServicesData` entries receive
   `EFI_SMRAM_CLOSED | EFI_CACHEABLE | EFI_ALLOCATED`.
4. Other entries and uncovered gaps are emitted without `EFI_ALLOCATED`.

Unexpected gaps, out-of-range entries, and incompatible adjacent regions are guarded by debug assertions.
The serializer writes the same address into `CpuStart` and `PhysicalStart`; its current model assumes identity-mapped
MMRAM. It synthesizes the region flags rather than copying all input flags.

`IsSupervisorPage` is logged but is not encoded in the output descriptors. The final MMRAM HOB describes allocation
occupancy; it is not a complete privilege-ownership or page-permission policy.

## Capacity calculation and platform reserve

The initial reservation uses a platform-configurable fixed reserve:

```text
slack_bytes = EFI_PAGES_TO_SIZE (FixedPcdGet32(PcdMmSupervisorHobSlackPageCount))
capacity = AlignUp(inbound_list_bytes + early_mmram_hob_bytes, 4096) + slack_bytes
```

`inbound_list_bytes` includes the original end marker and MMRAM HOBs, even though those records are not copied.
`early_mmram_hob_bytes` is calculated before subsequent initialization allocations. The reserve covers the generated
module/DEPEX records, pass-down record, end marker, and growth from the early memory map to the final map. It is a
platform capacity choice, not an exact sizing pass, and does not require repeating discovery or image loading.

### Configuring the reserve

The PCD is declared in [MmSupervisorPkg.dec](../../MmSupervisorPkg.dec) and consumed by
[MmSupervisorInit.inf](../../Core/MmSupervisorInit.inf):

| Property | Value |
| --- | --- |
| Name | `gMmSupervisorPkgTokenSpaceGuid.PcdMmSupervisorHobSlackPageCount` |
| Access method | `FixedAtBuild` |
| Datum type | `UINT32` |
| Units | Pages, not bytes |
| Default | `1` page (4 KiB) |
| Scope | Extra HOB-list capacity for `MmSupervisorInit`, not the total buffer size or the legacy C supervisor |

For example, a platform DSC can reserve an additional 16 KiB:

```ini
[PcdsFixedAtBuild]
  gMmSupervisorPkgTokenSpaceGuid.PcdMmSupervisorHobSlackPageCount|4
```

This example is not a recommended minimum for every platform. Choose sufficient headroom for the supported driver
set, dependency expressions, CPU resources, and allocation fragmentation. Increasing the reserve consumes additional
MMRAM; the buffer is not shrunk after construction.

Prefer a multiple of `EFI_PAGE_SIZE` so that the tracked capacity matches the allocated page extent. The current
implementation adds the PCD after aligning the initial estimate. For a non-page-multiple value, the allocator rounds
up to whole pages, but the builder still limits writes to `mMmHobSize`.

Validate the chosen value across supported configurations using the finalization log:

```text
MM Supervisor Hob list complete: ... bytes used of ..., ... spare
```

Retain headroom for future additions and recheck it when the driver set or initialization allocations change.
The append helpers continue to enforce the capacity and fail initialization if it is exhausted.

### Output-size reference

For the current X64 layouts, define:

```text
G(payload) = AlignUp(24 + payload, 8)  # GUID HOB header plus payload
D[i]       = DEPEX byte length for driver i
N          = final MMRAM descriptor count
C          = bytes of retained inbound records, including their alignment

required = C
         + 2 * 72                              # supervisor and user module HOBs
         + Sum(72 + G(24 + D[i]))               # driver module and DEPEX HOBs
         + G(64)                               # pass-down HOB
         + G(8 + 32 * N)                        # final MMRAM descriptor HOB
         + 8                                   # end marker
```

This formula explains what consumes the reserved capacity; the builder does not perform a separate pass to compute
it. For example, 60 drivers with 32-byte DEPEX expressions consume `60 * (72 + 80) = 9,120` bytes for their records
alone. The platform reserve must accommodate the supported output, rather than an arbitrary number of drivers.

The allocation address remains stable after it is embedded in the entry stubs. The final MMRAM snapshot is generated
after initialization allocations, including the HOB allocation itself, so a larger build-time reserve is reflected
in that snapshot without introducing runtime resizing.

`PrepareRuntimeMmramHob` also has a sizing-query mode: with `Cursor == 0`, it returns `EFI_BUFFER_TOO_SMALL` and puts
the required size in `Remaining`. On a capacity error it likewise overwrites `Remaining` with the required size.
That error result must not be treated as the normal builder's remaining-capacity state.

## Handoff, lifetime, and validation

The [entry installer](../../../SeaPkg/Library/SmmCpuFeaturesLib/SmmStm.c) writes `mMmHobStart` into
`FIXUP64_HOB_START` for the V5 entry format. The [X64 entry stub](../../../SeaPkg/MmiEntrySeaV5/MmiEntrySeaV5.nasmb) passes:

- `RCX`: CPU index.
- `RDX`: HOB-list base.

It calls the separately loaded supervisor entry point. There is no separate HOB-size argument in this call.

The [memory-protection initialization](../../Core/Mem/SmmCpuMemoryManagementInit.c) applies read-only and
execute-protected attributes to the HOB allocation. Describing a pointer in a HOB does not itself protect the pointed-to
resource, authenticate its contents, or establish that the runtime may trust it.

The builder assumes a well-formed inbound list and valid loaded-module/resource information. It is not a general
validator for arbitrary HOB bytes. Runtime integration must define how the consumer:

- Establishes a trusted parsing bound and checks record lengths, alignment, termination, and address arithmetic.
- Handles unsupported pass-down revisions, missing records, and duplicate module identities.
- Checks DEPEX lengths against the enclosing record, excluding padding.
- Validates referenced allocations, array bounds, entry points, and lifetimes.
- Reconstructs allocation and privilege ownership without treating `EFI_ALLOCATED` as a privilege label.

## Failure handling and extension checklist

Module and pass-down producers return an error when their records cannot be appended; the main initialization path
reports the error and invokes `PANIC`. The initialization, final-map, and termination helpers invoke `PANIC` on their
fatal construction failures. Appends are not transactional: some records may already exist when a later append fails.
Do not hand a partially built list to the runtime.

`HobAppendGuid` also rejects a record whose aligned size does not fit the 16-bit `HobLength`.
The finalization log reports bytes used, total capacity, and remaining space for diagnosing capacity problems.

When extending the handoff, check:

1. Producer and consumer agree on GUIDs, record types, field offsets, and any revision change.
2. New variable-length payloads are included in the capacity budget, including padding.
3. New referenced resources are allocated before the final memory-map snapshot.
4. No pointer is published to temporary initialization storage that will be reclaimed.
5. Tests cover zero/many drivers, zero/large DEPEX, exact-fit and insufficient capacity, fragmented/adjacent MMRAM,
   and rejection of malformed or unsupported records by the consumer.
