/** @file
  Internal header with function declarations for StandaloneRing3Shim driver

  Copyright (c), Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _STANDALONE_RING3_SHIM_H_
#define _STANDALONE_RING3_SHIM_H_

#define EFI_HANDLE_SIGNATURE  SIGNATURE_32('h','n','d','l')

///
/// IHANDLE - contains a list of protocol handles
///
typedef struct {
  UINTN         Signature;
  /// All handles list of IHANDLE
  LIST_ENTRY    AllHandles;
  /// List of PROTOCOL_INTERFACE's for this handle
  LIST_ENTRY    Protocols;
  UINTN         LocateRequest;
} IHANDLE;

#define ASSERT_IS_HANDLE(a)  ASSERT((a)->Signature == EFI_HANDLE_SIGNATURE)

#define PROTOCOL_ENTRY_SIGNATURE  SIGNATURE_32('p','r','t','e')

///
/// PROTOCOL_ENTRY - each different protocol has 1 entry in the protocol
/// database.  Each handler that supports this protocol is listed, along
/// with a list of registered notifies.
///
typedef struct {
  UINTN         Signature;
  /// Link Entry inserted to mProtocolDatabase
  LIST_ENTRY    AllEntries;
  /// ID of the protocol
  EFI_GUID      ProtocolID;
  /// All protocol interfaces
  LIST_ENTRY    Protocols;
  /// Registered notification handlers
  LIST_ENTRY    Notify;
} PROTOCOL_ENTRY;

#define PROTOCOL_INTERFACE_SIGNATURE  SIGNATURE_32('p','i','f','c')

///
/// PROTOCOL_INTERFACE - each protocol installed on a handle is tracked
/// with a protocol interface structure
///
typedef struct {
  UINTN             Signature;
  /// Link on IHANDLE.Protocols
  LIST_ENTRY        Link;
  /// Back pointer
  IHANDLE           *Handle;
  /// Link on PROTOCOL_ENTRY.Protocols
  LIST_ENTRY        ByProtocol;
  /// The protocol ID
  PROTOCOL_ENTRY    *Protocol;
  /// The interface value
  VOID              *Interface;
} PROTOCOL_INTERFACE;

#define PROTOCOL_NOTIFY_SIGNATURE  SIGNATURE_32('p','r','t','n')

///
/// PROTOCOL_NOTIFY - used for each register notification for a protocol
///
typedef struct {
  UINTN               Signature;
  PROTOCOL_ENTRY      *Protocol;
  /// All notifications for this protocol
  LIST_ENTRY          Link;
  /// Notification function
  EFI_MM_NOTIFY_FN    Function;
  /// Last position notified
  LIST_ENTRY          *Position;
} PROTOCOL_NOTIFY;

extern LIST_ENTRY  gHandleList;

EFI_STATUS
EFIAPI
CentralRing3JumpPointer (
  IN EFI_HANDLE  *DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  );

EFI_STATUS
EFIAPI
ApRing3JumpPointer (
  IN EFI_AP_PROCEDURE2  Procedure,
  IN VOID               *ProcedureArgument
  );

EFI_STATUS
EFIAPI
SyscallMmInstallConfigurationTable (
  IN  CONST EFI_MM_SYSTEM_TABLE  *SystemTable,
  IN  CONST EFI_GUID             *Guid,
  IN  VOID                       *Table,
  IN  UINTN                      TableSize
  );

EFI_STATUS
EFIAPI
MmAllocateUserPool (
  IN   EFI_MEMORY_TYPE  PoolType,
  IN   UINTN            Size,
  OUT  VOID             **Buffer
  );

EFI_STATUS
EFIAPI
MmFreeUserPool (
  IN VOID  *Buffer
  );

VOID
MmInitializeMemoryServices (
  VOID
  );

EFI_STATUS
EFIAPI
SyscallMmAllocatePages (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory
  );

EFI_STATUS
EFIAPI
SyscallMmFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages
  );

EFI_STATUS
EFIAPI
SyscallMmStartupThisAp (
  IN EFI_AP_PROCEDURE  Procedure,
  IN UINTN             CpuNumber,
  IN OUT VOID          *ProcArguments OPTIONAL
  );

EFI_STATUS
EFIAPI
SyscallMmiHandlerRegister (
  IN  EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN  CONST EFI_GUID              *HandlerType OPTIONAL,
  OUT EFI_HANDLE                  *DispatchHandle
  );

EFI_STATUS
EFIAPI
SyscallMmiHandlerUnRegister (
  IN EFI_HANDLE  DispatchHandle
  );

EFI_STATUS
EFIAPI
MmInstallUserProtocolInterface (
  IN OUT EFI_HANDLE      *UserHandle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface
  );

EFI_STATUS
EFIAPI
MmUninstallUserProtocolInterface (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol,
  IN VOID        *Interface
  );

EFI_STATUS
EFIAPI
MmHandleUserProtocol (
  IN  EFI_HANDLE  UserHandle,
  IN  EFI_GUID    *Protocol,
  OUT VOID        **Interface
  );

EFI_STATUS
EFIAPI
MmRegisterUserProtocolNotify (
  IN  CONST EFI_GUID    *Protocol,
  IN  EFI_MM_NOTIFY_FN  Function,
  OUT VOID              **Registration
  );

EFI_STATUS
EFIAPI
MmLocateHandleUser (
  IN     EFI_LOCATE_SEARCH_TYPE  SearchType,
  IN     EFI_GUID                *Protocol   OPTIONAL,
  IN     VOID                    *SearchKey  OPTIONAL,
  IN OUT UINTN                   *BufferSize,
  OUT    EFI_HANDLE              *Buffer
  );

EFI_STATUS
EFIAPI
MmLocateUserProtocol (
  IN  EFI_GUID  *Protocol,
  IN  VOID      *Registration OPTIONAL,
  OUT VOID      **Interface
  );

// -----------------------Internal Helper Functions-----------------------

EFI_STATUS
MmInstallUserProtocolInterfaceNotify (
  IN OUT EFI_HANDLE          *UserHandle,
  IN     EFI_GUID            *Protocol,
  IN     EFI_INTERFACE_TYPE  InterfaceType,
  IN     VOID                *Interface,
  IN     BOOLEAN             Notify
  );

VOID
MmNotifyUserProtocol (
  IN PROTOCOL_INTERFACE  *Prot
  );

PROTOCOL_ENTRY  *
MmFindUserProtocolEntry (
  IN EFI_GUID  *Protocol,
  IN BOOLEAN   Create
  );

PROTOCOL_INTERFACE *
MmFindUserProtocolInterface (
  IN IHANDLE   *Handle,
  IN EFI_GUID  *Protocol,
  IN VOID      *Interface
  );

PROTOCOL_INTERFACE *
MmRemoveInterfaceFromUserProtocol (
  IN IHANDLE   *Handle,
  IN EFI_GUID  *Protocol,
  IN VOID      *Interface
  );

// -----------------------Shim Event Broadcaster-----------------------

typedef struct {
  EFI_MM_HANDLER_ENTRY_POINT    Handler;
  EFI_GUID                      *HandlerType;
  EFI_HANDLE                    DispatchHandle;
  BOOLEAN                       UnRegister;
} MM_SHIM_MMI_HANDLERS;

EFI_STATUS
EFIAPI
MmExitBootServiceHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  );

EFI_STATUS
EFIAPI
MmReadyToBootHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  );

EFI_STATUS
EFIAPI
MmReadyToLockHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  );

EFI_STATUS
EFIAPI
MmEndOfDxeHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  );

#endif
