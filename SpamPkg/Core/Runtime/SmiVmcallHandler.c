/** @file
  SMI VMCALL handler

  Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "StmRuntime.h"

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallInitializeProtectionHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  DEBUG ((EFI_D_INFO, "STM_API_INITIALIZE_PROTECTION:\n"));
  return ERROR_STM_ALREADY_STARTED;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallStartHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  //
  // Let STM enable SMI for SMM guest
  //
  DEBUG ((EFI_D_INFO, "STM_API_START:\n"));
  if (!mGuestContextCommonSmm.GuestContextPerCpu[Index].Active) {
    mGuestContextCommonSmm.GuestContextPerCpu[Index].Active = TRUE;
    SmmSetup (Index);
    return STM_SUCCESS;
  } else {
    return ERROR_STM_ALREADY_STARTED;
  }
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallStopHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  X86_REGISTER  *Reg;

  Reg = &mGuestContextCommonSmi.GuestContextPerCpu[Index].Register;

  //
  // Launch SMM Teardown handler.
  //
  DEBUG ((EFI_D_INFO, "STM_API_STOP:\n"));
  SmmTeardown (Index);
  WriteUnaligned32 ((UINT32 *)&Reg->Rax, STM_SUCCESS);
  VmWriteN (VMCS_N_GUEST_RFLAGS_INDEX, VmReadN (VMCS_N_GUEST_RFLAGS_INDEX) & ~RFLAGS_CF);
  StmTeardown (Index);
  CpuDeadLoop ();

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallProtectResourceHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  STM_RSC     *StmResource;
  STM_RSC     *BiosResource;
  STM_STATUS  Status;
  STM_RSC     *LocalBuffer;

  // ECX:EBX - STM_RESOURCE_LIST
  AcquireSpinLock (&mHostContextCommon.SmiVmcallLock);
  DEBUG ((EFI_D_INFO, "STM_API_PROTECT_RESOURCE:\n"));

  // BiosHwResourceRequirementsPtr to local BiosResource, delay it to first ProtectResource VMCALL, because BIOS may change resource at runtime.
  if (mGuestContextCommonSmm.BiosHwResourceRequirementsPtr == 0) {
    if (!IsResourceListValid ((STM_RSC *)(UINTN)mHostContextCommon.HostContextPerCpu[0].TxtProcessorSmmDescriptor->BiosHwResourceRequirementsPtr, FALSE)) {
      DEBUG ((EFI_D_ERROR, "ValidateBiosResourceList fail!\n"));
      ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
      return ERROR_STM_MALFORMED_RESOURCE_LIST;
    }

    mGuestContextCommonSmm.BiosHwResourceRequirementsPtr = (UINT64)(UINTN)DuplicateResource ((STM_RSC *)(UINTN)mHostContextCommon.HostContextPerCpu[0].TxtProcessorSmmDescriptor->BiosHwResourceRequirementsPtr);
    RegisterBiosResource ((STM_RSC *)(UINTN)mGuestContextCommonSmm.BiosHwResourceRequirementsPtr);
  }

  //
  // Copy data to local, to prevent time of check VS time of use attack
  //
  LocalBuffer = RawDuplicateResource ((STM_RSC *)(UINTN)AddressParameter);
  if (LocalBuffer == NULL) {
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_MALFORMED_RESOURCE_LIST;
  }

  StmResource = (STM_RSC *)(UINTN)LocalBuffer;

  DumpStmResource (StmResource);

  if (!IsResourceListValid (StmResource, TRUE)) {
    DEBUG ((EFI_D_ERROR, "IsResourceListValid fail!\n"));
    RawFreeResource (LocalBuffer);
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_MALFORMED_RESOURCE_LIST;
  }

  DEBUG ((EFI_D_INFO, "IsResourceListValid pass!\n"));

  BiosResource = (STM_RSC *)(UINTN)mGuestContextCommonSmm.BiosHwResourceRequirementsPtr;
  if (IsResourceListOverlap (StmResource, BiosResource)) {
    DEBUG ((EFI_D_ERROR, "IsResourceListOverlap fail!\n"));
    RawFreeResource (LocalBuffer);
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_UNPROTECTABLE_RESOURCE;
  }

  DEBUG ((EFI_D_INFO, "IsResourceListOverlap pass!\n"));

  Status = AddProtectedResource (&mHostContextCommon.MleProtectedResource, StmResource);
  if (Status != STM_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "AddProtectedResource fail!\n"));
    RawFreeResource (LocalBuffer);
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return Status;
  }

  AddProtectedResourceWithType (&mHostContextCommon.MleProtectedTrappedIoResource, StmResource, TRAPPED_IO_RANGE);

  RegisterProtectedResource (StmResource);

  RawFreeResource (LocalBuffer);
  ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallUnprotectResourceHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  STM_RSC  *StmResource;
  STM_RSC  *LocalBuffer;

  // ECX:EBX - STM_RESOURCE_LIST
  AcquireSpinLock (&mHostContextCommon.SmiVmcallLock);
  DEBUG ((EFI_D_INFO, "STM_API_UNPROTECT_RESOURCE:\n"));

  //
  // Copy data to local, to prevent time of check VS time of use attack
  //
  LocalBuffer = RawDuplicateResource ((STM_RSC *)(UINTN)AddressParameter);
  if (LocalBuffer == NULL) {
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_MALFORMED_RESOURCE_LIST;
  }

  StmResource = (STM_RSC *)(UINTN)LocalBuffer;

  if (!IsResourceListValid (StmResource, TRUE)) {
    DEBUG ((EFI_D_ERROR, "IsResourceListValid fail!\n"));
    RawFreeResource (LocalBuffer);
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_MALFORMED_RESOURCE_LIST;
  }

  DEBUG ((EFI_D_INFO, "IsResourceListValid pass!\n"));

  DumpStmResource (StmResource);

  DeleteProtectedResource (&mHostContextCommon.MleProtectedResource, StmResource);

  UnRegisterProtectedResource (StmResource);

  RawFreeResource (LocalBuffer);
  ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallGetBiosResourcesHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  STM_RSC       *BiosResource;
  UINTN         BiosResourceSize;
  UINT32        PageNum;
  X86_REGISTER  *Reg;

  Reg = &mGuestContextCommonSmi.GuestContextPerCpu[Index].Register;

  // ECX:EBX - STM_RESOURCE_LIST
  // EDX: PageCount
  AcquireSpinLock (&mHostContextCommon.SmiVmcallLock);
  DEBUG ((EFI_D_INFO, "STM_API_GET_BIOS_RESOURCES:\n"));

  // BiosHwResourceRequirementsPtr to local BiosResource, delay it to first ProtectResource VMCALL, because BIOS may change resource at runtime.
  if (mGuestContextCommonSmm.BiosHwResourceRequirementsPtr == 0) {
    if (!IsResourceListValid ((STM_RSC *)(UINTN)mHostContextCommon.HostContextPerCpu[0].TxtProcessorSmmDescriptor->BiosHwResourceRequirementsPtr, FALSE)) {
      DEBUG ((EFI_D_ERROR, "ValidateBiosResourceList fail!\n"));
      ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
      return ERROR_STM_MALFORMED_RESOURCE_LIST;
    }

    mGuestContextCommonSmm.BiosHwResourceRequirementsPtr = (UINT64)(UINTN)DuplicateResource ((STM_RSC *)(UINTN)mHostContextCommon.HostContextPerCpu[0].TxtProcessorSmmDescriptor->BiosHwResourceRequirementsPtr);
    RegisterBiosResource ((STM_RSC *)(UINTN)mGuestContextCommonSmm.BiosHwResourceRequirementsPtr);
  }

  PageNum = (UINT32)Reg->Rdx;

  if (!IsGuestAddressValid ((UINTN)AddressParameter, STM_PAGES_TO_SIZE (PageNum + 1), TRUE)) {
    DEBUG ((EFI_D_ERROR, "Security Violation!\n"));
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_SECURITY_VIOLATION;
  }

  BiosResource     = (STM_RSC *)(UINTN)mGuestContextCommonSmm.BiosHwResourceRequirementsPtr;
  BiosResourceSize = GetSizeFromResource (BiosResource);
  if (BiosResourceSize == 0) {
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_SECURITY_VIOLATION;
  }

  DEBUG ((EFI_D_INFO, "BiosResource (%d) - %016lx(%08x), PageCount - %d\n", (UINTN)Index, (UINT64)(UINTN)BiosResource, (UINTN)BiosResourceSize, (UINTN)PageNum));
  //  DumpStmResource (BiosResource);

  ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);

  if (PageNum >= STM_SIZE_TO_PAGES (BiosResourceSize)) {
    WriteUnaligned32 ((UINT32 *)&Reg->Rdx, 0);
    return ERROR_STM_PAGE_NOT_FOUND;
  }

  // Write data
  CopyMem (
    (VOID *)(UINTN)AddressParameter,
    (VOID *)((UINTN)BiosResource + SIZE_4KB * PageNum),
    SIZE_4KB
    );
  PageNum++;
  if (PageNum >= STM_SIZE_TO_PAGES (BiosResourceSize)) {
    WriteUnaligned32 ((UINT32 *)&Reg->Rdx, 0);
  } else {
    WriteUnaligned32 ((UINT32 *)&Reg->Rdx, PageNum);
  }

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallManageVmcsDatabaseHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  STM_VMCS_DATABASE_REQUEST  *VmcsDatabaseRequest;
  STM_STATUS                 Status;
  STM_VMCS_DATABASE_REQUEST  LocalBuffer;

  // ECX:EBX - STM_VMCS_DATABASE_REQUEST
  AcquireSpinLock (&mHostContextCommon.SmiVmcallLock);
  DEBUG ((EFI_D_INFO, "STM_API_MANAGE_VMCS_DATABASE:\n"));

  if (!IsGuestAddressValid ((UINTN)AddressParameter, sizeof (STM_VMCS_DATABASE_REQUEST), TRUE)) {
    DEBUG ((EFI_D_ERROR, "Security Violation!\n"));
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_SECURITY_VIOLATION;
  }

  //
  // Copy data to local, to prevent time of check VS time of use attack
  //
  CopyMem (&LocalBuffer, (VOID *)(UINTN)AddressParameter, sizeof (LocalBuffer));

  VmcsDatabaseRequest = (STM_VMCS_DATABASE_REQUEST *)&LocalBuffer;

  Status = RequestVmcsDatabaseEntry (
             VmcsDatabaseRequest,
             (VMCS_RECORD_STRUCTURE *)(UINTN)mHostContextCommon.VmcsDatabase
             );

  DEBUG ((EFI_D_INFO, "VMCS Database (%d) - %016lx\n", (UINTN)Index, mHostContextCommon.VmcsDatabase));

  DumpVmcsRecord (mHostContextCommon.VmcsDatabase);
  ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);

  return Status;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallEventNewLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  UINT32                            PageIndex;
  STM_EVENT_LOG_MANAGEMENT_REQUEST  *EventLogRequest;
  UINTN                             PageCount;
  UINT8                             LocalBuffer[SIZE_4KB];

  //
  // SmiVmcallManageEventLogHandler already checked [AddressParameter, sizeof(STM_EVENT_LOG_MANAGEMENT_REQUEST)]
  //
  // Use PageCount only, because other data is still in Non-SMRAM and under attack.
  //

  // ECX:EBX - STM_EVENT_LOG_MANAGEMENT_REQUEST
  EventLogRequest = (STM_EVENT_LOG_MANAGEMENT_REQUEST *)(UINTN)AddressParameter;

  PageCount = (UINTN)EventLogRequest->Data.LogBuffer.PageCount;
  if (PageCount == 0) {
    return ERROR_STM_INVALID_PAGECOUNT;
  }

  if (PageCount > ((SIZE_4KB - sizeof (STM_EVENT_LOG_MANAGEMENT_REQUEST)) / sizeof (UINT64))) {
    return ERROR_STM_INVALID_PAGECOUNT;
  }

  if (!IsGuestAddressValid ((UINTN)AddressParameter, sizeof (STM_EVENT_LOG_MANAGEMENT_REQUEST) + (PageCount - 1) * sizeof (UINT64), TRUE)) {
    DEBUG ((EFI_D_ERROR, "Security Violation!\n"));
    return ERROR_STM_SECURITY_VIOLATION;
  }

  //
  // Copy data to local, to prevent time of check VS time of use attack
  //
  CopyMem (LocalBuffer, (VOID *)(UINTN)AddressParameter, sizeof (STM_EVENT_LOG_MANAGEMENT_REQUEST) + (PageCount - 1) * sizeof (UINT64));

  // ECX:EBX - STM_EVENT_LOG_MANAGEMENT_REQUEST
  EventLogRequest = (STM_EVENT_LOG_MANAGEMENT_REQUEST *)LocalBuffer;
  //
  // Check if local copy matches previous PageCount
  //
  if (PageCount != (UINTN)EventLogRequest->Data.LogBuffer.PageCount) {
    DEBUG ((EFI_D_ERROR, "Security Violation!\n"));
    return ERROR_STM_SECURITY_VIOLATION;
  }

  DEBUG ((EFI_D_INFO, "NEW_LOG: PageCount - %x\n", PageCount));
  for (PageIndex = 0; PageIndex < PageCount; PageIndex++) {
    DEBUG ((EFI_D_INFO, "Page(%x) - %08x\n", (UINTN)PageIndex, (UINTN)EventLogRequest->Data.LogBuffer.Pages[PageIndex]));
    if (!IsGuestAddressValid ((UINTN)EventLogRequest->Data.LogBuffer.Pages[PageIndex], SIZE_4KB, TRUE)) {
      DEBUG ((EFI_D_ERROR, "Security Violation!\n"));
      return ERROR_STM_SECURITY_VIOLATION;
    }
  }

  DEBUG ((EFI_D_INFO, "\n"));

  if (mHostContextCommon.EventLog.State != EvtInvalid) {
    return ERROR_STM_LOG_ALLOCATED;
  }

  mHostContextCommon.EventLog.PageCount = EventLogRequest->Data.LogBuffer.PageCount;
  // Check page in MLE memory
  CopyMem (mHostContextCommon.EventLog.Pages, EventLogRequest->Data.LogBuffer.Pages, EventLogRequest->Data.LogBuffer.PageCount * sizeof (UINT64));

  mHostContextCommon.EventLog.State = EvtLogStopped;

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallEventConfigureLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  STM_EVENT_LOG_MANAGEMENT_REQUEST  *EventLogRequest;
  STM_EVENT_LOG_MANAGEMENT_REQUEST  LocalBuffer;

  //
  // Copy data to local, to prevent time of check VS time of use attack
  //
  CopyMem (&LocalBuffer, (VOID *)(UINTN)AddressParameter, sizeof (LocalBuffer));

  // ECX:EBX - STM_EVENT_LOG_MANAGEMENT_REQUEST
  EventLogRequest = (STM_EVENT_LOG_MANAGEMENT_REQUEST *)&LocalBuffer;

  DEBUG ((EFI_D_INFO, "CONFIGURE_LOG: EventEnables - (%x)\n", (UINTN)EventLogRequest->Data.EventEnableBitmap));
  if (mHostContextCommon.EventLog.State == EvtInvalid) {
    return ERROR_STM_LOG_NOT_ALLOCATED;
  }

  if (mHostContextCommon.EventLog.State == EvtLogStarted) {
    return ERROR_STM_LOG_NOT_STOPPED;
  }

  if (EventLogRequest->Data.EventEnableBitmap >= (1 << EvtMleMax)) {
    return ERROR_STM_RESERVED_BIT_SET;
  }

  mHostContextCommon.EventLog.EventEnableBitmap = EventLogRequest->Data.EventEnableBitmap;

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallEventStartLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  LOG_ENTRY_DATA  LogEntryData;

  DEBUG ((EFI_D_INFO, "START_LOG:\n"));
  if (mHostContextCommon.EventLog.State == EvtInvalid) {
    return ERROR_STM_LOG_NOT_ALLOCATED;
  }

  if (mHostContextCommon.EventLog.State == EvtLogStarted) {
    return ERROR_STM_LOG_NOT_STOPPED;
  }

  if (mHostContextCommon.EventLog.EventEnableBitmap == 0) {
    return ERROR_STM_NO_EVENTS_ENABLED;
  }

  mHostContextCommon.EventLog.State = EvtLogStarted;
  LogEntryData.Started.Reserved     = 0;
  AddEventLog (EvtLogStarted, &LogEntryData, sizeof (LogEntryData.Started), &mHostContextCommon.EventLog);

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallEventStopLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  LOG_ENTRY_DATA  LogEntryData;

  DEBUG ((EFI_D_INFO, "STOP_LOG:\n"));
  if (mHostContextCommon.EventLog.State == EvtInvalid) {
    return ERROR_STM_LOG_NOT_ALLOCATED;
  }

  if (mHostContextCommon.EventLog.State == EvtLogStopped) {
    return ERROR_STM_LOG_NOT_STARTED;
  }

  LogEntryData.Stopped.Reserved = 0;
  AddEventLog (EvtLogStopped, &LogEntryData, sizeof (LogEntryData.Stopped), &mHostContextCommon.EventLog);
  mHostContextCommon.EventLog.State = EvtLogStopped;

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallEventClearLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  DEBUG ((EFI_D_INFO, "CLEAR_LOG:\n"));
  if (mHostContextCommon.EventLog.State == EvtInvalid) {
    return ERROR_STM_LOG_NOT_ALLOCATED;
  }

  if (mHostContextCommon.EventLog.State == EvtLogStarted) {
    return ERROR_STM_LOG_NOT_STOPPED;
  }

  ClearEventLog (&mHostContextCommon.EventLog);

  return STM_SUCCESS;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallEventDeleteLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  DEBUG ((EFI_D_INFO, "DELETE_LOG:\n"));
  if (mHostContextCommon.EventLog.State == EvtLogStarted) {
    return ERROR_STM_LOG_NOT_STOPPED;
  }

  mHostContextCommon.EventLog.State             = (UINT32)EvtInvalid;
  mHostContextCommon.EventLog.EventSerialNumber = 0;
  mHostContextCommon.EventLog.EventEnableBitmap = 0;
  mHostContextCommon.EventLog.PageCount         = 0;
  ZeroMem (mHostContextCommon.EventLog.Pages, STM_PAGES_TO_SIZE (1));

  return STM_SUCCESS;
}

STM_VMCALL_HANDLER_STRUCT  mSmiVmcallEventLogHandler[] = {
  { STM_EVENT_LOG_MANAGEMENT_REQUEST_NEW_LOG,       SmiVmcallEventNewLogHandler       },
  { STM_EVENT_LOG_MANAGEMENT_REQUEST_CONFIGURE_LOG, SmiVmcallEventConfigureLogHandler },
  { STM_EVENT_LOG_MANAGEMENT_REQUEST_START_LOG,     SmiVmcallEventStartLogHandler     },
  { STM_EVENT_LOG_MANAGEMENT_REQUEST_STOP_LOG,      SmiVmcallEventStopLogHandler      },
  { STM_EVENT_LOG_MANAGEMENT_REQUEST_CLEAR_LOG,     SmiVmcallEventClearLogHandler     },
  { STM_EVENT_LOG_MANAGEMENT_REQUEST_DELETE_LOG,    SmiVmcallEventDeleteLogHandler    },
};

/**

  This function returns SMI EventLog VMCALL handler by FuncIndex.

  @param FuncIndex         VmCall function index

  @return VMCALL Handler

**/
STM_VMCALL_HANDLER
GetSmiVmcallEventLogHandlerByIndex (
  IN UINT32  FuncIndex
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof (mSmiVmcallEventLogHandler)/sizeof (mSmiVmcallEventLogHandler[0]); Index++) {
    if (mSmiVmcallEventLogHandler[Index].FuncIndex == FuncIndex) {
      return mSmiVmcallEventLogHandler[Index].StmVmcallHandler;
    }
  }

  return NULL;
}

/**

  This function is VMCALL handler for SMI.

  @param Index             CPU index
  @param AddressParameter  Address parameter

  @return VMCALL status

**/
STM_STATUS
SmiVmcallManageEventLogHandler (
  IN UINT32  Index,
  IN UINT64  AddressParameter
  )
{
  STM_EVENT_LOG_MANAGEMENT_REQUEST  *EventLogRequest;
  STM_STATUS                        Status;
  STM_VMCALL_HANDLER                StmVmcallHandler;

  // ECX:EBX - STM_EVENT_LOG_MANAGEMENT_REQUEST
  AcquireSpinLock (&mHostContextCommon.SmiVmcallLock);
  DEBUG ((EFI_D_INFO, "STM_API_MANAGE_EVENT_LOG:\n"));

  EventLogRequest = (STM_EVENT_LOG_MANAGEMENT_REQUEST *)(UINTN)AddressParameter;

  if (!IsGuestAddressValid ((UINTN)AddressParameter, sizeof (STM_EVENT_LOG_MANAGEMENT_REQUEST), TRUE)) {
    DEBUG ((EFI_D_ERROR, "Security Violation!\n"));
    ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);
    return ERROR_STM_SECURITY_VIOLATION;
  }

  StmVmcallHandler = GetSmiVmcallEventLogHandlerByIndex (EventLogRequest->SubFunctionIndex);
  if (StmVmcallHandler == NULL) {
    // Should not happen
    DEBUG ((EFI_D_INFO, "GetSmiVmcallEventLogHandlerByIndex - %x!\n", (UINTN)EventLogRequest->SubFunctionIndex));
    CpuDeadLoop ();
    Status = ERROR_INVALID_API;
  } else {
    Status = StmVmcallHandler (Index, AddressParameter);
  }

  ReleaseSpinLock (&mHostContextCommon.SmiVmcallLock);

  return Status;
}

STM_VMCALL_HANDLER_STRUCT  mSmiVmcallHandler[] = {
  { STM_API_START,                 SmiVmcallStartHandler                },
  { STM_API_STOP,                  SmiVmcallStopHandler                 },
  { STM_API_PROTECT_RESOURCE,      SmiVmcallProtectResourceHandler      },
  { STM_API_UNPROTECT_RESOURCE,    SmiVmcallUnprotectResourceHandler    },
  { STM_API_GET_BIOS_RESOURCES,    SmiVmcallGetBiosResourcesHandler     },
  { STM_API_MANAGE_VMCS_DATABASE,  SmiVmcallManageVmcsDatabaseHandler   },
  { STM_API_INITIALIZE_PROTECTION, SmiVmcallInitializeProtectionHandler },
  { STM_API_MANAGE_EVENT_LOG,      SmiVmcallManageEventLogHandler       },
};

/**

  This function returns SMI VMCALL handler by FuncIndex.

  @param FuncIndex         VmCall function index

  @return VMCALL Handler

**/
STM_VMCALL_HANDLER
GetSmiVmcallHandlerByIndex (
  IN UINT32  FuncIndex
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof (mSmiVmcallHandler)/sizeof (mSmiVmcallHandler[0]); Index++) {
    if (mSmiVmcallHandler[Index].FuncIndex == FuncIndex) {
      return mSmiVmcallHandler[Index].StmVmcallHandler;
    }
  }

  return NULL;
}

/**

  This function is VMCALL handler for SMI.

  @param Index CPU index

**/
VOID
SmiVmcallHandler (
  IN UINT32  Index
  )
{
  X86_REGISTER        *Reg;
  STM_STATUS          Status;
  STM_VMCALL_HANDLER  StmVmcallHandler;
  UINT64              AddressParameter;

  Reg = &mGuestContextCommonSmi.GuestContextPerCpu[Index].Register;

  StmVmcallHandler = GetSmiVmcallHandlerByIndex (ReadUnaligned32 ((UINT32 *)&Reg->Rax));
  if (StmVmcallHandler == NULL) {
    DEBUG ((EFI_D_INFO, "GetSmiVmcallHandlerByIndex - %x!\n", (UINTN)ReadUnaligned32 ((UINT32 *)&Reg->Rax)));
    // Should not happen
    CpuDeadLoop ();
    Status = ERROR_INVALID_API;
  } else {
    AddressParameter = ReadUnaligned32 ((UINT32 *)&Reg->Rbx) + LShiftU64 (ReadUnaligned32 ((UINT32 *)&Reg->Rcx), 32);
    Status           = StmVmcallHandler (Index, AddressParameter);
  }

  if (Status == STM_SUCCESS) {
    VmWriteN (VMCS_N_GUEST_RFLAGS_INDEX, VmReadN (VMCS_N_GUEST_RFLAGS_INDEX) & ~RFLAGS_CF);
  } else {
    VmWriteN (VMCS_N_GUEST_RFLAGS_INDEX, VmReadN (VMCS_N_GUEST_RFLAGS_INDEX) | RFLAGS_CF);
    AddEventLogInvalidParameter (ReadUnaligned32 ((UINT32 *)&Reg->Rax));
  }

  WriteUnaligned32 ((UINT32 *)&Reg->Rax, Status);
  VmWriteN (VMCS_N_GUEST_RIP_INDEX, VmReadN (VMCS_N_GUEST_RIP_INDEX) + VmRead32 (VMCS_32_RO_VMEXIT_INSTRUCTION_LENGTH_INDEX));

  return;
}
