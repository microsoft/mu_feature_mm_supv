/** @file
  MMI management.

  Copyright (c) 2009 - 2013, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"
#include "Mem/Mem.h"

LIST_ENTRY  mMmiEntryList = INITIALIZE_LIST_HEAD_VARIABLE (mMmiEntryList);
MMI_ENTRY   mRootMmiEntry = {
  MMI_ENTRY_SIGNATURE,
  INITIALIZE_LIST_HEAD_VARIABLE (mRootMmiEntry.AllEntries),
  { 0 },
  INITIALIZE_LIST_HEAD_VARIABLE (mRootMmiEntry.MmiHandlers),
};

/**
  Finds the MMI entry for the requested handler type.

  @param  HandlerType            The type of the interrupt
  @param  Create                 Create a new entry if not found

  @return MMI entry

**/
MMI_ENTRY  *
EFIAPI
MmCoreFindMmiEntry (
  IN EFI_GUID  *HandlerType,
  IN BOOLEAN   Create
  )
{
  LIST_ENTRY  *Link;
  MMI_ENTRY   *Item;
  MMI_ENTRY   *MmiEntry;

  //
  // Search the MMI entry list for the matching GUID
  //
  MmiEntry = NULL;
  for (Link = mMmiEntryList.ForwardLink;
       Link != &mMmiEntryList;
       Link = Link->ForwardLink)
  {
    Item = CR (Link, MMI_ENTRY, AllEntries, MMI_ENTRY_SIGNATURE);
    if (CompareGuid (&Item->HandlerType, HandlerType)) {
      //
      // This is the MMI entry
      //
      MmiEntry = Item;
      break;
    }
  }

  //
  // If the protocol entry was not found and Create is TRUE, then
  // allocate a new entry
  //
  if ((MmiEntry == NULL) && Create) {
    MmiEntry = AllocatePool (sizeof (MMI_ENTRY));
    if (MmiEntry != NULL) {
      //
      // Initialize new MMI entry structure
      //
      MmiEntry->Signature = MMI_ENTRY_SIGNATURE;
      CopyGuid ((VOID *)&MmiEntry->HandlerType, HandlerType);
      InitializeListHead (&MmiEntry->MmiHandlers);

      //
      // Add it to MMI entry list
      //
      InsertTailList (&mMmiEntryList, &MmiEntry->AllEntries);
    }
  }

  return MmiEntry;
}

/**
  Manage MMI of a particular type.

  @param  HandlerType    Points to the handler type or NULL for root MMI handlers.
  @param  Context        Points to an optional context buffer.
  @param  CommBuffer     Points to the optional communication buffer.
  @param  CommBufferSize Points to the size of the optional communication buffer.

  @retval EFI_WARN_INTERRUPT_SOURCE_PENDING  Interrupt source was processed successfully but not quiesced.
  @retval EFI_INTERRUPT_PENDING              One or more MMI sources could not be quiesced.
  @retval EFI_NOT_FOUND                      Interrupt source was not handled or quiesced.
  @retval EFI_SUCCESS                        Interrupt source was handled and quiesced.

**/
EFI_STATUS
EFIAPI
MmiManage (
  IN     CONST EFI_GUID  *HandlerType,
  IN     CONST VOID      *Context         OPTIONAL,
  IN OUT VOID            *CommBuffer      OPTIONAL,
  IN OUT UINTN           *CommBufferSize  OPTIONAL
  )
{
  LIST_ENTRY   *Link;
  LIST_ENTRY   *Head;
  MMI_ENTRY    *MmiEntry;
  MMI_HANDLER  *MmiHandler;
  BOOLEAN      SuccessReturn;
  BOOLEAN      SupervisorPath;
  EFI_STATUS   Status;
  BOOLEAN      IsUserRange;

  Status         = EFI_NOT_FOUND;
  SuccessReturn  = FALSE;
  SupervisorPath = FALSE;

  if ((CommBuffer != NULL) && (CommBufferSize == NULL)) {
    return EFI_NOT_FOUND;
  }

  if (CommBuffer == NULL) {
    // Normal asynchronous SMI will be user path only
    SupervisorPath = FALSE;
  } else {
    // Determine if the communicate buffer is supervisor or user pages
    Status = InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer, *CommBufferSize, &IsUserRange);
    if (EFI_ERROR (Status)) {
      return EFI_NOT_FOUND;
    }

    SupervisorPath = !IsUserRange;
  }

  if (HandlerType == NULL) {
    //
    // Root MMI handler
    //

    MmiEntry = &mRootMmiEntry;
  } else {
    //
    // Non-root MMI handler
    //
    MmiEntry = MmCoreFindMmiEntry ((EFI_GUID *)HandlerType, FALSE);
    if (MmiEntry == NULL) {
      //
      // There is no handler registered for this interrupt source
      //
      return Status;
    }
  }

  Head = &MmiEntry->MmiHandlers;

  for (Link = Head->ForwardLink; Link != Head; Link = Link->ForwardLink) {
    MmiHandler = CR (Link, MMI_HANDLER, Link, MMI_HANDLER_SIGNATURE);

    if (!SupervisorPath && !MmiHandler->IsSupervisor) {
      Status = InvokeDemotedMmHandler (
                 MmiHandler,
                 Context,
                 CommBuffer,
                 CommBufferSize
                 );
    } else if (SupervisorPath && MmiHandler->IsSupervisor) {
      Status = MmiHandler->Handler (
                             (EFI_HANDLE)MmiHandler,
                             Context,
                             CommBuffer,
                             CommBufferSize
                             );
    } else {
      // We do not dispatch supervisor handlers during user channel and vice versa
      continue;
    }

    switch (Status) {
      case EFI_INTERRUPT_PENDING:
        //
        // If a handler returns EFI_INTERRUPT_PENDING and HandlerType is not NULL then
        // no additional handlers will be processed and EFI_INTERRUPT_PENDING will be returned.
        //
        if (HandlerType != NULL) {
          return EFI_INTERRUPT_PENDING;
        }

        break;

      case EFI_SUCCESS:
        //
        // If at least one of the handlers returns EFI_SUCCESS then the function will return
        // EFI_SUCCESS. If a handler returns EFI_SUCCESS and HandlerType is not NULL then no
        // additional handlers will be processed.
        //
        if (HandlerType != NULL) {
          return EFI_SUCCESS;
        }

        SuccessReturn = TRUE;
        break;

      case EFI_WARN_INTERRUPT_SOURCE_QUIESCED:
        //
        // If at least one of the handlers returns EFI_WARN_INTERRUPT_SOURCE_QUIESCED
        // then the function will return EFI_SUCCESS.
        //
        SuccessReturn = TRUE;
        break;

      case EFI_WARN_INTERRUPT_SOURCE_PENDING:
        //
        // If all the handlers returned EFI_WARN_INTERRUPT_SOURCE_PENDING
        // then EFI_WARN_INTERRUPT_SOURCE_PENDING will be returned.
        //
        break;

      default:
        //
        // Unexpected status code returned.
        //
        ASSERT_EFI_ERROR (Status);
        break;
    }
  }

  if (SuccessReturn) {
    Status = EFI_SUCCESS;
  }

  return Status;
}

/**
  Registers a handler to execute within MM.

  @param  Handler             Handler service function pointer.
  @param  HandlerType         Points to the handler type or NULL for root MMI handlers.
  @param  DispatchHandle      On return, contains a unique handle which can be used to later unregister the handler function.
  @param  IsSupervisorHandler Ownership of the target handler. User handlers will be dispatched after privilege demotion.

  @retval EFI_SUCCESS           Handler register success.
  @retval EFI_INVALID_PARAMETER Handler or DispatchHandle is NULL.

**/
EFI_STATUS
EFIAPI
CoreMmiHandlerRegister (
  IN  EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN  CONST EFI_GUID              *HandlerType  OPTIONAL,
  OUT EFI_HANDLE                  *DispatchHandle,
  IN  BOOLEAN                     IsSupervisorHandler
  )
{
  MMI_HANDLER  *MmiHandler;
  MMI_ENTRY    *MmiEntry;
  LIST_ENTRY   *List;

  if ((Handler == NULL) || (DispatchHandle == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  MmiHandler = AllocateZeroPool (sizeof (MMI_HANDLER));
  if (MmiHandler == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  MmiHandler->Signature    = MMI_HANDLER_SIGNATURE;
  MmiHandler->Handler      = Handler;
  MmiHandler->IsSupervisor = IsSupervisorHandler;

  if (HandlerType == NULL) {
    //
    // This is root MMI handler
    //
    MmiEntry = &mRootMmiEntry;
  } else {
    //
    // None root MMI handler
    //
    MmiEntry = MmCoreFindMmiEntry ((EFI_GUID *)HandlerType, TRUE);
    if (MmiEntry == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  List = &MmiEntry->MmiHandlers;

  MmiHandler->MmiEntry = MmiEntry;
  InsertTailList (List, &MmiHandler->Link);

  *DispatchHandle = (EFI_HANDLE)MmiHandler;

  return EFI_SUCCESS;
}

/**
  Registers a supervisor handler to execute within MM. This handler will not be demoted when dispatched.

  @param  Handler        Handler service function pointer.
  @param  HandlerType    Points to the handler type or NULL for root MMI handlers.
  @param  DispatchHandle On return, contains a unique handle which can be used to later unregister the handler function.

  @retval EFI_SUCCESS           Handler register success.
  @retval EFI_INVALID_PARAMETER Handler or DispatchHandle is NULL.

**/
EFI_STATUS
EFIAPI
MmiSupvHandlerRegister (
  IN   EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN   CONST EFI_GUID              *HandlerType  OPTIONAL,
  OUT  EFI_HANDLE                  *DispatchHandle
  )
{
  return CoreMmiHandlerRegister (Handler, HandlerType, DispatchHandle, TRUE);
}

/**
  Registers a user handler to execute within MM. This handler will be demoted when dispatched.

  @param  Handler        Handler service function pointer.
  @param  HandlerType    Points to the handler type or NULL for root MMI handlers.
  @param  DispatchHandle On return, contains a unique handle which can be used to later unregister the handler function.

  @retval EFI_SUCCESS           Handler register success.
  @retval EFI_INVALID_PARAMETER Handler or DispatchHandle is NULL.

**/
EFI_STATUS
EFIAPI
MmiUserHandlerRegister (
  IN   EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN   CONST EFI_GUID              *HandlerType  OPTIONAL,
  OUT  EFI_HANDLE                  *DispatchHandle
  )
{
  return CoreMmiHandlerRegister (Handler, HandlerType, DispatchHandle, FALSE);
}

/**
  Unregister a handler in MM.

  @param  DispatchHandle  The handle that was specified when the handler was registered.

  @retval EFI_SUCCESS           Handler function was successfully unregistered.
  @retval EFI_INVALID_PARAMETER DispatchHandle does not refer to a valid handle.

**/
EFI_STATUS
EFIAPI
MmiHandlerUnRegister (
  IN EFI_HANDLE  DispatchHandle
  )
{
  MMI_HANDLER  *MmiHandler;
  MMI_ENTRY    *MmiEntry;
  LIST_ENTRY   *EntryLink;
  LIST_ENTRY   *HandlerLink;

  if (DispatchHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Look for it in root MMI handlers
  //
  MmiHandler = NULL;
  for ( HandlerLink = GetFirstNode (&mRootMmiEntry.MmiHandlers)
        ; !IsNull (&mRootMmiEntry.MmiHandlers, HandlerLink) && ((EFI_HANDLE)MmiHandler != DispatchHandle)
        ; HandlerLink = GetNextNode (&mRootMmiEntry.MmiHandlers, HandlerLink)
        )
  {
    MmiHandler = CR (HandlerLink, MMI_HANDLER, Link, MMI_HANDLER_SIGNATURE);
  }

  //
  // Look for it in non-root MMI handlers
  //
  for ( EntryLink = GetFirstNode (&mMmiEntryList)
        ; !IsNull (&mMmiEntryList, EntryLink) && ((EFI_HANDLE)MmiHandler != DispatchHandle)
        ; EntryLink = GetNextNode (&mMmiEntryList, EntryLink)
        )
  {
    MmiEntry = CR (EntryLink, MMI_ENTRY, AllEntries, MMI_ENTRY_SIGNATURE);
    for ( HandlerLink = GetFirstNode (&MmiEntry->MmiHandlers)
          ; !IsNull (&MmiEntry->MmiHandlers, HandlerLink) && ((EFI_HANDLE)MmiHandler != DispatchHandle)
          ; HandlerLink = GetNextNode (&MmiEntry->MmiHandlers, HandlerLink)
          )
    {
      MmiHandler = CR (HandlerLink, MMI_HANDLER, Link, MMI_HANDLER_SIGNATURE);
    }
  }

  if ((EFI_HANDLE)MmiHandler != DispatchHandle) {
    return EFI_INVALID_PARAMETER;
  }

  MmiEntry = MmiHandler->MmiEntry;

  RemoveEntryList (&MmiHandler->Link);
  FreePool (MmiHandler);

  if (MmiEntry == NULL) {
    //
    // This is root MMI handler
    //
    return EFI_SUCCESS;
  }

  if (IsListEmpty (&MmiEntry->MmiHandlers)) {
    //
    // No handler registered for this interrupt now, remove the MMI_ENTRY
    //
    RemoveEntryList (&MmiEntry->AllEntries);

    FreePool (MmiEntry);
  }

  return EFI_SUCCESS;
}
