/** @file
  MMI management.

  Copyright (c) 2009 - 2013, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MmSupervisorCore.h"
#include "PrivilegeMgmt/PrivilegeMgmt.h"
#include "Mem/Mem.h"

//
// mMmiManageCallingDepth is used to track the depth of recursive calls of MmiManage.
//
UINTN  mMmiManageCallingDepth = 0;

LIST_ENTRY  mMmiEntryList = INITIALIZE_LIST_HEAD_VARIABLE (mMmiEntryList);
MMI_ENTRY   mRootMmiEntry = {
  MMI_ENTRY_SIGNATURE,
  INITIALIZE_LIST_HEAD_VARIABLE (mRootMmiEntry.AllEntries),
  { 0 },
  INITIALIZE_LIST_HEAD_VARIABLE (mRootMmiEntry.MmiHandlers),
};

/**
  Remove MmiHandler and free the memory it used.
  If MmiEntry is empty, remove MmiEntry and free the memory it used.

  @param  MmiHandler  Points to MMI handler.
  @param  MmiEntry    Points to MMI Entry or NULL for root MMI handlers.

  @retval TRUE        MmiEntry is removed.
  @retval FALSE       MmiEntry is not removed.
**/
BOOLEAN
RemoveMmiHandler (
  IN MMI_HANDLER  *MmiHandler,
  IN MMI_ENTRY    *MmiEntry
  )
{
  ASSERT (MmiHandler->ToRemove);
  RemoveEntryList (&MmiHandler->Link);
  FreePool (MmiHandler);

  //
  // Remove the MMI_ENTRY if all handlers have been removed.
  //
  if (MmiEntry != NULL) {
    if (IsListEmpty (&MmiEntry->MmiHandlers)) {
      RemoveEntryList (&MmiEntry->AllEntries);
      FreePool (MmiEntry);
      return TRUE;
    }
  }

  return FALSE;
}

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
  LIST_ENTRY   *EntryLink;
  MMI_ENTRY    *MmiEntry;
  MMI_HANDLER  *MmiHandler;
  EFI_STATUS   ReturnStatus;
  BOOLEAN      WillReturn;
  BOOLEAN      SupervisorPath;
  EFI_STATUS   Status;
  BOOLEAN      IsUserRange;

  PERF_FUNCTION_BEGIN ();

  mMmiManageCallingDepth++;
  Status         = EFI_NOT_FOUND;
  ReturnStatus   = Status;
  SupervisorPath = FALSE;

  if ((CommBuffer != NULL) && (CommBufferSize == NULL)) {
    goto Done;
  }

  if (CommBuffer == NULL) {
    // Normal asynchronous SMI will be user path only
    SupervisorPath = FALSE;
  } else {
    // Determine if the communicate buffer is supervisor or user pages
    Status = InspectTargetRangeOwnership ((EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer, *CommBufferSize, &IsUserRange);
    if (EFI_ERROR (Status)) {
      Status = EFI_NOT_FOUND;
      goto Done;
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
      Status = EFI_NOT_FOUND;
      goto Done;
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
          ReturnStatus = EFI_INTERRUPT_PENDING;
          WillReturn   = TRUE;
        } else {
          //
          // If any other handler's result sets ReturnStatus as EFI_SUCCESS, the return status
          // will be EFI_SUCCESS.
          //
          if (ReturnStatus != EFI_SUCCESS) {
            ReturnStatus = Status;
          }
        }

        break;

      case EFI_SUCCESS:
        //
        // If at least one of the handlers returns EFI_SUCCESS then the function will return
        // EFI_SUCCESS. If a handler returns EFI_SUCCESS and HandlerType is not NULL then no
        // additional handlers will be processed.
        //
        if (HandlerType != NULL) {
          WillReturn = TRUE;
        }

        ReturnStatus = EFI_SUCCESS;
        break;

      case EFI_WARN_INTERRUPT_SOURCE_QUIESCED:
        //
        // If at least one of the handlers returns EFI_WARN_INTERRUPT_SOURCE_QUIESCED
        // then the function will return EFI_SUCCESS.
        //
        ReturnStatus = EFI_SUCCESS;
        break;

      case EFI_WARN_INTERRUPT_SOURCE_PENDING:
        //
        // If all the handlers returned EFI_WARN_INTERRUPT_SOURCE_PENDING
        // then EFI_WARN_INTERRUPT_SOURCE_PENDING will be returned.
        //
        if (ReturnStatus != EFI_SUCCESS) {
          ReturnStatus = Status;
        }

        break;

      default:
        //
        // Unexpected status code returned.
        //
        ASSERT_EFI_ERROR (Status);
        break;
    }

    if (WillReturn) {
      break;
    }
  }

  if (mMmiManageCallingDepth == 0) {
    PANIC ("MmiManage: MMI manage calling depth reaching 0!!!\n");
  }

  mMmiManageCallingDepth--;

  //
  // MmiHandlerUnRegister() calls from MMI handlers are deferred till this point.
  // Before returned from MmiManage, delete the MmiHandler which is
  // marked as ToRemove.
  // Note that MmiManage can be called recursively.
  //
  if (mMmiManageCallingDepth == 0) {
    //
    // Go through all MmiHandler in root Mmi handlers
    //
    for ( Link = GetFirstNode (&mRootMmiEntry.MmiHandlers)
          ; !IsNull (&mRootMmiEntry.MmiHandlers, Link);
          )
    {
      //
      // MmiHandler might be removed in below, so cache the next link in Link
      //
      MmiHandler = CR (Link, MMI_HANDLER, Link, MMI_HANDLER_SIGNATURE);
      Link       = GetNextNode (&mRootMmiEntry.MmiHandlers, Link);
      if (MmiHandler->ToRemove) {
        //
        // Remove MmiHandler if the ToRemove is set.
        //
        RemoveMmiHandler (MmiHandler, NULL);
      }
    }

    //
    // Go through all MmiHandler in non-root MMI handlers
    //
    for ( EntryLink = GetFirstNode (&mMmiEntryList)
          ; !IsNull (&mMmiEntryList, EntryLink);
          )
    {
      //
      // MmiEntry might be removed in below, so cache the next link in EntryLink
      //
      MmiEntry  = CR (EntryLink, MMI_ENTRY, AllEntries, MMI_ENTRY_SIGNATURE);
      EntryLink = GetNextNode (&mMmiEntryList, EntryLink);
      for ( Link = GetFirstNode (&MmiEntry->MmiHandlers)
            ; !IsNull (&MmiEntry->MmiHandlers, Link);
            )
      {
        //
        // MmiHandler might be removed in below, so cache the next link in Link
        //
        MmiHandler = CR (Link, MMI_HANDLER, Link, MMI_HANDLER_SIGNATURE);
        Link       = GetNextNode (&MmiEntry->MmiHandlers, Link);
        if (MmiHandler->ToRemove) {
          //
          // Remove MmiHandler if the ToRemove is set.
          //
          if (RemoveMmiHandler (MmiHandler, MmiEntry)) {
            break;
          }
        }
      }
    }
  }

Done:
  PERF_FUNCTION_END ();
  return ReturnStatus;
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
  MmiHandler->ToRemove     = FALSE;
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
  Unregister a handler in MM with specified ownership.

  @param  DispatchHandle        The handle that was specified when the handler was registered.
  @param  IsSupervisorHandler   The flag to indicate this is intending to unregister user or
                                supervisor handler.

  @retval EFI_SUCCESS           Handler function was successfully unregistered.
  @retval EFI_INVALID_PARAMETER DispatchHandle does not refer to a valid handle or the ownership
                                of DispatchHandle mismatches with IsSupervisorHandler.

**/
EFI_STATUS
EFIAPI
MmiHandlerUnRegisterEx (
  IN EFI_HANDLE  DispatchHandle,
  IN BOOLEAN     IsSupervisorHandler
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

  if (((EFI_HANDLE)MmiHandler != DispatchHandle) || (MmiHandler->IsSupervisor != IsSupervisorHandler)) {
    return EFI_INVALID_PARAMETER;
  }

  MmiHandler->ToRemove = TRUE;
  if (mMmiManageCallingDepth > 0) {
    //
    // This function is called from MmiManage()
    // Do not delete or remove MmiHandler or MmiEntry now.
    //
    return EFI_SUCCESS;
  }

  MmiEntry = MmiHandler->MmiEntry;
  RemoveMmiHandler (MmiHandler, MmiEntry);

  return EFI_SUCCESS;
}

/**
  Unregister a handler in MM owned by supervisor.

  @param  DispatchHandle  The handle that was specified when the handler was registered.

  @retval EFI_SUCCESS           Handler function was successfully unregistered.
  @retval EFI_INVALID_PARAMETER DispatchHandle does not refer to a valid handle.

**/
EFI_STATUS
EFIAPI
MmiHandlerSupvUnRegister (
  IN  EFI_HANDLE  DispatchHandle
  )
{
  return MmiHandlerUnRegisterEx (DispatchHandle, TRUE);
}

/**
  Unregister a handler in MM owned by users.

  @param  DispatchHandle  The handle that was specified when the handler was registered.

  @retval EFI_SUCCESS           Handler function was successfully unregistered.
  @retval EFI_INVALID_PARAMETER DispatchHandle does not refer to a valid handle.

**/
EFI_STATUS
EFIAPI
MmiHandlerUserUnRegister (
  IN  EFI_HANDLE  DispatchHandle
  )
{
  return MmiHandlerUnRegisterEx (DispatchHandle, FALSE);
}
