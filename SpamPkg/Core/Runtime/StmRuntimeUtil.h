/** @file
  SMM runtime header file

  Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _STM_RUNTIME_UTIL_H_
#define _STM_RUNTIME_UTIL_H_

/**
  Helper function to check if two ranges overlap.

  @param[in] Start1    Start address of the first range.
  @param[in] Size1     Size of the first range.
  @param[in] Start2    Start address of the second range.
  @param[in] Size2     Size of the second range.
  @param[out] Overlap  TRUE if the two ranges overlap, FALSE otherwise.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  Overlap is NULL.
  @retval other error value
**/
EFI_STATUS
EFIAPI
TwoRangesOverlap (
  IN UINT64    Start1,
  IN UINT64    Size1,
  IN UINT64    Start2,
  IN UINT64    Size2,
  OUT BOOLEAN  *Overlap
  );

/**
  Helper function to check if one range is inside another.

  @param[in] Start1     Start address of the first range.
  @param[in] Size1      Size of the first range.
  @param[in] Start2     Start address of the second range.
  @param[in] Size2      Size of the second range.
  @param[out] IsInside  TRUE if the first range is inside the second range, FALSE otherwise.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  IsInside is NULL.
  @retval other error value
**/
EFI_STATUS
EFIAPI
Range1InsideRange2 (
  IN UINT64    Start1,
  IN UINT64    Size1,
  IN UINT64    Start2,
  IN UINT64    Size2,
  OUT BOOLEAN  *IsInside
  );

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length in bytes to be checked.

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
  The main validation routine for the SPAM Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then measure
  the content into TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and measure into TPM.

  @param[in]  SpamResponderData  The pointer to the SPAM_RESPONDER_DATA structure.
  @param[out] RetDigestList      The digest list of the image.
  @param[out] NewPolicy          The new policy populated by this routine.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SpamResponderReport (
  IN  SPAM_RESPONDER_DATA  *SpamResponderData,
  OUT TPML_DIGEST_VALUES   *RetDigestList,
  OUT VOID                 **NewPolicy  OPTIONAL
  );

#endif
