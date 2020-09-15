
# @file
# unit tests for policy_entry
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

from policy_entry import *
import unittest


class TestAccessType(unittest.TestCase):

    READ_STR = AccessType.bits[0]
    WRITE_STR = AccessType.bits[1]
    EXECUTE_STR = AccessType.bits[2]
    STRICT_WIDTH_STR = AccessType.bits[3]
    COND_READ_STR = AccessType.bits[4]
    COND_WRITE_STR = AccessType.bits[5]
    INHERITED_STR = "INHERITED"

    def test_valid_Read_Inherited(self):
        a = AccessType(AccessType.READ_INHERITED)
        self.assertEqual(a.value, AccessType.READ_INHERITED)
        self.assertEqual(str(a), self.READ_STR)

    def test_valid_Write_Inherited(self):
        a = AccessType(AccessType.WRITE_INHERITED)
        self.assertEqual(a.value, AccessType.WRITE_INHERITED)
        self.assertEqual(str(a), self.WRITE_STR)

    def test_valid_Execute_Inherited(self):
        a = AccessType(AccessType.EXECUTE_INHERITED)
        self.assertEqual(a.value, AccessType.EXECUTE_INHERITED)
        self.assertEqual(str(a), self.EXECUTE_STR)

    def test_valid_Strict_Width_Inherited(self):
        a = AccessType(AccessType.STRICT_WIDTH_INHERITED)
        self.assertEqual(a.value, AccessType.STRICT_WIDTH_INHERITED)
        self.assertEqual(str(a), self.STRICT_WIDTH_STR)

    def test_valid_Inherited(self):
        a = AccessType(AccessType.INHERITED)
        self.assertEqual(a.value, AccessType.INHERITED)
        self.assertEqual(str(a), self.INHERITED_STR)

    def test_valid_Cond_Read(self):
        a = AccessType(AccessType.COND_READ_INHERITED)
        self.assertEqual(a.value, AccessType.COND_READ_INHERITED)
        self.assertEqual(str(a), self.COND_READ_STR)

    def test_valid_Cond_Write(self):
        a = AccessType(AccessType.COND_WRITE_INHERITED)
        self.assertEqual(a.value, AccessType.COND_WRITE_INHERITED)
        self.assertEqual(str(a), self.COND_WRITE_STR)

    def test_invalid_value(self):
        with self.assertRaises(Exception) as context:
            a = AccessType(6789)
        self.assertTrue(str(context.exception).startswith("Invalid value"))

    def test_valid_ReadWrite_Inherited(self):
        a = AccessType(AccessType.WRITE_INHERITED | AccessType.READ_INHERITED)
        self.assertEqual(a.value, AccessType.WRITE_INHERITED +
                         AccessType.READ_INHERITED)
        self.assertIn(self.READ_STR, str(a))
        self.assertIn(self.WRITE_STR, str(a))
        self.assertIn("|", str(a))
        self.assertNotIn(self.EXECUTE_STR, str(a))

    def test_valid_Cond_ReadWrite_Inherited(self):
        a = AccessType(AccessType.COND_WRITE_INHERITED | AccessType.COND_READ_INHERITED)
        self.assertEqual(a.value, AccessType.COND_WRITE_INHERITED +
                         AccessType.COND_READ_INHERITED)
        self.assertIn(self.COND_READ_STR, str(a))
        self.assertIn(self.COND_WRITE_STR, str(a))
        self.assertIn("|", str(a))
        self.assertNotIn(self.EXECUTE_STR, str(a))


class TestMemoryPolicyEntry(unittest.TestCase):

    def test_valid_memory_policy_entry(self):
        a = MemoryPolicyEntry(BaseAddress=0x1000,
                              Size=0x1000, MemoryAttributes=0x12345678)
        self.assertEqual(a.BaseAddress, 0x1000)
        self.assertEqual(a.Size, 0x1000)
        self.assertEqual(a.MemoryAttributes, 0x12345678)
        self.assertEqual(a.GetType(), POLICY_TYPE.MEMORY)
        a.Encode()

    def test_invalid_memory_policy_entry(self):
        a = MemoryPolicyEntry()
        with self.assertRaises(Exception) as context:
            a.Encode()
        self.assertTrue(str(context.exception).startswith("Invalid Data"))


class TestIoPolicyEntry(unittest.TestCase):

    def test_valid_io_policy_entry(self):
        a = IoPolicyEntry(IoAddress=100,
                          Size=4, Attributes=AccessType.WRITE_INHERITED)
        self.assertEqual(a.IoAddress, 100)
        self.assertEqual(a.Size, 4)
        self.assertEqual(a.Attributes.value, AccessType(
            AccessType.WRITE_INHERITED).value)
        self.assertEqual(a.GetType(), POLICY_TYPE.IO)
        a.Encode()

    def test_invalid_io_policy_entry(self):
        a = IoPolicyEntry()
        with self.assertRaises(Exception) as context:
            a.Encode()
        self.assertTrue(str(context.exception).startswith("Invalid Data"))


class TestMsrPolicyEntry(unittest.TestCase):

    def test_valid_msr_policy_entry(self):
        a = MsrPolicyEntry(MsrAddress=0xC0012000,
                           Size=4, Attributes=(AccessType.READ_INHERITED + AccessType.WRITE_INHERITED))
        self.assertEqual(a.MsrAddress, 0xC0012000)
        self.assertEqual(a.Size, 4)
        self.assertEqual(a.Attributes.value,
                         AccessType.READ_INHERITED | AccessType.WRITE_INHERITED)
        self.assertEqual(a.GetType(), POLICY_TYPE.MSR)
        a.Encode()

    def test_invalid_msr_policy_entry(self):
        a = MsrPolicyEntry()
        with self.assertRaises(Exception) as context:
            a.Encode()
        self.assertTrue(str(context.exception).startswith("Invalid Data"))


class TestInstructionPolicyEntry(unittest.TestCase):

    def test_valid_instruction_policy_entry(self):
        a = InstructionPolicyEntry(InstructionName='WBINVD',
                                   Attributes=(AccessType.INHERITED))
        self.assertEqual(a.InstructionIndex, 0x01)
        self.assertEqual(a.Attributes.value,
                         AccessType.INHERITED)
        self.assertEqual(a.GetType(), POLICY_TYPE.INSTRUCTION)
        a.Encode()

    def test_invalid_instruction_policy_entry(self):
        a = InstructionPolicyEntry()
        with self.assertRaises(Exception) as context:
            a.Encode()
        self.assertTrue(str(context.exception).startswith("Invalid Data"))


class TestSaveStatePolicyEntry(unittest.TestCase):

    def test_valid_save_state_policy_entry(self):
        SaveStateName = 'RAX'
        Condition = 'IoWrite'
        a = SaveStatePolicyEntry(SaveStateFieldName=SaveStateName,
                                Attributes=(AccessType.COND_READ_INHERITED),
                                AccessCondition=Condition)
        self.assertEqual(a.SaveStateIndex,
                         int(ALLOWED_SAVE_STATE_FIELD[SaveStateName.upper()]))
        self.assertEqual(a.Attributes.value,
                         AccessType.COND_READ_INHERITED)
        self.assertEqual(a.AccessCondition,
                         int(ALLOWED_SAVE_STATE_ACCESS_CONDITION[Condition.upper()]))
        self.assertEqual(a.GetType(), POLICY_TYPE.SAVESTATE)
        a.Encode()

    def test_invalid_save_state_policy_entry(self):
        a = SaveStatePolicyEntry()
        with self.assertRaises(Exception) as context:
            a.Encode()
        self.assertTrue(str(context.exception).startswith("Invalid Data"))


class TestPolicyRoot(unittest.TestCase):

    def test_valid_policy_root(self):
        a = PolicyRoot(Type = POLICY_TYPE.MSR, AccessAttr = AccessAttribute.ACCESS_ATTR_DENY)
        self.assertEqual(a.GetType(), POLICY_TYPE.MSR)
        self.assertEqual(a.AccessAttr.value, AccessAttribute.ACCESS_ATTR_DENY)
        self.assertEqual(a.Count, 0)

        b = MsrPolicyEntry(MsrAddress=0xC0012000,
                           Size=4, Attributes=(AccessType.READ_INHERITED + AccessType.WRITE_INHERITED))
        a.AddPolicy (b)
        a.Encode()

    def test_invalid_policy_root(self):
        a = PolicyRoot()
        with self.assertRaises(Exception) as context:
            a.Encode()
        self.assertTrue(str(context.exception).startswith("Invalid Data"))


class TestSupervisorPolicy(unittest.TestCase):

    # 0 Memory policies
    # 2 IO policies
    # 3 MSR policies
    # 2 Instruction policies
    VALID_LEGACY_POLICY = '02000000a8000000280000000000000028000000020000004c000000030000008800000002000000010000000200000012000000f80c04000a00010000000200000012000000fc0c04000200010000000300000014000000800000c004000600010000000300000014000000100001c004000600010000000300000014000000110101c0080006000100000004000000100000000100000001000000040000001000000002000000'

    # 0 Memory policies
    # 2 IO policies
    # 3 MSR policies
    # 2 Instruction policies
    # 1 SaveState policies
    VALID_POLICY = '00000100E80000000000000000000000000000000000000000000000000000002800000005000000010000001800000002000000A00000000200000001000000010000001800000003000000B00000000300000001000000010000001800000004000000C80000000200000000000000010000001800000005000000D80000000100000000000000010000001800000001000000E80000000000000001000000F80C04000A000000FC0C040002000000800000C001000700810000C004000700100001C0010007000000040000000000010004000000000000000000100000000200000000000000'

    def test_valid_legacy_policy(self):
        a = Supervisor_Policy()
        a.Decode(bytes.fromhex(self.VALID_LEGACY_POLICY))
        self.assertEqual(a.Version, 2)
        self.assertEqual(len(a.PolicyRoots), 3)
        for pr in a.PolicyRoots:
            if pr.GetType() == POLICY_TYPE.IO:
                self.assertEqual(len(pr.PolicyEntries), 2)
            elif pr.GetType() == POLICY_TYPE.MSR:
                self.assertEqual(len(pr.PolicyEntries), 3)
            elif pr.GetType() == POLICY_TYPE.INSTRUCTION:
                self.assertEqual(len(pr.PolicyEntries), 2)
            else:
                self.assertTrue (False)
        ret = a.Encode()
        self.assertEqual(ret, bytes.fromhex(self.VALID_LEGACY_POLICY))

    def test_valid_policy(self):
        a = Supervisor_Policy()
        a.Decode(bytes.fromhex(self.VALID_POLICY))
        self.assertEqual(a.Version, 0x00010000)
        self.assertEqual(len(a.PolicyRoots), 5)
        for pr in a.PolicyRoots:
            if pr.GetType() == POLICY_TYPE.MEMORY:
                self.assertEqual(len(pr.PolicyEntries), 0)
            elif pr.GetType() == POLICY_TYPE.IO:
                self.assertEqual(len(pr.PolicyEntries), 2)
            elif pr.GetType() == POLICY_TYPE.MSR:
                self.assertEqual(len(pr.PolicyEntries), 3)
            elif pr.GetType() == POLICY_TYPE.INSTRUCTION:
                self.assertEqual(len(pr.PolicyEntries), 2)
            elif pr.GetType() == POLICY_TYPE.SAVESTATE:
                self.assertEqual(len(pr.PolicyEntries), 1)
            else:
                self.assertTrue (False)
        ret = a.Encode()
        self.assertEqual(ret, bytes.fromhex(self.VALID_POLICY))

if __name__ == '__main__':
    unittest.main()
