import unittest
import os
from pwdy import *
from pwdy.credentials import Credential, CredentialSerializer
from pwdy.gpg import GPGCommunicator

cred = Credential('service', 'user', 'pass', 'hey other info')
cred2 = Credential('s2', 'joe', 'p123', 'pin: 1111')

expected_dict = {'service_name': 'service',
                 'username': 'user',
                 'password': 'pass',
                 'other_info': 'hey other info'}


class TestCredential(unittest.TestCase):

    def test_dict(self):
        self.assertEqual(cred.json_dict, expected_dict)

    def test_str(self):
        self.assertEqual(str(cred), "service:user")


class TestGPG(unittest.TestCase):

    filename = "temp"
    msg = "foobaz!"

    def tearDown(self):
        os.system("rm %s" % self.filename)

    def test_gpg(self):
        GPGCommunicator.encrypt(self.msg, self.filename, "pass123")
        out = GPGCommunicator.decrypt(self.filename, "pass123")

        self.assertEqual(self.msg, out)

    def test_bad_pass(self):
        GPGCommunicator.encrypt(self.msg, self.filename, "pass123")

        def fail():
            GPGCommunicator.decrypt(self.filename, "wrong_pass")

        self.assertRaises(GPGCommunicator.KeyfileDecodeError,
                          fail)


class TestSerializing(unittest.TestCase):

    data_location = "./test-passwds.gpg"

    def setUp(self):
        self.serializer = CredentialSerializer(self.data_location,
                                               passphrase="foobar")
        self.cred_list = [cred, cred2]

    def tearDown(self):
        os.system("rm %s" % self.data_location)

    def test_dump_load(self):
        self._test_dump()
        self._test_load()
        self._test_load_dict()

    def _test_dump(self):
        self.serializer.dump(self.cred_list)

        self.assertTrue(self.serializer._credfile_exists())

    def _test_load(self):
        cred_list = self.serializer.load()
        eq = self.assertEqual

        eq(2, len(cred_list))
        eq(expected_dict, cred_list[0].json_dict)
        eq('p123', cred_list[1].password)

    def _test_load_dict(self):
        cred_dict = self.serializer.load_dict()
        eq = self.assertEqual

        eq('pin: 1111', cred_dict[str(cred2)].other_info)
        eq('user', cred_dict[str(cred)].username)

    def test_insert(self):
        self.assertEqual(0, len(self.serializer.load()))

        self.assertTrue(self.serializer.insert(cred))
        self.assertFalse(self.serializer.insert(cred))
        self.assertEqual(1, len(self.serializer.load()))

        new_cred = Credential('gmail', 'joe', '123')
        self.assertTrue(self.serializer.insert(new_cred))
        self.assertEqual(2, len(self.serializer.load()))

        new_cred.service_name = 'hotmail'
        self.assertTrue(self.serializer.insert(new_cred))
        self.assertEqual(3, len(self.serializer.load()))

if __name__ == '__main__':
    unittest.main()
