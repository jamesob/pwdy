import unittest
import os
from pwdy import *

cred = Credential('service', 'user', 'pass', 'hey other info')
cred2 = Credential('s2', 'joe', 'p123', 'pin: 1111')

expected_dict = {'service_name': 'service',
                 'username': 'user',
                 'password': 'pass',
                 'other_info': 'hey other info'}

class TestCredential(unittest.TestCase):


    def test_creds(self):
        global cred
        global expected_dict
 
        self.assertEqual(cred.json_dict, expected_dict)
                         
class TestSerializing(unittest.TestCase):


    def setUp(self):
        self.data_location = "./test-passwds.gpg"
        self.serializer = CredentialSerializer(self.data_location,
                                               passphrase="foobar")
        self.cred_list = [cred, cred2]

    def test_dump_load(self):
        self._test_dump()
        self._test_load()
        self._test_load_dict()

    def _test_dump(self):
        self.serializer.dump(self.cred_list)

        self.assertTrue(self.serializer.keyfile_exists())
        self.assertTrue(self.serializer.keyfile_writable())

    def _test_load(self):
        global expected_dict
        cred_list = self.serializer.load()
        eq = self.assertEqual

        eq(2, len(cred_list))
        eq(expected_dict, cred_list[0].json_dict)
        eq('p123', cred_list[1].password)

    def _test_load_dict(self):
        cred_dict = self.serializer.load_dict()
        eq = self.assertEqual

        eq('pin: 1111', cred_dict['s2'].other_info)
        eq('user', cred_dict['service'].username)
 
    def test_insert(self):
        global cred

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
 
    def tearDown(self):
        os.remove(self.data_location)

if __name__ == '__main__':
    unittest.main()

