#!/usr/bin/python

"""
Contains code for communicating with GPG via subprocess. For use in the
CredentialSerializer class.
"""

from utils import Shell
from base64 import b64encode, b64decode


class GPGCommunicator(object):

    class KeyfileDecodeError(Exception):
        def __init__(self, value):
            self.value = value

    @staticmethod
    def _add_passphrase(gpg_cmd_list, passphrase):
        """Add the use of a passphrase to a GPG command. Mostly for testing.
        Return a list."""
        return gpg_cmd_list + ['--passphrase', passphrase]

    @staticmethod
    def encrypt(msg, credfile, passphrase=None):
        """Encrypt a string symmetrically with GPG to `self.credfile_loc`.
        Return True if successful, False otherwise.

        Encode the message in base64 for some obscurity in case someone is
        somehow watching the IPC. Optionally, use a passphrase (this is
        included for testing purposes).

        TODO: account for case of bad password.
        """
        gpg_cmd = ['gpg', '--yes', '-c', '--output', credfile]

        if passphrase:
            gpg_cmd = GPGCommunicator._add_passphrase(gpg_cmd, passphrase)

        (stdout, stderr, retcode) = Shell.pipe(gpg_cmd, b64encode(msg))

        return True if retcode == 0 else False

    @staticmethod
    def decrypt(credfile, passphrase=None):
        """Decrypt `self.credfile_loc` and return it as a string; if
        unsuccessful, return the empty string."""
        gpg_cmd = ['gpg']

        if passphrase:
            gpg_cmd = GPGCommunicator._add_passphrase(gpg_cmd, passphrase)

        gpg_cmd += ['-d', credfile]

        (stdout, stderr, retcode) = Shell.pipe(gpg_cmd)

        if retcode == 0:
            return b64decode(stdout)
        else:
            err = "Keyfile couldn't be decoded (return code: %d)." % retcode
            raise GPGCommunicator.KeyfileDecodeError(err)

            return ""
