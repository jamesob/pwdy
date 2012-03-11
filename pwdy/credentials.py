import json
import os
from gpg import *


class Credential(object):
    """A credential to be stored and later accessed.
    Usually instantiated from an imported JSON file for temporary usage.
    """

    def __init__(self, service_name, username, password, other_info=""):
        self.service_name = service_name
        self.username = username
        self.password = password
        self.other_info = other_info

    @property
    def json_dict(self):
        """Return a json-friendly dict representation of this credential."""
        return self.__dict__

    def __str__(self):
        return "%s:%s" % (self.service_name, self.username)


class CredentialSerializer(object):
    """Responsible for communicating stored credential information
    between Python and the filesystem in a secure way.

    Arguments:
      - `crypto`: must implement methods `encrypt` and `decrypt`.
    """

    def __init__(self, dest, passphrase, crypto=GPGCommunicator):
        self.credfile_loc = dest
        self.passphrase = passphrase
        self.crypto = crypto

        self.create_credfile()

    def dump(self, creds):
        """Dump a list or dict of `Credential`s to the filesystem.
        Optionally, use a passphrase to do so (mostly for testing).
        """
        if type(creds) is dict:
            creds = creds.values()

        dict_list = [c.json_dict for c in creds]
        json_str = json.dumps(dict_list)

        self.crypto.encrypt(json_str, self.credfile_loc, self.passphrase)

    def load(self):
        """Return a list of `Credential`s accessed from an encrypted file.
        Optionally, use a passphrase to do so (mostly for testing).
        """
        if not self._credfile_exists():
            return self.handle_no_store()

        try:
            json_str = self.crypto.decrypt(self.credfile_loc, self.passphrase)
        except GPGCommunicator.KeyfileDecodeError as e:
            print("%s bad password?" % e.value)
            exit(1)

        dict_list = json.loads(json_str)

        return [Credential(**c_dict) for c_dict in dict_list]

    def handle_no_store(self):
        """Handle the event that no credential storage currently exists."""
        return []

    def load_dict(self, *args, **kwargs):
        """Same as load, but return a dict of `Credential`s keyed by their
        string representations."""
        cred_list = self.load(*args, **kwargs)

        return dict([(str(c), c) for c in cred_list])

    def insert(self, new_cred):
        """Insert a new `Credential` and save it out to filesystem. Return True
        if successful, False if otherwise."""

        existing_cred_dict = self.load_dict()

        if str(new_cred) in existing_cred_dict.keys():
            return False
        else:
            existing_cred_dict[str(new_cred)] = new_cred
            self.dump(existing_cred_dict)
            return True

    def _credfile_exists(self):
        """Return whether or not the credentials file currently exists."""
        return os.path.exists(self.credfile_loc)

    def create_credfile(self):
        if not self._credfile_exists():
            self.dump([])
