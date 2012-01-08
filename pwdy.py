#!/usr/bin/python

import subprocess as subp
import os
import json
import argparse
from getpass import getpass
from base64 import b64encode, b64decode

PWDY_DIR = os.environ['HOME'] + '/.pwdy'
PWD_FILE = '%s/passwd.gpg' % PWDY_DIR

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
        return {'service_name': self.service_name,
                'username': self.username,
                'password': self.password,
                'other_info': self.other_info}

class CredentialSerializer(object):
    """Responsible for communicating stored credential information
    between Python and the filesystem in a secure way."""
         

    def __init__(self, dest, passphrase=None):
        self.keyfile_loc = dest
        self.passphrase = passphrase
    
    def _pipe(self, cmd, in_pipe):
        """Execute `cmd`, piping in `in_pipe` and return a tuple containing stdout
        and stderr."""
        p = subp.Popen(cmd, stdout=subp.PIPE, stdin=subp.PIPE)
        return p.communicate(in_pipe)

    def _add_passphrase(self, gpg_cmd_list):
        """Add the use of a passphrase to a GPG command. Mostly for testing.
        Return a list."""
        return gpg_cmd_list + ['--passphrase', self.passphrase]

    def _encrypt(self, msg):
        """Encrypt a string symmetrically with GPG to `self.keyfile_loc`.
        
        Encode the message in base64 for some obscurity in case someone is
        somehow watching the IPC. Optionally, use a passphrase (this is included
        for testing purposes).
        """
        gpg_cmd = ['gpg', '--yes', '-c', '--output', self.keyfile_loc]

        if self.passphrase is not None:
            gpg_cmd = self._add_passphrase(gpg_cmd)

        try:
            self._pipe(gpg_cmd, b64encode(msg))
        except IOError:
            print("Can't write to dest ('%s')." % self.keyfile_loc)
     
    def _decrypt(self):
        """Decrypt `self.keyfile_loc` and return it as a string."""
 
        gpg_cmd = ['gpg']

        if self.passphrase is not None:
            gpg_cmd = self._add_passphrase(gpg_cmd)
                                      
        gpg_cmd += ['-d', self.keyfile_loc]

        return b64decode(subp.check_output(gpg_cmd))
                         
    def dump(self, creds):
        """Dump a list or dict of `Credential`s to the filesystem.
        
        Optionally, use a passphrase to do so (mostly for testing).
        """
        if type(creds) is dict:
            creds = creds.values()

        dict_list = [c.json_dict for c in creds]
        json_str = json.dumps(dict_list)

        self._encrypt(json_str)

    def load(self):
        """Return a list of `Credential`s accessed from an encrypted file.
        
        Optionally, use a passphrase to do so (mostly for testing).
        """
        if self.keyfile_exists() is False:
            return self.handle_no_store()

        json_str = self._decrypt()
        dict_list = json.loads(json_str)

        cred_list = []

        for c_dict in dict_list:
            cred_list.append(Credential(**c_dict))

        return cred_list

    def handle_no_store(self):
        """Handle the event that no credential storage currently exists."""
        return []

    def load_dict(self, *args, **kwargs):
        """Same as load, but return a dict of `Credential`s keyed by
        service name."""
        cred_list = self.load(*args, **kwargs)

        return dict([(c.service_name, c) for c in cred_list])

    def insert(self, new_cred):
        """Insert a new `Credential` and save it out to filesystem. Return True
        if successful, False if otherwise."""

        existing_cred_dict = self.load_dict()

        if new_cred.service_name in existing_cred_dict.keys():
            return False
        else:
            existing_cred_dict[new_cred.service_name] = new_cred
            self.dump(existing_cred_dict)
            return True

    def keyfile_exists(self):
        """Return whether or not the credentials file currently exists."""
        return os.path.exists(self.keyfile_loc)

    def keyfile_writable(self):
        """Return whether or not the credentials file is writable."""
        return os.access(self.keyfile_loc, os.W_OK)

    def create_keyfile(self):
        if not self.keyfile_exists():
            self.dump([])

class InteractionUtility(object):
    """A collection of utility functions for interacting with users."""


    @staticmethod
    def new_pass_confirm(prompt="Password"):
        """Get a new password from a user twice and confirm that they match.
        
        If we try thrice to get a new password and they don't match any time,
        return False.
        """
        new_pass = False

        for _ in range(3):
            first_try = getpass(prompt + ": ")
            second_try = getpass(prompt + " (again): ")

            if first_try == second_try:
                new_pass = second_try
                break

            print "Passwords didn't match."
        
        if new_pass is False:
            print "Tried three times for a matching password. Quitting."

        return new_pass
 
    @staticmethod
    def make_cred(**kwargs):
        """Accept same arguments as `Credential` constructor; prompt user for
        any required fields that are missing, return a new `Credential`."""

        existing_keys = kwargs.keys()

        non_pass_fields = [
            ("Service name", "service_name"),
            ("Username", "username"),
            ("Other info", "other_info"),
        ]

        for name, field in non_pass_fields:
            if name not in existing_keys:
                kwargs[field] = raw_input("%s: " % name)
 
        if "password" not in existing_keys:
            prompt = "Password for %s@%s" \
                     % (kwargs['username'], kwargs['service_name'])
            kwargs["password"] = InteractionUtility.new_pass_confirm(prompt)

        return Credential(**kwargs)
                             
    @staticmethod
    def init_keyfile(keyfile_loc):
        """If no keyfile exists, create one."""
        y_n = raw_input("No keyfile exists at '%s'. Create one? [y/n]: " \
                        % keyfile_loc)

        if y_n[0].lower() == 'y':
            pphrase = InteractionUtility.new_pass_confirm("Keyfile password")
            s = CredentialSerializer(keyfile_loc, passphrase=pphrase)
            s.create_keyfile()
            return True
        else:
            return False
                        

def parser():
    """Return an `ArgumentParser` instance."""
    _desc = "A password-storage utility."
    parser = argparse.ArgumentParser(description=_desc)
                   
    parser.add_argument('-l', '--list',
                        action='store_const', const='list',
                        default=False,
                        dest='operation',
                        help='List the services.')
                                               
    parser.add_argument('-a', '--add-cred',
                        action='store_const', const='add_cred',
                        default=False,
                        dest='operation',
                        help='Add a credential.')
                                               
    return parser

def interpret_args(ns, keyfile):
    """Interpret arguments obtained by the argparser.
    
    `ns` is the namespace full of arguments.
    """
                                       
    def _add_new_cred(serializer, new_cred):
        """Add a new credential."""
        success = serializer.insert(new_cred)

        if success is False:
            print "Failed to add new credential."

    def _list_services(serializer):
        """List the services currently tracked by pwdy."""
        creds = serializer.load()
        services = sorted([c.service_name for c in creds])

        for i in services:
            print i
    
    def _make_serializer():
        """Ask user for passphrase, instantiate and return serializer."""
        pphrase = getpass("Password for keyfile: ")

        return CredentialSerializer(keyfile, passphrase=pphrase)

    def _check_keyfile_exists():
        if not os.path.exists(keyfile):
            result = InteractionUtility.init_keyfile(keyfile)

            if not result:
                exit()


    new_cred = None

    if ns.operation == 'add_cred':
        new_cred = InteractionUtility.make_cred()

    _check_keyfile_exists()
    serializer = _make_serializer()

    if ns.operation == 'list':
        _list_services(serializer)
    elif ns.operation == 'add_cred':
        _add_new_cred(serializer, new_cred)
    else:
        print "No valid operation specified."
                 
if __name__ == '__main__':
    import sys

    home = os.environ['HOME']
    pwdy_file = home + "/.pwdy_passwords"

    args = parser().parse_args()
    interpret_args(args, pwdy_file)
                   
