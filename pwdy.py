#!/usr/bin/python

import subprocess as subp
import os
import json
import argparse
from getpass import getpass
from base64 import b64encode, b64decode

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

    def __str__(self):
        return "%s:%s" % (self.service_name, self.username)

class CredentialSerializer(object):
    """Responsible for communicating stored credential information
    between Python and the filesystem in a secure way."""
         

    def __init__(self, dest, passphrase):
        self.keyfile_loc = dest
        self.passphrase = passphrase

        assert self.keyfile_exists(), \
               "Specified keyfile '%s' doesn't exist." % dest
                    
    def dump(self, creds):
        """Dump a list or dict of `Credential`s to the filesystem.
        
        Optionally, use a passphrase to do so (mostly for testing).
        """
        if type(creds) is dict:
            creds = creds.values()

        dict_list = [c.json_dict for c in creds]
        json_str = json.dumps(dict_list)

        GPGCommunicator.encrypt(json_str, self.keyfile_loc, self.passphrase)

    def load(self):
        """Return a list of `Credential`s accessed from an encrypted file.
        
        Optionally, use a passphrase to do so (mostly for testing).
        """
        if not self.keyfile_exists():
            return self.handle_no_store()

        json_str = GPGCommunicator.decrypt(self.keyfile_loc, self.passphrase)
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

    def _keyfile_exists(self):
        """Return whether or not the credentials file currently exists."""
        return os.path.exists(self.keyfile_loc)

    def create_keyfile(self):
        if not self.keyfile_exists():
            self.dump([])

class GPGCommunicator(object):


    @staticmethod
    def _pipe(cmd, in_pipe=None):
        """Execute `cmd`, piping in `in_pipe` and return a tuple containing
        (stdout, stderr, returncode)."""
        p = subp.Popen(cmd, 
                       stdout=subp.PIPE, 
                       stderr=subp.PIPE, 
                       stdin=subp.PIPE)

        return p.communicate(in_pipe) + (p.returncode,)

    @staticmethod
    def _add_passphrase(gpg_cmd_list, passphrase):
        """Add the use of a passphrase to a GPG command. Mostly for testing.
        Return a list."""
        return gpg_cmd_list + ['--passphrase', passphrase]

    @staticmethod
    def encrypt(msg, keyfile, passphrase=None):
        """Encrypt a string symmetrically with GPG to `self.keyfile_loc`. Return
        True if successful, False otherwise.
        
        Encode the message in base64 for some obscurity in case someone is
        somehow watching the IPC. Optionally, use a passphrase (this is included
        for testing purposes).

        TODO: account for case of bad password.
        """
        gpg_cmd = ['gpg', '--yes', '-c', '--output', keyfile]

        if passphrase:
            gpg_cmd = GPGCommunicator._add_passphrase(gpg_cmd, passphrase)

        (stdout, stderr, retcode) = GPGCommunicator._pipe(gpg_cmd,
                                                          b64encode(msg))
        return True if retcode == 0 else False
     
    @staticmethod
    def decrypt(keyfile, passphrase=None):
        """Decrypt `self.keyfile_loc` and return it as a string; if
        unsuccessful, return the empty string."""
 
        gpg_cmd = ['gpg']

        if passphrase:
            gpg_cmd = GPGCommunicator._add_passphrase(gpg_cmd, passphrase)

        gpg_cmd += ['-d', keyfile]

        (stdout, stderr, retcode) = GPGCommunicator._pipe(gpg_cmd)
        
        if retcode == 0:
            return b64decode(stdout)
        else:
            return ""

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

        non_pass_fields = [
            ("Service name", "service_name"),
            ("Username", "username"),
            ("Other info", "other_info"),
        ]

        new_kwargs = {}

        for name, field in non_pass_fields:
            if (field not in kwargs.keys()) or (not kwargs[field]):
                new_kwargs[field] = raw_input("%s: " % name)
            else:
                new_kwargs[field] = kwargs[field]
 
        if ("password" not in kwargs.keys()) or (not kwargs["password"]):
            prompt = "Password for %s@%s" \
                     % (new_kwargs['username'], new_kwargs['service_name'])
            new_kwargs["password"] = InteractionUtility.new_pass_confirm(prompt)

        return Credential(**new_kwargs)
                             
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
                        action='store_const', const='list_creds',
                        default=False,
                        dest='operation',
                        help='List the credentials.')
                                                      
    parser.add_argument('-a', '--add-cred',
                        action='store_const', const='add_cred',
                        default=False,
                        dest='operation',
                        help='Add a credential.')
                                                        
    parser.add_argument('-s', '--service-name',
                        action='store',
                        dest='service_name',
                        help='The name of the service when adding a cred.')
                                                         
    parser.add_argument('-u', '--username',
                        action='store',
                        dest='username',
                        help='The username when adding a cred.')
                                                                         
    parser.add_argument('-p', '--password',
                        action='store',
                        dest='password',
                        help='The password when adding a cred (not recommended).')
                                                                          
    parser.add_argument('-o', '--other-info',
                        action='store',
                        dest='other_info',
                        help='A string of other information when adding a cred.')
                                                                         
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
                      
    def _list_creds(serializer):
        """List the credentials currently tracked by pwdy."""
        creds = serializer.load()
        creds_str = sorted([str(c) for c in creds])

        for i in creds_str:
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
        new_cred = InteractionUtility.make_cred(**ns.__dict__)

    _check_keyfile_exists()
    serializer = _make_serializer()

    if ns.operation == 'list_creds':
        _list_creds(serializer)
    elif ns.operation == 'add_cred':
        _add_new_cred(serializer, new_cred)
    else:
        print "No valid operation specified."

def graceful_exit(signal, frame):
    print
    exit()
                 
if __name__ == '__main__':
    import sys
    import signal

    home = os.environ['HOME']
    pwdy_file = home + "/.pwdy_passwords"

    signal.signal(signal.SIGINT, graceful_exit)
    args = parser().parse_args()
    interpret_args(args, pwdy_file)
                   
