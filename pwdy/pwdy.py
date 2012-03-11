#!/usr/bin/python

import os
import sys
from credentials import Credential, CredentialSerializer
from argh import *
from getpass import getpass

home = os.environ['HOME']
pwdy_file = home + "/.pwdy_passwords"


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
    def init_credfile(credfile_loc):
        """If no credfile exists, create one."""

        y_n = raw_input("No credfile exists at '%s'. Create one? [y/n]: " \
                        % credfile_loc)

        if y_n[0].lower() == 'y':
            pphrase = InteractionUtility.new_pass_confirm("Keyfile password")
            CredentialSerializer(credfile_loc, passphrase=pphrase)
            return True
        else:
            return False

    @staticmethod
    def to_clipboard(text):
        """Push text onto the clipboard. Linux/Darwin supported."""
        clipboard_progs = {
            "darwin": "pbcopy",
            "linux2": "xclip",
        }

        to_clip = clipboard_progs[sys.platform]
        return Shell.pipe(to_clip, text)


def make_serializer():
    """Ask user for passphrase, instantiate and return serializer."""
    global pwdy_file
    if not os.path.exists(pwdy_file):
        result = InteractionUtility.init_credfile(pwdy_file)

        if not result:
            exit()

    pphrase = getpass("Password for credfile: ")

    return CredentialSerializer(pwdy_file, passphrase=pphrase)


@arg('--service-name', help='The name of the service when adding a cred.')
@arg('--username', help='The username when adding a cred.')
@arg('--password', help='The password when adding a cred (not recommended).')
@arg('--other-info', help='A string of other information when adding a cred.')
def add(args):
    """Add a new credential."""
    serializer = make_serializer()
    new_cred = InteractionUtility.make_cred(**args.__dict__)
    success = serializer.insert(new_cred)

    if success is False:
        yield "Failed to add new credential."

    update()


@command
def ls():
    """List the credentials currently tracked by pwdy."""
    creds = make_serializer().load()
    creds_str = sorted([str(c) for c in creds])

    for i in creds_str:
        yield i


@command
def update():
    """Regenerate the file used for credential tab-completion."""
    global home
    cred_ids = " ".join([c for c in ls()])

    with open('/Users/job/code/pwdy/pwdy/bash_completion.sh.tpl', 'r') as f:
        format_str = f.read()

    with open(os.path.join(home, '.pwdy_completion.sh'), 'w') as f:
        f.write(format_str % cred_ids)

    yield "Completion updated."


@arg('cred_id', help='A string of other information when adding a cred.')
def get(args):
    """Print a credential's other_info and copy the password to the
    clipboard."""
    serializer = make_serializer()
    cred = serializer.load_dict()[args.cred_id]

    yield "Retrieved credential for %s." % args.cred_id
    yield "  Username: %s" % cred.username

    if cred.other_info:
        yield '  Other info: "%s"' % cred.other_info

    InteractionUtility.to_clipboard(cred.password)
    yield "  Password copied to clipboard."


def graceful_exit(signal, frame):
    print
    exit()

if __name__ == '__main__':
    import signal

    signal.signal(signal.SIGINT, graceful_exit)

    p = ArghParser(description="A password-storage utility.")
    cmds = [add, ls, get, update]
    p.add_commands(cmds)
    p.dispatch()
