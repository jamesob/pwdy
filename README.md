# pwdy

A reasonably secure way to store your passwords in an OS-independent way.
Accessible by a fully-featured command-line interface.

## Usage

    broderick ~ $ pwdy -h
    usage: pwdy.py [-h] [-l] [-g CRED_ID] [-a] [-s SERVICE_NAME] [-u USERNAME]
                   [-p PASSWORD] [-o OTHER_INFO]

    A password-storage utility.

    optional arguments:
      -h, --help            show this help message and exit
      -l, --list            List the credentials.
      -g CRED_ID, --get-cred CRED_ID
                            Retrieve a credential, put it on the clipboard, and
                            print other information.
      -a, --add-cred        Add a credential.
      -s SERVICE_NAME, --service-name SERVICE_NAME
                            The name of the service when adding a cred.
      -u USERNAME, --username USERNAME
                            The username when adding a cred.
      -p PASSWORD, --password PASSWORD
                            The password when adding a cred (not recommended).
      -o OTHER_INFO, --other-info OTHER_INFO
                            A string of other information when adding a cred.

## Install

1. Clone the git repo.
2. Symlink or copy `pwdy.py` to somewhere in your `$PATH`.
3. Run `pwdy -l` to initiate a key file.
4. Optionally, copy the keyfile into a Dropbox or source-control system and
   symlink it back to `~/.pwdy_passwords`.

## Run the unit tests

1. `python test.py`

## Limitations

Of course this is all hackable, but currently `pwdy` is limited to

  * one keyfile.

## Security assumptions

Someone can attack `pwdy` by

  * intercepting a string passed back and forth (via Python's `subprocess`
    module) between the Python process and the `gnupg` process, or

  * somehow rifling through Python's heap during execution.

These are vulnerabilities I'm willing to live with until I discover a better way
to protect against them. I reckon the latter to be fairly unlikely given how
quickly the process completes once it's storing sensitive information.

## Architecture

Your private credentials are stored in base64'd JSON strings encrypted with
`gnupg`. The base64 conversion is purely for obscurity (which is, of course,
theoretically shallow), but may help to make the passage of credentials less
obvious to someone snooping on the IPC between Python and GnuPG.

## TODO

In order of priority:

- BASH credential tab-completion
- RC configuration
- Use a Python library for crypto instead of GPG


