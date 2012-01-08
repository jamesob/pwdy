# pwdy

A reasonably secure way to store your passwords in an OS-independent way.
Accessible by a fully-featured command-line interface.

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


