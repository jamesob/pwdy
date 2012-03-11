import subprocess as subp


class Shell(object):
    """A utility class for dealing with shell communication."""

    @staticmethod
    def pipe(cmd, in_pipe=None):
        """Execute `cmd`, piping in `in_pipe` and return a tuple containing
        (stdout, stderr, returncode)."""
        p = subp.Popen(cmd,
                       stdout=subp.PIPE,
                       stderr=subp.PIPE,
                       stdin=subp.PIPE)

        return p.communicate(in_pipe) + (p.returncode,)
