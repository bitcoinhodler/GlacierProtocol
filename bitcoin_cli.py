"""
Helpers for running bitcoin-cli subprocesses.
"""

from decimal import Decimal
import json as systemjson
import shlex
import subprocess


verbose_mode = False
cli_args = None


def _verbose(content):
    """
    Print content iff verbose_mode is enabled.
    """
    if verbose_mode:
        print(content)


def _run_subprocess(exe, *args):
    """
    Run a subprocess (bitcoind or bitcoin-cli).

    Returns => (command, return code, output)

    exe: executable file name (e.g. bitcoin-cli)
    args: arguments to exe
    """
    cmd_list = [exe] + cli_args + list(args)
    _verbose("bitcoin cli call:\n  {0}\n".format(" ".join(shlex.quote(x) for x in cmd_list)))
    with subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as pipe:
        output, _ = pipe.communicate()
    output = output.decode('ascii')
    retcode = pipe.returncode
    _verbose("bitcoin cli call return code: {0}  output:\n  {1}\n".format(retcode, output))
    return (cmd_list, retcode, output)


def call(*args):
    """
    Run `bitcoin-cli`, return OS return code.
    """
    _, retcode, _ = _run_subprocess("bitcoin-cli", *args)
    return retcode


def checkoutput(*args):
    """
    Run `bitcoin-cli`, fail if OS return code nonzero, return output.
    """
    cmd_list, retcode, output = _run_subprocess("bitcoin-cli", *args)
    if retcode != 0:
        raise subprocess.CalledProcessError(retcode, cmd_list, output=output)
    return output


def json(*args):
    """
    Run `bitcoin-cli`, parse output as JSON.
    """
    return systemjson.loads(checkoutput(*args), parse_float=Decimal)


def bitcoind_call(*args):
    """
    Run `bitcoind`, return OS return code.
    """
    _, retcode, _ = _run_subprocess("bitcoind", *args)
    return retcode
