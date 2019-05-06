"""
Helpers for running bitcoin-cli subprocesses.
"""

from decimal import Decimal
import json
import shlex
import subprocess


verbose_mode = False
cli_args = None


def verbose(content):
    """
    Print content iff verbose_mode is enabled.
    """
    if verbose_mode:
        print(content)


def run_subprocess(exe, *args):
    """
    Run a subprocess (bitcoind or bitcoin-cli).

    Returns => (command, return code, output)

    exe: executable file name (e.g. bitcoin-cli)
    args: arguments to exe
    """
    cmd_list = [exe] + cli_args + list(args)
    verbose("bitcoin cli call:\n  {0}\n".format(" ".join(shlex.quote(x) for x in cmd_list)))
    with subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1) as pipe:
        output, _ = pipe.communicate()
    output = output.decode('ascii')
    retcode = pipe.returncode
    verbose("bitcoin cli call return code: {0}  output:\n  {1}\n".format(retcode, output))
    return (cmd_list, retcode, output)


def bitcoin_cli_call(*args):
    """
    Run `bitcoin-cli`, return OS return code.
    """
    _, retcode, _ = run_subprocess("bitcoin-cli", *args)
    return retcode


def bitcoin_cli_checkcall(*args):
    """
    Run `bitcoin-cli`, ensure no error.
    """
    cmd_list, retcode, output = run_subprocess("bitcoin-cli", *args)
    if retcode != 0:
        raise subprocess.CalledProcessError(retcode, cmd_list, output=output)


def bitcoin_cli_checkoutput(*args):
    """
    Run `bitcoin-cli`, fail if OS return code nonzero, return output.
    """
    cmd_list, retcode, output = run_subprocess("bitcoin-cli", *args)
    if retcode != 0:
        raise subprocess.CalledProcessError(retcode, cmd_list, output=output)
    return output


def bitcoin_cli_json(*args):
    """
    Run `bitcoin-cli`, parse output as JSON.
    """
    return json.loads(bitcoin_cli_checkoutput(*args), parse_float=Decimal)


def bitcoind_call(*args):
    """
    Run `bitcoind`, return OS return code.
    """
    _, retcode, _ = run_subprocess("bitcoind", *args)
    return retcode
