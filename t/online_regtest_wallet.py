#!/usr/bin/env python3
"""
"Online" node simulator for developer tests.

Launches bitcoind in regtest mode, then constructs transactions as
expected by the developer tests. This simulates the online blockchain,
and is used to demonstrate that the transactions constructed by
glacierscript.py can be mined successfully.

See the interactive help for usage details.

The Makefile runs this in order to validate the withdrawal
transactions generated by GlacierScript.

"""

import argparse
from decimal import Decimal
import json
import os
import pprint
import re
import shutil
import subprocess
import sys
import textwrap
import time

from atomic_write import atomic_write
import segwit_addr
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import glacierscript  # noqa:pylint:wrong-import-position
import bitcoin_cli    # noqa:pylint:wrong-import-position

# Vars that glacierscript expects (ugh)
bitcoin_cli.cli_args = ["-regtest", "-datadir=bitcoin-online-data"]
glacierscript.wif_prefix = "EF"

MIN_FEE = Decimal("0.00010000")


def start(args):
    """Run the `start` subcommand to load bitcoind."""
    # We start with a pre-created wallet.dat so that our addresses
    # will be the same every time we run.
    stop(None)
    os.makedirs('bitcoin-online-data/regtest/wallets')
    shutil.copyfile(os.path.join(os.path.dirname(__file__), 'regtest-initial-wallet.dat'),
                    'bitcoin-online-data/regtest/wallets/wallet.dat')

    glacierscript.ensure_bitcoind_running('-txindex')
    mine_block(101)  # 101 so we have some coinbase outputs that are spendable
    # Load all transactions in tx.json and reconstruct those in our blockchain
    txfile = TxFile()
    for txdata in txfile:
        for hextx in txdata['txs']:
            xact = build_input_xact(txdata['address'], hextx)
            # We should always create the same transactions, since we start
            # with a seeded wallet and tx.json is append-only.
            if xact != hextx:
                actual = bitcoin_cli.json("decoderawtransaction", xact)
                expected = bitcoin_cli.json("decoderawtransaction", hextx)
                print("Expected transaction:", file=sys.stderr)
                pprint.pprint(expected, stream=sys.stderr)
                print("Actual transaction constructed:", file=sys.stderr)
                pprint.pprint(actual, stream=sys.stderr)
                raise RuntimeError("Did not create expected transaction for " + txdata['file'])
        if args.program == start:  # noqa:pylint:comparison-with-callable
            # If we're running `convert` then we allow runfile to differ, since
            # otherwise we wouldn't be able to change it and then re-convert it
            confirm_txs_in_runfile(txdata)


def confirm_txs_in_runfile(txdata):
    """
    Confirm the input txs in *.run file match tx.json.
    """
    if txdata['obsolete']:
        # This is an old transaction that we created only to keep
        # other tests' transactions from changing. Doesn't match any
        # *.run file anymore.
        return
    # Find *.run in t/ directory, same directory as this script
    runfile = os.path.join(os.path.dirname(__file__), txdata['file'])
    prf = ParsedRunfile(runfile)
    if set(txdata['txs']) != set(prf.input_txs):
        print("In file {}, found unexpected input transactions.".format(runfile))
        print("If this file has deliberately changed, run `{} convert {}`".format(__file__, runfile))
        raise SystemExit("Error: Unexpected transaction in *.run file")


def mine_block(count=1):
    """
    Mine one or more blocks in our regtest blockchain.
    """
    adrs = bitcoin_cli.checkoutput("getnewaddress", '', 'p2sh-segwit').strip()
    bitcoin_cli.json("generatetoaddress", "{}".format(count), adrs)


def create_input2(addresstype, amount):
    """
    Create an input for an input (input^2).

    Because GlacierScript needs the entire transaction for each input,
    the format of the inputs to that transaction matter. This function
    will create transactions which become inputs to the transactions
    we feed to GlacierScript.

    addresstype: string: legacy, p2sh-segwit, or bech32
    amount: Decimal: amount in tBTC

    Returns an input in the format expected by createrawtransaction,
    e.g. a dict with keys txid, vout.

    Creates & mines transactions.
    """
    unspents = bitcoin_cli.json("listunspent")
    # Choose first unspent that's large enough. There should always be one because of
    # all our coinbase outputs of 50.0 BTC
    inputtx = next(unspent for unspent in unspents if unspent["amount"] >= amount + MIN_FEE)
    change_adrs = bitcoin_cli.checkoutput("getnewaddress", '', addresstype).strip()
    dest_adrs = bitcoin_cli.checkoutput("getnewaddress", '', addresstype).strip()
    outputs = [
        {dest_adrs: amount}
    ]
    change_amount = inputtx["amount"] - amount - MIN_FEE
    if change_amount > 0:
        outputs.insert(0, {change_adrs: change_amount})

    hextx = create_and_mine([inputtx], outputs)

    txdec = bitcoin_cli.json("decoderawtransaction", hextx)
    # Find our vout. This is more flexible than necessary since we
    # fix the order of our two outputs above. It's always the last one.
    vout = next(vout for vout in txdec["vout"] if dest_adrs in vout["scriptPubKey"]["addresses"])
    return {
        "txid": txdec["txid"],
        "vout": vout["n"]
    }


def build_one_input2(vin, amount_btc):
    """
    Construct a single input for an input (input^2).

    vin: One entry from tx["vin"] that we want to reconstruct
    amount_btc: amount in BTC to put in this utxo

    Returns: one input in createrawtransaction form
    """
    # We have to parse scriptSig's asm to figure out what form this is
    # in (legacy, p2sh-segwit, or bech32),

    # The input could also be a multisig p2sh, or any other crazy
    # thing, but I don't think we need to support that.

    scriptsigs = {
        # Standard P2PKH: sig pubkey
        'legacy': r'sig: [0-9a-f]{140,144}\[ALL\] [0-9a-f]{66} witness: None',
        # P2WPKH-in-P2SH:
        'p2sh-segwit': r'sig: [0-9a-f]{44} witness: [0-9a-f]{140,144} [0-9a-f]{66}',
        # P2WPKH:
        'bech32': r'sig:  witness: [0-9a-f]{140,144} [0-9a-f]{66}',
    }
    witness = " ".join(vin["txinwitness"]) if "txinwitness" in vin else "None"
    vin_sig = "sig: {} witness: {}".format(vin["scriptSig"]["asm"], witness)
    try:
        form = next(f for f in scriptsigs if re.fullmatch(scriptsigs[f], vin_sig))
    except StopIteration as exc:
        raise NotImplementedError("unrecognized scriptsig in vin: {}".format(vin)) from exc
    return create_input2(form, amount_btc)


def build_inputs2(like_tx):
    """
    Given a JSON decoded transaction, build the inputs needed.

    Returns: list of inputs in createrawtransaction form, which you
    can give directly to create_and_mine().

    """
    # The total value of all the inputs we create must add up to the
    # total outputs plus the min xact fee.
    total_output_btc = sum(vout["value"] for vout in like_tx["vout"])
    input_count = len(like_tx["vin"])
    each_input_btc = (total_output_btc + MIN_FEE) / input_count
    # Add one sat to each input (which will go to the miner fee)
    # so that rounding doesn't result in a less-than-min miner fee
    each_input_btc = each_input_btc.quantize(glacierscript.SATOSHI_PLACES) + glacierscript.SATOSHI_PLACES

    return [build_one_input2(vin, each_input_btc) for vin in like_tx["vin"]]


def build_one_inp_output(cold_address, vout):
    """
    Construct a single output for an input.

    cold_address: Glacier-created cold storage address that this
    transaction should deposit to

    vout: One entry from tx["vout"] that we want to reconstruct

    Returns: one output in createrawtransaction form,
    i.e. { address: amount }

    """
    if cold_address in vout["scriptPubKey"]["addresses"]:
        return {cold_address: vout["value"]}

    # Decipher scriptPubKey.asm to determine address type (legacy, p2sh-segwit, bech32)
    type_conversion = {  # convert from scriptPubKey.type to getnewaddress type
        'pubkeyhash': 'legacy',
        'scripthash': 'p2sh-segwit',  # not necessarily true, but Glacier can't tell the difference
        'witness_v0_keyhash': 'bech32',
    }
    if vout["scriptPubKey"]["type"] not in type_conversion:
        raise NotImplementedError("unrecognized scriptPubKey type in vout: {}".format(vout))
    addr_type = type_conversion[vout["scriptPubKey"]["type"]]
    change_adrs = bitcoin_cli.checkoutput("getnewaddress", '', addr_type).strip()
    return {change_adrs: vout["value"]}


def build_inp_outputs(cold_address, like_tx):
    """
    Given a JSON decoded transaction, build the outputs needed.

    cold_address: Glacier-created cold storage address that this
    transaction should deposit to

    Returns: list of outputs in createrawtransaction form, which you
    can give directly to create_and_mine().

    """
    return [build_one_inp_output(cold_address, vout) for vout in like_tx["vout"]]


def build_input_xact(cold_address, like_this):
    """
    Construct a single transaction on the blockchain.

    As expected by one of our Glacier withdrawal tests.

    cold_address: Glacier-created cold storage address that this
    transaction should deposit to

    like_this: example transaction that we want the new one to look
    like.

    Returns: raw hex transaction.

    """
    like_tx = bitcoin_cli.json("decoderawtransaction", like_this)
    inputs = build_inputs2(like_tx)
    outputs = build_inp_outputs(cold_address, like_tx)
    return create_and_mine(inputs, outputs)


def create_and_mine(inputs, outputs):
    """
    Take the given inputs and outputs and put that transaction into the blockchain.

    inputs: <list> in createrawtransaction form

    Returns the raw hex transaction.
    """
    rawtx = bitcoin_cli.checkoutput("createrawtransaction",
                                    glacierscript.jsonstr(inputs),
                                    glacierscript.jsonstr(outputs)).strip()
    signedtx = bitcoin_cli.json("signrawtransactionwithwallet", rawtx)
    if not signedtx["complete"]:
        raise ValueError("unable to sign transaction")
    try:
        confirm_raw_tx(signedtx["hex"])
    except subprocess.CalledProcessError as exc:
        print("Failed to confirm tx:\n", exc.output)
        raise exc
    return signedtx["hex"]


def confirm_raw_tx(xact):
    """
    Given a raw transaction, submit that to bitcoind.

    Also mine it, and fail if it's not accepted.

    Bitcoind must already be running.
    """
    txid = bitcoin_cli.checkoutput("sendrawtransaction", xact).strip()
    mine_block()
    # Ensure that transaction was mined successfully
    rawtx = bitcoin_cli.json("getrawtransaction", txid, 'true')
    if rawtx["confirmations"] == 0:
        raise ValueError("somehow my xact did not get mined?")


class NoTransactionFound(Exception):
    """
    Raised when we cannot find a withdrawal transaction in the file we're searching.
    """


def submit(args):
    """
    Given a golden output file, submit it to our blockchain.

    Proves that it validates.

    Also decode it into JSON and write it out to *.decoded file so Git
    can see the changes.
    """
    infile = args.goldenfile
    try:
        rawtx = find_withdrawal_tx(infile)
        confirm_raw_tx(rawtx)
        decoded_tx = bitcoin_cli.checkoutput("decoderawtransaction", rawtx)
    except NoTransactionFound:
        decoded_tx = "No transaction found\n"
    write_decoded_tx(infile, decoded_tx)


def find_withdrawal_tx(infile):
    """
    Search infile for the withdrawal transaction generated by Glacier.

    infile: <string> filename of a *.golden file

    Returns the rawtx as a string, or raises NoTransactionFound.
    """
    with open(infile, 'rt') as infh:
        # Find line following "Raw signed transaction (hex):"
        match = False
        for line in infh:
            if match:
                return line.strip()
            if line == "Raw signed transaction (hex):\n":
                match = True
    raise NoTransactionFound()


def write_decoded_tx(infile, decoded_tx):
    """Write out the decoded_tx to the *.decoded file."""
    EXPECTED_SUFFIX = r"\.golden(\.re)?\Z"
    NEW_SUFFIX = ".decoded"
    decoded_file = re.sub(EXPECTED_SUFFIX, NEW_SUFFIX, infile)
    if not decoded_file.endswith(NEW_SUFFIX):
        raise ValueError("expected filename to end with " + EXPECTED_SUFFIX)
    with open(decoded_file, 'wt') as outfh:
        outfh.write(decoded_tx)


class TxFile():
    """
    Class to model tx.json file.

    This file keeps track of all the transactions we need to create
    which will be used as inputs to our test withdrawals.

    Why keep such a file?

    If a developer changes or adds a test, it's important for test
    stability that that test's new transactions get created after all
    the previous ones, including the ones previously used by that
    test.

    Otherwise, touching one test could change all the inputs used by
    all of the tests.

    Therefore, we keep track of even obsolete tests formerly used by a
    given *.run file. The tx.json file is effectively append-only:
    except for marking old transactions as obsolete, the only changes
    we make are to append new transactions to the end of the list. (By
    the `convert` subcommand.)

    """

    def __init__(self):
        """Load tx.json and populate our database."""
        with open(self._filename(), 'rt') as infile:
            infile.readline()  # first line is comment, throw away
            struct = infile.read()
            self.txlist = json.loads(struct)

    def __iter__(self):
        """Iterate over the transaction list."""
        return iter(self.txlist)

    @staticmethod
    def _filename():
        """Return filename including path of our tx.json."""
        return os.path.join(os.path.dirname(__file__), 'tx.json')

    def get(self, filename):
        """
        Return the tx.json structure for the specified *.run file.

        Returns None if this file is not in tx.json.
        """
        basefilename = os.path.basename(filename)
        try:
            return next(clump
                        for clump in self.txlist
                        if clump['file'] == basefilename and not clump['obsolete'])
        except StopIteration:
            return None

    def put(self, filename, cold_storage_address, txs):
        """
        Replace the TX structures for the specified filename with txs.

        Mark any old txs as obsolete, append the
        new txs to the list, and write the list back to tx.json.
        """
        basefilename = os.path.basename(filename)
        new = {
            'address': cold_storage_address,
            'file': basefilename,
            'obsolete': False,
            'txs': txs,
        }
        old = self.get(filename)
        if old:
            old['obsolete'] = True
        self.txlist.append(new)
        self.save()

    def save(self):
        """Write out new tx.json file."""
        with atomic_write(self._filename()) as outfile:
            outfile.write("// This file created and used by online_regtest_wallet.py\n")
            outfile.write(json.dumps(self.txlist, indent=2, sort_keys=True))
            outfile.write("\n")


class ParseError(RuntimeError):
    """Exception class for errors encountered in parsing a *.run file."""


class ParsedRunfile():
    """
    Representation of a *.run file.

    This class will parse a *.run file, convert its glacierscript
    command-line to use --regtest instead of --testnet, find the input
    transactions used, and present them as an API for possible
    modification. It can then write out the regenerated file.
    """

    def __init__(self, filename):
        """Open file and parse it."""
        self.modified = False
        self.filename = filename
        self._input_txs = []
        self._input_tx_files = []
        with open(filename, 'rt') as infile:
            contents = infile.read()
        self.parse_lines(contents)

    @property
    def input_txs(self):
        """Return the list of input transactions used by this runfile."""
        return self._input_txs

    @input_txs.setter
    def input_txs(self, value):
        """Assign a new list of input transactions to replace the originals."""
        self.modified = True
        self._input_txs = value

    @staticmethod
    def parser_coroutine(contents):
        """
        Accept a sequence of regexps that contents must match, yielding matched strings.

        The contents must match each regexp in order.

        Exits once all the contents have been consumed.
        """
        match = None
        while contents:
            regexp = yield match.group() if match else None
            match = re.match(regexp, contents, re.DOTALL | re.MULTILINE | re.VERBOSE)
            if not match:
                raise ParseError("did not match expected regexp")
            contents = contents[match.end():]
        yield match.group()  # Last group...shouldn't ever return

    def parse_lines(self, contents):
        """Go through contents (one giant string) to find what we need."""
        parser = self.parser_coroutine(contents)
        next(parser)  # prime the coroutine
        front_matter = parser.send(r"""
                           \A     # beginning of file
                           .*?    # match as few as possible
                           ^      # beginning of line
                           \$GLACIERSCRIPT  # Run script
                           [^\n]* # any extra cmdline options (like -v)
                           \s+ -- # beginning of --testnet or --regtest
                        """)
        testmode = parser.send(r"""
                       (testnet|regtest)
                    """)
        if testmode == 'testnet':
            testmode = 'regtest'
            self.modified = True
        cmdline_and_confirm = parser.send(r"""
                            =\$1 \s create-withdrawal-data \s \<\< \s INPUT \n  # rest of cmdline
                            (y\n){6}       # safety confirmations
                        """)
        self.cold_storage_address = parser.send(r"""
                            2[0-9a-zA-Z]+ \n # cold storage address
                        """).strip()
        script = parser.send(r"""
                            [0-9a-fA-F]+ \n   # redeem script
                        """)
        dest_address = parser.send(r"""
                            [0-9a-zA-Z]+ \n    # destination address
                        """).strip()
        if dest_address.startswith('tb1'):
            # Convert bech32 address from testnet to regtest
            # (Old-style non-segwit addresses are identical on testnet vs regtest.)
            witver, witprog = segwit_addr.decode('tb', dest_address)
            dest_address = segwit_addr.encode('bcrt', witver, witprog)
            self.modified = True

        input_tx_count = int(parser.send(r"""
                            \d+ \n
                        """))
        self._input_txs = []
        self._input_tx_files = []
        for _ in range(input_tx_count):
            filename = None
            xact = parser.send(r"""
                               [^\n]+ \n   # input tx or filename with same
                               """).rstrip()
            if not re.match(r"^[0-9a-fA-F]+$", xact):
                # If not hex, this must be a filename
                filename = xact
                xact = open(filename).read().strip()
            self._input_txs.append(xact)
            self._input_tx_files.append(filename)

        back_matter = parser.send(r"""
                            .* \Z  # everything up to the end
                        """)
        self.front_matter = front_matter \
            + testmode \
            + cmdline_and_confirm \
            + self.cold_storage_address + "\n" \
            + script \
            + dest_address + "\n" \
            + str(input_tx_count) \
            + "\n"
        self.back_matter = back_matter

    def save(self):
        """Write out a new runfile with our modified input transactions."""
        if not self.modified:
            return
        with atomic_write(self.filename) as outfile:
            outfile.write(self.front_matter)
            for idx, xact in enumerate(self._input_txs):
                if self._input_tx_files[idx]:
                    outfile.write(self._input_tx_files[idx] + "\n")
                    with open(self._input_tx_files[idx], 'wt') as txfile:
                        txfile.write(xact + "\n")
                else:
                    outfile.write(xact + "\n")

            outfile.write(self.back_matter)


def convert_one_file(filename):
    """
    Convert one *.run file from testnet to regtest.

    It's important that our updates of tx.json happen before the *.run
    script is rewritten.  That way, if we get interrupted between
    those two, the next time we run, we'll find our transactions in
    tx.json and everything will just work. If we did it in the
    opposite order, we'd leave things in a broken state.
    """
    runfile = ParsedRunfile(filename)
    txjson = TxFile()
    tx_from_json = txjson.get(filename)
    if not tx_from_json \
       or tx_from_json['address'] != runfile.cold_storage_address \
       or tx_from_json['txs'] != runfile.input_txs:
        newtx = [build_input_xact(runfile.cold_storage_address, hex)
                 for hex in runfile.input_txs]
        runfile.input_txs = newtx
        txjson.put(filename, runfile.cold_storage_address, newtx)
    runfile.save()


def convert(args):
    """
    Parse a *.run test input, convert it from testnet to regtest (if needed).

    Save the generated input transactions in file tx.json,
    write out new *.run file with its input transactions replaced with regtest versions.

    We must run start() first, to be sure the current blockchain is in a known state,
    before we start creating additional transactions.
    """
    start(args)
    for runfile in args.runfile:
        print("Converting {} to regtest...".format(runfile))
        try:
            convert_one_file(runfile)
        except ParseError:
            print("*** Error converting that one. This is expected, if this test doesn't actually create any withdrawal transaction.")
    stop(args)


def stop(_):
    """
    Stop the bitcoind server.

    Does no harm if it's not running.
    """
    if bitcoin_cli.call('stop') == 0:
        # in case already running, wait a bit for it to exit
        time.sleep(1)

    try:
        shutil.rmtree('bitcoin-online-data')
    except FileNotFoundError:
        pass  # we don't care if it wasn't already there


def main():
    """Launch main command-line program."""
    parser = argparse.ArgumentParser(description="""
        This tool is used to control an "online" Bitcoin node for testing Glacier.
    """, epilog="Run <subcommand> --help for more about that subcommand.")
    parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')
    subparsers = parser.add_subparsers(title='Subcommands')

    parser_start = subparsers.add_parser(
        'start',
        help="Start the regtest server",
        description=textwrap.dedent("""\
        Start the regtest server and create transactions as expected
        by test withdrawals.

        This will read tx.json to find the list of transactions to
        create, and will parse all the *.run files to ensure that the
        transactions constructed match what the run files use as
        inputs.

        Glacier's Makefile runs this command once before running any
        tests.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_start.set_defaults(program=start)

    parser_submit = subparsers.add_parser(
        'submit',
        help="Submit a withdrawal transaction to the network",
        description=textwrap.dedent("""\
        Parse a *.golden test output, and submit its withdrawal
        transaction to bitcoind. Fail if not accepted and mined into
        the regtest blockchain. Also writes out a *.decoded file to
        document the constructed transaction in the git history.

        Glacier's Makefile runs this command after running any test
        with a filename of "*withdrawal*", if the *.run file
        has --regtest in it.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_submit.set_defaults(program=submit)
    parser_submit.add_argument('goldenfile')

    parser_convert = subparsers.add_parser(
        'convert',
        help="Convert a test's *.run from testnet to regtest",
        description=textwrap.dedent("""\
        Parse one or more *.run files, which must be withdrawal tests,
        and look for transactions used as inputs. Convert each from
        testnet to regtest (if needed), save the generated input
        transactions in file tx.json, and write out new *.run files
        with all input transactions replaced with regtest versions.

        Running convert on an already-converted file has no effect.

        Test developers are expected to run this once after
        hand-creating any new tests via testnet.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_convert.set_defaults(program=convert)
    parser_convert.add_argument('runfile', nargs='+')

    parser_stop = subparsers.add_parser(
        'stop',
        help="Stop the regtest server",
        description=textwrap.dedent("""\
        Stop the bitcoind regtest server started previously by the
        `start` subcommand, and delete the bitcoin-online-data dir
        that it was using as its data directory.

        Glacier's Makefile runs this command once after all tests
        pass.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_stop.set_defaults(program=stop)

    args = parser.parse_args()

    bitcoin_cli.verbose_mode = args.verbose

    if hasattr(args, 'program'):
        args.program(args)
    else:
        parser.print_usage()


if __name__ == "__main__":
    with glacierscript.subprocess_catcher():
        main()
