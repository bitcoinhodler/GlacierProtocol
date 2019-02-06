#!/usr/bin/env python3

################################################################################################
#
# GlacierScript:  Part of the Glacier Protocol (http://glacierprotocol.org)
#
# GlacierScript is designed specifically for use in the context of executing the broader Glacier
# Protocol, a step-by-step procedure for high-security cold storage of Bitcoin.  It is not
# intended to be used as standalone software.
#
# GlacierScript primarily replaces tasks that users would otherwise be doing manually, such as
# typing things on the command line, copying-and-pasting strings, and hand-editing JSON.  It
# mostly consists of print statements, user input, string & JSON manipulation, and command-line
# wrappers around Bitcoin Core and other applications (e.g. those involved in reading and writing
# QR codes.)
#
# GlacierScript avoids cryptographic and other security-sensitive operations as much as possible.
#
# GlacierScript depends on the following command-line applications:
# - Bitcoin Core (http://bitcoincore.org)
# - qrencode (QR code writer: http://packages.ubuntu.com/xenial/qrencode)
# - zbarimg (QR code reader: http://packages.ubuntu.com/xenial/zbar-tools)
#
################################################################################################

# standard Python libraries
import argparse
from collections import OrderedDict
from decimal import Decimal
import glob
from hashlib import sha256, md5
import json
import os
import shlex
import subprocess
import sys
import time

# Taken from https://github.com/keis/base58
from base58 import b58encode_check

SATOSHI_PLACES = Decimal("0.00000001")

verbose_mode = 0

################################################################################################
#
# Minor helper functions
#
################################################################################################

def hash_sha256(s):
    """A thin wrapper around the hashlib SHA256 library to provide a more functional interface"""
    m = sha256()
    m.update(s.encode('ascii'))
    return m.hexdigest()


def hash_md5(s):
    """A thin wrapper around the hashlib md5 library to provide a more functional interface"""
    m = md5()
    m.update(s.encode('ascii'))
    return m.hexdigest()


def satoshi_to_btc(satoshi):
    """
    Converts a value in satoshi to a value in BTC
    outputs => Decimal

    satoshi: <int>
    """
    value = Decimal(satoshi) / Decimal(100000000)
    return value.quantize(SATOSHI_PLACES)


def btc_to_satoshi(btc):
    """
    Converts a value in BTC to satoshi
    outputs => <int>

    btc: <Decimal> or <Float>
    """
    value = btc * 100000000
    return int(value)


################################################################################################
#
# Subprocess helper functions
#
################################################################################################

def verbose(content):
    if verbose_mode: print(content)


def run_subprocess(exe, *args):
    """
    Run a subprocess (bitcoind or bitcoin-cli)
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
    Run `bitcoin-cli`, return OS return code
    """
    _, retcode, _ = run_subprocess("bitcoin-cli", *args)
    return retcode

def bitcoin_cli_checkcall(*args):
    """
    Run `bitcoin-cli`, ensure no error
    """
    cmd_list, retcode, output = run_subprocess("bitcoin-cli", *args)
    if retcode != 0: raise subprocess.CalledProcessError(retcode, cmd_list, output=output)


def bitcoin_cli_checkoutput(*args):
    """
    Run `bitcoin-cli`, fail if OS return code nonzero, return output
    """
    cmd_list, retcode, output = run_subprocess("bitcoin-cli", *args)
    if retcode != 0: raise subprocess.CalledProcessError(retcode, cmd_list, output=output)
    return output


def bitcoin_cli_json(*args):
    """
    Run `bitcoin-cli`, parse output as JSON
    """
    return json.loads(bitcoin_cli_checkoutput(*args))


def bitcoind_call(*args):
    """
    Run `bitcoind`, return OS return code
    """
    _, retcode, _ = run_subprocess("bitcoind", *args)
    return retcode


################################################################################################
#
# Read & validate random data from the user
#
################################################################################################

def validate_rng_seed(seed, min_length):
    """
    Validates random hexadecimal seed
    returns => <boolean>

    seed: <string> hex string to be validated
    min_length: <int> number of characters required.  > 0
    """

    if len(seed) < min_length:
        print("Error: Computer entropy must be at least {0} characters long".format(min_length))
        return False

    if len(seed) % 2 != 0:
        print("Error: Computer entropy must contain an even number of characters.")
        return False

    try:
        int(seed, 16)
    except ValueError:
        print("Error: Illegal character. Computer entropy must be composed of hexadecimal characters only (0-9, a-f).")
        return False

    return True


def read_rng_seed_interactive(min_length):
    """
    Reads random seed (of at least min_length hexadecimal characters) from standard input
    returns => string

    min_length: <int> minimum number of bytes in the seed.
    """

    char_length = min_length * 2

    def ask_for_rng_seed(length):
        print("Enter at least {0} characters of computer entropy. Spaces are OK, and will be ignored:".format(length))

    ask_for_rng_seed(char_length)
    seed = input()
    seed = unchunk(seed)

    while not validate_rng_seed(seed, char_length):
        ask_for_rng_seed(char_length)
        seed = input()
        seed = unchunk(seed)

    return seed


def validate_dice_seed(dice, min_length):
    """
    Validates dice data (i.e. ensures all digits are between 1 and 6).
    returns => <boolean>

    dice: <string> representing list of dice rolls (e.g. "5261435236...")
    """

    if len(dice) < min_length:
        print("Error: You must provide at least {0} dice rolls".format(min_length))
        return False

    for die in dice:
        try:
            i = int(die)
            if i < 1 or i > 6:
                print("Error: Dice rolls must be between 1 and 6.")
                return False
        except ValueError:
            print("Error: Dice rolls must be numbers between 1 and 6")
            return False

    return True


def read_dice_seed_interactive(min_length):
    """
    Reads min_length dice rolls from standard input, as a string of consecutive integers
    Returns a string representing the dice rolls
    returns => <string>

    min_length: <int> number of dice rolls required.  > 0.
    """

    def ask_for_dice_seed(x):
        print("Enter {0} dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:".format(x))

    ask_for_dice_seed(min_length)
    dice = input()
    dice = unchunk(dice)

    while not validate_dice_seed(dice, min_length):
        ask_for_dice_seed(min_length)
        dice = input()
        dice = unchunk(dice)

    return dice


################################################################################################
#
# private key generation
#
################################################################################################

def xor_hex_strings(str1, str2):
    """
    Return xor of two hex strings.
    An XOR of two pieces of data will be as random as the input with the most randomness.
    We can thus combine two entropy sources in this way as a safeguard against one source being
    compromised in some way.
    For details, see http://crypto.stackexchange.com/a/17660

    returns => <string> in hex format
    """
    if len(str1) != len(str2):
        raise Exception("tried to xor strings of unequal length")
    str1_dec = int(str1, 16)
    str2_dec = int(str2, 16)

    xored = str1_dec ^ str2_dec

    return "{:0{}x}".format(xored, len(str1))


def hex_private_key_to_WIF_private_key(hex_key):
    """
    Converts a raw 256-bit hex private key to WIF format
    returns => <string> in hex format
    """
    hex_key_with_prefix = wif_prefix + hex_key + "01"
    wif_key = b58encode_check(bytes.fromhex(hex_key_with_prefix))
    return wif_key.decode('ascii')



################################################################################################
#
# Local exception classes
#
################################################################################################

class GlacierExcessiveFee(Exception):
    """
    Raised when transaction fee is determined to be excessive.
    """

################################################################################################
#
# Bitcoin helper functions
#
################################################################################################

def ensure_bitcoind_running():
    """
    Start bitcoind (if it's not already running) and ensure it's functioning properly
    """
    # start bitcoind.  If another bitcoind process is already running, this will just print an error
    # message (to /dev/null) and exit.
    #
    # -connect=0.0.0.0 because we're doing local operations only (and have no network connection anyway)
    bitcoind_call("-daemon", "-connect=0.0.0.0")

    # verify bitcoind started up and is functioning correctly
    times = 0
    while times <= 20:
        times += 1
        if bitcoin_cli_call("getnetworkinfo") == 0:
            # getaddressinfo API changed in v0.18.0
            require_minimum_bitcoind_version(180000)
            return
        time.sleep(0.5)

    raise Exception("Timeout while starting bitcoin server")

def require_minimum_bitcoind_version(min_version):
    """
    Fail if the bitcoind version in use is older than required
    <min_version> - required minimum version in format of getnetworkinfo, i.e. 150100 for v0.15.1
    """
    networkinfo = bitcoin_cli_json("getnetworkinfo")

    if int(networkinfo["version"]) < min_version:
        print("ERROR: Your bitcoind version is too old. You have {}, I need {} or newer. Exiting...".format(networkinfo["version"], min_version))
        sys.exit()

def get_pubkey_for_wif_privkey(privkey):
    """A method for retrieving the pubkey associated with a private key from bitcoin core
       <privkey> - a bitcoin private key in WIF format"""

    # Bitcoin Core doesn't have an RPC for "get the addresses associated w/this private key"
    # just "get the addresses associated with this label"
    # where "label" corresponds to an arbitrary tag we can associate with each private key
    # so, we'll generate a unique "label" to attach to this private key.

    label = hash_sha256(privkey)

    ensure_bitcoind_running()
    bitcoin_cli_checkcall("importprivkey", privkey, label)
    addresses = bitcoin_cli_json("getaddressesbylabel", label)

    # getaddressesbylabel returns multiple addresses associated with
    # this one privkey; since we use it only for communicating the
    # pubkey to addmultisigaddress, it doesn't matter which one we
    # choose; they are all associated with the same pubkey.

    address = next(iter(addresses))

    validate_output = bitcoin_cli_json("getaddressinfo", address)
    return validate_output["pubkey"]


def addmultisigaddress(m, pubkeys, address_type='p2sh-segwit'):
    """
    Call `bitcoin-cli addmultisigaddress`
    returns => JSON response from bitcoin-cli

    m: <int> number of multisig keys required for withdrawal
    pubkeys: List<string> hex pubkeys for each of the N keys
    """
    pubkey_string = json.dumps(pubkeys)
    return bitcoin_cli_json("addmultisigaddress", str(m), pubkey_string, "", address_type)


def get_fee_interactive(xact, destinations):
    """
    Returns a recommended transaction fee, given market fee data provided by the user interactively
    Because fees tend to be a function of transaction size, we build the transaction in order to
    recomend a fee.
    return => <Decimal> fee value

    Parameters:
      xact: WithdrawalXact object
      destinations: {address <string>: amount<string>} dictionary mapping destination addresses to amount in BTC
    """

    ensure_bitcoind_running()

    approve = False
    while not approve:
        print("\nEnter fee rate.")
        xact.fee_basis_satoshis_per_byte = int(input("Satoshis per vbyte: "))
        try:
            fee = xact.calculate_fee(destinations)
        except GlacierExcessiveFee as e:
            print(e)
        else:
            print("\nBased on the provided rate, the fee will be {} bitcoin.".format(fee))
            confirm = yes_no_interactive()

            if confirm:
                approve = True
            else:
                print("\nFee calculation aborted. Starting over...")

    return fee


################################################################################################
#
# Withdrawal transaction construction class
#
################################################################################################

class WithdrawalXact:
    """
    Class for constructing a withdrawal transaction

    Attributes:
    source_address: <string> input_txs will be filtered for utxos to this source address
    redeem_script: <string>
    """

    MAX_FEE = .005  # in btc.  hardcoded limit to protect against user typos

    def __init__(self, source_address, redeem_script):
        self.source_address = source_address
        self.redeem_script = redeem_script
        self._seen_txhashes = set()  # only for detecting duplicates
        self._inputs = []
        self.keys = []
        self._validate_address()
        self._teach_address_to_wallet()
        self._pubkeys = self._find_pubkeys()

    def add_key(self, key):
        self.keys.append(key)
        # Teach the wallet about this key
        pubkey = get_pubkey_for_wif_privkey(key)
        if pubkey not in self._pubkeys:
            print("ERROR: that key does not belong to this source address, exiting...")
            sys.exit()

    def create_signed_transaction(self, destinations):
        """
        Returns a hex string representing a signed bitcoin transaction
        returns => <string>

        destinations: {address <string>: amount<string>} dictionary mapping destination addresses to amount in BTC
        """
        ensure_bitcoind_running()

        # prune destination addresses sent 0 btc
        destinations = OrderedDict((key, val) for key, val in destinations.items() if val != '0')

        prev_txs = json.dumps(self._inputs)
        tx_unsigned_hex = bitcoin_cli_checkoutput(
            "createrawtransaction",
            prev_txs,
            json.dumps(destinations)).strip()

        signed_tx = bitcoin_cli_json(
            "signrawtransactionwithwallet",
            tx_unsigned_hex, prev_txs)
        return signed_tx

    def unspent_total(self):
        """
        Return the total amount of BTC available to spend from the input UTXOs
        """
        return sum(Decimal(utxo["amount"]).quantize(SATOSHI_PLACES) for utxo in self._inputs)

    def add_input_xact(self, hex_tx):
        """
        Look for outputs in the supplied transaction which match our cold storage address.
        Save them for later use in constructing the withdrawal.

        hex_tx (string): hex-encoded transaction whose outputs we want to spend
        """
        # For each UTXO used as input, we need the txid, vout index, scriptPubKey, amount, and redeemScript
        # to generate a signature
        tx = bitcoin_cli_json("decoderawtransaction", hex_tx)
        if tx['hash'] in self._seen_txhashes:
            print("ERROR: duplicated input transactions, exiting...")
            sys.exit()
        self._seen_txhashes.add(tx['hash'])

        utxos = self._get_utxos(tx)
        if len(utxos) == 0:
            print("\nTransaction data not found for source address: {}".format(self.source_address))
            sys.exit()

        txid = tx["txid"]
        for utxo in utxos:
            self._inputs.append(OrderedDict([
                ("txid", txid),
                ("vout", int(utxo["n"])),
                ("amount", utxo["value"]),
                ("scriptPubKey", utxo["scriptPubKey"]["hex"]),
                ("redeemScript", self.redeem_script),
            ]))

    def _teach_address_to_wallet(self):
        """
        Teaches the bitcoind wallet about our multisig address, so it can
        use that knowledge to sign the transaction we're about to create.
        """

        # If address is p2wsh-in-p2sh, then the user-provided
        # redeem_script is actually witnessScript, and I need to get the
        # redeemScript from `decodescript`.

        decoded_script = bitcoin_cli_json("decodescript", self.redeem_script)

        import_this = {
            "scriptPubKey": { "address": self.source_address },
            "timestamp": "now",
            "watchonly": True # to avoid warning about "Some private keys are missing[...]"
        }
        if decoded_script["p2sh"] == self.source_address:
            import_this["redeemscript"] = self.redeem_script
        else:
            # segwit (either p2wsh or p2sh-in-p2wsh)
            import_this["witnessscript"] = self.redeem_script
            if self.source_address == decoded_script["segwit"]["p2sh-segwit"]:
                import_this["redeemscript"] = decoded_script["segwit"]["hex"]
        results = bitcoin_cli_json("importmulti", json.dumps([import_this]))
        if not all(result["success"] for result in results) or \
           any("warnings" in result for result in results):
            raise Exception("Problem importing address to wallet")

    def _find_pubkeys(self):
        """
        Return a list of the pubkeys associated with our source address.

        Assumes that source_address has already been imported to the wallet using `importmulti`
        """
        out = bitcoin_cli_json("getaddressinfo", self.source_address)
        if "pubkeys" in out:
            return out["pubkeys"] # for non-segwit addresses
        else:
            return out["embedded"]["pubkeys"] # for segwit addresses

    def _validate_address(self):
        """
        Given our source cold storage address and redemption script,
        make sure the redeem script is valid and matches the address.
        """
        decoded_script = bitcoin_cli_json("decodescript", self.redeem_script)
        if decoded_script["type"] != "multisig":
            print("ERROR: Unrecognized redemption script. Doublecheck for typos. Exiting...")
            sys.exit()
        ok_addresses = [decoded_script["p2sh"]]
        if "segwit" in decoded_script:
            ok_addresses.append(decoded_script["segwit"]["p2sh-segwit"])
            ok_addresses.extend(decoded_script["segwit"]["addresses"])
        if self.source_address not in ok_addresses:
            print("ERROR: Redemption script does not match cold storage address. Doublecheck for typos. Exiting...")
            sys.exit()

    def _get_utxos(self, tx):
        """
        Given a transaction, find all the outputs that were sent to an address
        returns => List<Dictionary> list of UTXOs in bitcoin core format

        tx - <Dictionary> in bitcoin core format
        """
        utxos = []

        for output in tx["vout"]:
            if "addresses" not in output["scriptPubKey"]:
                # In Bitcoin Core versions older than v0.16, native segwit outputs have no address decoded
                continue
            out_addresses = output["scriptPubKey"]["addresses"]
            amount_btc = output["value"]
            if self.source_address in out_addresses:
                utxos.append(output)

        return utxos

    def calculate_fee(self, destinations):
        """
        Given a list of destinations, calculate the total fee in BTC at the given basis
        returbs => Decimal total fee in BTC

        destinations - <Dictionary> pairs of {addresss:amount} to send
        """
        signed_tx = self.create_signed_transaction(destinations)

        decoded_tx = bitcoin_cli_json("decoderawtransaction", signed_tx["hex"])
        size = decoded_tx["vsize"]

        fee = satoshi_to_btc(size * self.fee_basis_satoshis_per_byte)
        if fee > self.MAX_FEE:
            raise GlacierExcessiveFee("Calculated fee ({}) is too high. Must be under {}".format(fee, self.MAX_FEE))
        return fee



################################################################################################
#
# QR code helper functions
#
################################################################################################

def decode_one_qr(filename):
    """
    Decode a QR code from an image file, and return the decoded string.
    """
    zresults = subprocess.run(["zbarimg", "--set", "*.enable=0", "--set", "qr.enable=1",
                              "--quiet", "--raw", filename], check=True, stdout=subprocess.PIPE)
    return zresults.stdout.decode('ascii').strip()


def decode_qr(filenames):
    """
    Decode a (series of) QR codes from a (series of) image file(s), and return the decoded string.
    """
    return ''.join(decode_one_qr(f) for f in filenames)


def write_qr_code(filename, data):
    """
    Write one QR code.
    """
    subprocess.run(["qrencode", "-o", filename, data], check=True)


def write_and_verify_qr_code(name, filename, data):
    """
    Write a QR code and then read it back to try and detect any tricksy malware tampering with it.

    name: <string> short description of the data
    filename: <string> filename for storing the QR code
    data: <string> the data to be encoded

    If data fits in a single QR code, we use filename directly. Otherwise
    we add "-%02d" to each filename; e.g. transaction-01.png transaction-02.png.

    The `qrencode` program can do this directly using "structured symbols" with
    its -S option, but `zbarimg` doesn't recognize those at all. See:
    https://github.com/mchehab/zbar/issues/66

    It's also possible that some mobile phone QR scanners won't recognize such
    codes. So we split it up manually here.

    The theoretical limit of alphanumeric QR codes is 4296 bytes, though
    somehow qrencode can do up to 4302.

    """
    # Remove any stale files, so we don't confuse user if a previous
    # withdrawal created 3 files (or 1 file) and this one only has 2
    base, ext = os.path.splitext(filename)
    for deleteme in glob.glob("{}*{}".format(base, ext)):
        os.remove(deleteme)
    MAX_QR_LEN = 4296
    if len(data) <= MAX_QR_LEN:
        write_qr_code(filename, data)
        filenames = [filename]
    else:
        idx = 1
        filenames = []
        intdata = data
        while len(intdata) > 0:
            thisdata = intdata[0:MAX_QR_LEN]
            intdata = intdata[MAX_QR_LEN:]
            thisfile = "{}-{:02d}{}".format(base, idx, ext)
            filenames.append(thisfile)
            write_qr_code(thisfile, thisdata)
            idx += 1

    qrdata = decode_qr(filenames)
    if qrdata != data:
        print("********************************************************************")
        print("WARNING: {} QR code could not be verified properly. This could be a sign of a security breach.".format(name))
        print("********************************************************************")

    print("QR code for {0} written to {1}".format(name, ','.join(filenames)))


################################################################################################
#
# User sanity checking
#
################################################################################################

def yes_no_interactive():
    def confirm_prompt():
        return input("Confirm? (y/n): ")

    confirm = confirm_prompt()

    while True:
        if confirm.upper() == "Y":
            return True
        if confirm.upper() == "N":
            return False
        else:
            print("You must enter y (for yes) or n (for no).")
            confirm = confirm_prompt()

def safety_checklist():

    checks = [
        "Are you running this on a computer WITHOUT a network connection of any kind?",
        "Have the wireless cards in this computer been physically removed?",
        "Are you running on battery power?",
        "Are you running on an operating system booted from a USB drive?",
        "Is your screen hidden from view of windows, cameras, and other people?",
        "Are smartphones and all other nearby devices turned off and in a Faraday bag?"]

    for check in checks:
        answer = input(check + " (y/n)?")
        if answer.upper() != "Y":
            print("\n Safety check failed. Exiting.")
            sys.exit()


################################################################################################
#
# Main "entropy" function
#
################################################################################################


def unchunk(string):
    """
    Remove spaces in string
    """
    return string.replace(" ", "")


def chunk_string(string, length):
    """
    Splits a string into chunks of [length] characters, for easy human readability
    Source: https://stackoverflow.com/a/18854817/11031317
    """
    return (string[0+i:length+i] for i in range(0, len(string), length))


def entropy(n, length):
    """
    Generate n random strings for the user from /dev/random
    """
    safety_checklist()

    print("\n\n")
    print("Making {} random data strings....".format(n))
    print("If strings don't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.\n")

    idx = 0
    while idx < n:
        seed = subprocess.check_output(
            "xxd -l {} -p /dev/random".format(length), shell=True)
        idx += 1
        seed = seed.decode('ascii').replace('\n', '')
        print("Computer entropy #{0}: {1}".format(idx, " ".join(chunk_string(seed, 4))))


################################################################################################
#
# Main "deposit" function
#
################################################################################################

def deposit_interactive(m, n, dice_seed_length=62, rng_seed_length=20, p2wsh=False):
    """
    Generate data for a new cold storage address (private keys, address, redemption script)
    m: <int> number of multisig keys required for withdrawal
    n: <int> total number of multisig keys
    dice_seed_length: <int> minimum number of dice rolls required
    rng_seed_length: <int> minimum length of random seed required
    p2wsh: if True, generate p2wsh instead of p2wsh-in-p2sh
    """

    safety_checklist()
    ensure_bitcoind_running()

    print("\n")
    print("Creating {0}-of-{1} cold storage address.\n".format(m, n))

    keys = []

    while len(keys) < n:
        index = len(keys) + 1
        print("\nCreating private key #{}".format(index))

        dice_seed_string = read_dice_seed_interactive(dice_seed_length)
        dice_seed_hash = hash_sha256(dice_seed_string)

        rng_seed_string = read_rng_seed_interactive(rng_seed_length)
        rng_seed_hash = hash_sha256(rng_seed_string)

        # back to hex string
        hex_private_key = xor_hex_strings(dice_seed_hash, rng_seed_hash)
        WIF_private_key = hex_private_key_to_WIF_private_key(hex_private_key)
        keys.append(WIF_private_key)

    print("Private keys created.")
    print("Generating {0}-of-{1} cold storage address...\n".format(m, n))

    pubkeys = [get_pubkey_for_wif_privkey(key) for key in keys]
    address_type = 'bech32' if p2wsh else 'p2sh-segwit'
    results = addmultisigaddress(m, pubkeys, address_type)

    print("Private keys:")
    for idx, key in enumerate(keys):
        print("Key #{0}: {1}".format(idx + 1, key))

    print("\nCold storage address:")
    print("{}".format(results["address"]))

    print("\nRedemption script:")
    print("{}".format(results["redeemScript"]))
    print("")

    write_and_verify_qr_code("cold storage address", "address.png", results["address"])
    write_and_verify_qr_code("redemption script", "redemption.png",
                       results["redeemScript"])


################################################################################################
#
# Main "withdraw" function
#
################################################################################################

def withdraw_interactive():
    """
    Construct and sign a transaction to withdaw funds from cold storage
    All data required for transaction construction is input at the terminal
    """

    safety_checklist()
    ensure_bitcoind_running()

    approve = False

    while not approve:
        addresses = OrderedDict()

        print("\nYou will need to enter several pieces of information to create a withdrawal transaction.")
        print("\n\n*** PLEASE BE SURE TO ENTER THE CORRECT DESTINATION ADDRESS ***\n")

        source_address = input("\nSource cold storage address: ")
        addresses[source_address] = 0

        redeem_script = input("\nRedemption script for source cold storage address: ")
        xact = WithdrawalXact(source_address, redeem_script)

        dest_address = input("\nDestination address: ")
        addresses[dest_address] = 0

        num_tx = int(input("\nHow many unspent transactions will you be using for this withdrawal? "))


        for txcount in range(num_tx):
            print("\nPlease paste raw transaction #{} (hexadecimal format) with unspent outputs at the source address".format(txcount + 1))
            print("OR")
            print("input a filename located in the current directory which contains the raw transaction data")
            print("(If the transaction data is over ~4000 characters long, you _must_ use a file.):")

            hex_tx = input()
            if os.path.isfile(hex_tx):
                hex_tx = open(hex_tx).read().strip()

            xact.add_input_xact(hex_tx)

        print("\nTransaction data found for source address.")

        utxo_sum = xact.unspent_total()

        print("TOTAL unspent amount for this raw transaction: {} BTC".format(utxo_sum))

        print("\nHow many private keys will you be signing this transaction with? ")
        key_count = int(input("#: "))

        for key_idx in range(key_count):
            key = input("Key #{0}: ".format(key_idx + 1))
            xact.add_key(key)

        ###### fees, amount, and change #######

        input_amount = utxo_sum
        fee = get_fee_interactive(xact, addresses)
        # Got this far
        if fee > input_amount:
            print("ERROR: Your fee is greater than the sum of your unspent transactions.  Try using larger unspent transactions. Exiting...")
            sys.exit()

        print("\nPlease enter the decimal amount (in bitcoin) to withdraw to the destination address.")
        print("\nExample: For 2.3 bitcoins, enter \"2.3\".")
        print("\nAfter a fee of {0}, you have {1} bitcoins available to withdraw.".format(fee, input_amount - fee))
        print("\n*** Technical note for experienced Bitcoin users:  If the withdrawal amount & fee are cumulatively less than the total amount of the unspent transactions, the remainder will be sent back to the same cold storage address as change. ***\n")
        withdrawal_amount = input(
            "Amount to send to {0} (leave blank to withdraw all funds stored in these unspent transactions): ".format(dest_address))
        if withdrawal_amount == "":
            withdrawal_amount = input_amount - fee
        else:
            withdrawal_amount = Decimal(withdrawal_amount).quantize(SATOSHI_PLACES)

        if fee + withdrawal_amount > input_amount:
            print("Error: fee + withdrawal amount greater than total amount available from unspent transactions")
            raise Exception("Output values greater than input value")

        change_amount = input_amount - withdrawal_amount - fee

        # less than a satoshi due to weird floating point imprecision
        if change_amount < 1e-8:
            change_amount = 0

        if change_amount > 0:
            print("{0} being returned to cold storage address address {1}.".format(change_amount, xact.source_address))

        addresses[dest_address] = str(withdrawal_amount)
        addresses[xact.source_address] = str(change_amount)

        # check data
        print("\nIs this data correct?")
        print("*** WARNING: Incorrect data may lead to loss of funds ***\n")

        print("{0} BTC in unspent supplied transactions".format(input_amount))
        for address, value in addresses.items():
            if address == xact.source_address:
                print("{0} BTC going back to cold storage address {1}".format(value, address))
            else:
                print("{0} BTC going to destination address {1}".format(value, address))
        print("Fee amount: {0}".format(fee))
        print("\nSigning with private keys: ")
        for key in xact.keys:
            print("{}".format(key))

        print("\n")
        confirm = yes_no_interactive()

        if confirm:
            approve = True
        else:
            print("\nProcess aborted. Starting over....")

    #### Calculate Transaction ####
    print("\nCalculating transaction...\n")

    signed_tx = xact.create_signed_transaction(addresses)

    print("\nSufficient private keys to execute transaction?")
    print(signed_tx["complete"])

    print("\nRaw signed transaction (hex):")
    print(signed_tx["hex"])

    print("\nTransaction fingerprint (md5):")
    print(hash_md5(signed_tx["hex"]))

    write_and_verify_qr_code("transaction", "transaction.png", signed_tx["hex"].upper())


################################################################################################
#
# main function
#
# Show help, or execute one of the three main routines: entropy, deposit, withdraw
#
################################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('program', choices=[
                        'entropy', 'create-deposit-data', 'create-withdrawal-data'])

    parser.add_argument("--num-keys", type=int,
                        help="The number of keys to create random entropy for", default=1)
    parser.add_argument("-d", "--dice", type=int,
                        help="The minimum number of dice rolls to use for entropy when generating private keys (default: 62)", default=62)
    parser.add_argument("-r", "--rng", type=int,
                        help="Minimum number of 8-bit bytes to use for computer entropy when generating private keys (default: 20)", default=20)
    parser.add_argument(
        "-m", type=int, help="Number of signing keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=1)
    parser.add_argument(
        "-n", type=int, help="Number of total keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=2)
    parser.add_argument(
        "--p2wsh", action="store_true", help="Generate p2wsh (native segwit) deposit address, instead of p2wsh-in-p2sh")
    parser.add_argument('--testnet', type=int, help=argparse.SUPPRESS)
    parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')
    args = parser.parse_args()

    verbose_mode = args.verbose

    global cli_args, wif_prefix
    cli_args = ["-testnet", "-rpcport={}".format(args.testnet), "-datadir=bitcoin-test-data"] if args.testnet else []
    wif_prefix = "EF" if args.testnet else "80"

    if args.program == "entropy":
        entropy(args.num_keys, args.rng)

    if args.program == "create-deposit-data":
        deposit_interactive(args.m, args.n, args.dice, args.rng, args.p2wsh)

    if args.program == "create-withdrawal-data":
        withdraw_interactive()
