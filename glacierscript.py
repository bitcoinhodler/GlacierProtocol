#!/usr/bin/env python3
"""
GlacierScript: Part of the Glacier Protocol for Bitcoin storage.

https://glacierprotocol.org

GlacierScript is designed specifically for use in the context of
executing the broader Glacier Protocol, a step-by-step procedure for
high-security cold storage of Bitcoin. It is not intended to be used
as standalone software.

GlacierScript primarily replaces tasks that users would otherwise be
doing manually, such as typing things on the command line,
copying-and-pasting strings, and hand-editing JSON. It mostly
consists of print statements, user input, string & JSON manipulation,
and command-line wrappers around Bitcoin Core and other applications
(e.g. those involved in reading and writing QR codes.)

GlacierScript avoids cryptographic and other security-sensitive
operations as much as possible.

GlacierScript depends on the following command-line applications:

* Bitcoin Core (http://bitcoincore.org)

* qrencode (QR code writer:
  http://packages.ubuntu.com/xenial/qrencode)

* zbarimg (QR code reader:
  http://packages.ubuntu.com/xenial/zbar-tools)

"""

# standard Python libraries
from abc import ABCMeta, abstractmethod
import argparse
from collections import OrderedDict
import contextlib
from decimal import Decimal
import glob
from hashlib import sha256, md5
import json
import os
import re
import subprocess
import sys
import time

# Taken from https://github.com/keis/base58
from base58 import b58encode_check
import bitcoin_cli

SATOSHI_PLACES = Decimal("0.00000001")
wif_prefix = None


################################################################################################
#
# Minor helper functions
#
################################################################################################


def hash_sha256(val):
    """
    Return the SHA256 hash of the provided string.

    This is just a thin wrapper around the hashlib SHA256 library to
    provide a more functional interface.
    """
    hasher = sha256()
    hasher.update(val.encode('ascii'))
    return hasher.hexdigest()


def hash_md5(val):
    """
    Return the MD5 hash of the provided string.

    This is just a thin wrapper around the hashlib md5 library to
    provide a more functional interface.
    """
    hasher = md5()
    hasher.update(val.encode('ascii'))
    return hasher.hexdigest()


def satoshi_to_btc(satoshi):
    """
    Convert a value in satoshi to a value in BTC.

    outputs => Decimal

    satoshi: <int>
    """
    value = Decimal(satoshi) / Decimal(100000000)
    return value.quantize(SATOSHI_PLACES)


def address_from_vout(vout):
    """
    Given a vout from decoderawtransaction, return the Bitcoin address.
    """
    # Bitcoin Core <22.0 has list "addresses" (but always 0 or 1);
    # Bitcoin Core 22.0 has scalar "address"
    addrs = vout["scriptPubKey"].get("addresses", [
        vout["scriptPubKey"].get("address", None)
    ])
    if len(addrs) > 1:
        raise TypeError("how does one scriptPubKey have >1 corresponding address?")
    return addrs[0] if addrs else None


################################################################################################
#
# Read & validate random data from the user
#
################################################################################################

def validate_rng_seed(seed, min_length):
    """
    Validate random hexadecimal seed.

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
    Read random seed (of at least min_length hexadecimal characters) from standard input.

    returns => string

    min_length: <int> minimum number of bytes in the seed.
    """
    char_length = min_length * 2

    done = False
    while not done:
        print("Enter at least {0} characters of computer entropy. Spaces are OK, and will be ignored:".format(char_length))
        seed = input()
        seed = unchunk(seed)
        done = validate_rng_seed(seed, char_length)
    return seed


def validate_dice_seed(dice, min_length):
    """
    Validate dice data (i.e. ensures all digits are between 1 and 6).

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
    Read min_length dice rolls from standard input, as a string of consecutive integers.

    Returns a string representing the dice rolls
    returns => <string>

    min_length: <int> number of dice rolls required.  > 0.
    """
    done = False
    while not done:
        print("Enter {0} dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:".format(min_length))
        dice = input()
        dice = unchunk(dice)
        done = validate_dice_seed(dice, min_length)

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
        raise Exception("tried to xor strings of unequal length")  # pragma: no cover
    str1_dec = int(str1, 16)
    str2_dec = int(str2, 16)

    xored = str1_dec ^ str2_dec

    return "{:0{}x}".format(xored, len(str1))


def hex_private_key_to_wif_private_key(hex_key):
    """
    Convert a raw 256-bit hex private key to WIF format.

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


class GlacierFatal(Exception):
    """
    Raised when fatal error is detected.
    """

################################################################################################
#
# Bitcoin helper functions
#
################################################################################################


def ensure_bitcoind_running(*extra_args, descriptors=False):
    """
    Start bitcoind (if it's not already running) and ensure it's functioning properly.
    """
    # start bitcoind.  If another bitcoind process is already running, this will just print an error
    # message (to /dev/null) and exit.
    #
    # -connect=0.0.0.0 because we're doing local operations only (and have no network connection anyway)
    bitcoin_cli.bitcoind_call("-daemon", "-connect=0.0.0.0", *extra_args)

    # verify bitcoind started up and is functioning correctly
    times = 0
    while times <= 20:
        times += 1
        if bitcoin_cli.call("getnetworkinfo") == 0:
            # We need to support PSBTs that have both witness and non-witness data.
            # See https://github.com/bitcoin/bitcoin/pull/19215
            require_minimum_bitcoind_version(200100)
            create_default_wallet(descriptors=descriptors)
            ensure_expected_wallet(descriptors=descriptors)
            return
        time.sleep(0.5)

    raise Exception("Timeout while starting bitcoin server")  # pragma: no cover


def create_default_wallet(descriptors=False):
    """
    Ensure our wallet exists and is loaded.
    """
    # Anything other than "" requires -rpcwallet= on every bitcoin-cli call:
    wallet_name = ""
    loaded_wallets = bitcoin_cli.json("listwallets")
    if wallet_name in loaded_wallets:
        return  # our wallet already loaded
    all_wallets = bitcoin_cli.json("listwalletdir")
    # {
    #     "wallets": [
    #         {
    #             "name": ""
    #         }
    #     ]
    # }
    found = any(w["name"] == wallet_name for w in all_wallets["wallets"])
    cmd = ["loadwallet", wallet_name] if found else \
        [
            "-named",
            "createwallet",
            "wallet_name=" + wallet_name,
            "descriptors=" + ("true" if descriptors else "false"),
            "blank=true",
        ]
    loaded_wallet = bitcoin_cli.json(*cmd)
    if loaded_wallet["warning"] \
       and not loaded_wallet["warning"].startswith("Wallet created successfully"):
        raise Exception("problem running {} on default wallet".format(cmd))  # pragma: no cover


def ensure_expected_wallet(descriptors=False):
    """
    Ensure the expected wallet exists and is the expected type.

    Descriptor wallets are the future but will take some work to
    support throughout Glacier.
    """
    info = bitcoin_cli.json("getwalletinfo")
    if info.get("descriptors", False) != descriptors:
        if descriptors:
            raise Exception("default wallet is a legacy wallet; expected a descriptor wallet")
        raise Exception("default wallet is a descriptor wallet; expected a legacy wallet")


def require_minimum_bitcoind_version(min_version):
    """
    Fail if the bitcoind version in use is older than required.

    <min_version> - required minimum version in format of getnetworkinfo, i.e. 150100 for v0.15.1
    """
    networkinfo = bitcoin_cli.json("getnetworkinfo")

    if int(networkinfo["version"]) < min_version:
        raise GlacierFatal("Your bitcoind version is too old. You have {}, I need {} or newer".format(networkinfo["version"], min_version))  # pragma: no cover


def get_pubkey_for_wif_privkey(privkey):
    """
    Return pubkey associated with a private key.

    Runs Bitcoin Core to do the necessary calculations.

    <privkey> - a bitcoin private key in WIF format
    """
    dinfo = bitcoin_cli.json("getdescriptorinfo", "pkh({})".format(privkey))
    # The pubkey is displayed in the "descriptor" returned by getdescriptorinfo:
    #  "descriptor": "pkh(0277f15f22aeffaf3f3bc48a280a767f7c6af21276783c09ff3bcaabbece178113)#7d2u80af",
    pubkey_match = re.match(r"pkh\((.*)\)", dinfo["descriptor"])
    if not pubkey_match:
        raise GlacierFatal("unable to find pubkey in descriptor")
    return pubkey_match.group(1)


def build_descriptor(nrequired, keys, address_format):
    """
    Return (descriptor_with_privkeys, descriptor_with_pubkeys) for the specified multisig.

    nrequired: <int> number of multisig keys required for withdrawal
    keys: List<string> pubkeys or privkeys
    address_format: <string> 'p2sh', 'p2sh-p2wsh', or 'p2wsh'
    """
    base_desc = "multi({},{})".format(
        nrequired,
        ",".join(keys)
    )
    form = {
        'p2sh': "sh({})",
        'p2wsh': "wsh({})",
        'p2sh-p2wsh': "sh(wsh({}))",
    }
    if address_format not in form:
        raise GlacierFatal("Unrecognized address_format")
    desc = form[address_format].format(base_desc)
    dinfo = bitcoin_cli.json("getdescriptorinfo", desc)
    with_privkeys = desc + "#" + dinfo["checksum"]
    with_pubkeys = dinfo["descriptor"]
    return (with_privkeys, with_pubkeys)


def get_fee_interactive(xact, destinations):
    """
    Return a recommended transaction fee, given market fee data provided by the user interactively.

    Because fees tend to be a function of transaction size, we build the transaction in order to
    recommend a fee.
    return => <Decimal> fee value

    xact: WithdrawalXact object
    destinations: {address <string>: amount<string>} dictionary mapping destination addresses to amount in BTC
    """
    approve = False
    while not approve:
        print("\nEnter fee rate.")
        xact.fee_basis_satoshis_per_byte = int(input("Satoshis per vbyte: "))
        try:
            fee = xact.calculate_fee(destinations)
        except GlacierExcessiveFee as exc:
            print(exc)
        else:
            print("\nBased on the provided rate, the fee will be {} bitcoin.".format(fee))
            confirm = yes_no_interactive()

            if confirm:
                approve = True
            else:
                print("\nFee calculation aborted. Starting over...")

    return fee


# From https://stackoverflow.com/a/3885198 modified to dump as string, so no floats ever involved
class DecimalEncoder(json.JSONEncoder):
    """
    Encoder class for json.dumps() that dumps Decimal as a string.
    """

    def default(self, o):  # noqa:pylint:method-hidden
        """
        Convert anything that's not one of the built-in JSON types.
        """
        if isinstance(o, Decimal):
            return str(o)
        return super().default(o)  # pragma: no cover


def jsonstr(thing):
    """
    Return a JSON string representation of thing.

    Decimal values are encoded as strings to avoid any floating point imprecision.
    """
    return json.dumps(thing, cls=DecimalEncoder, sort_keys=True)


################################################################################################
#
# Final output representation
#
################################################################################################

class FinalOutput(metaclass=ABCMeta):
    """Represent either completed transaction or sequential-signed PSBT."""

    @abstractmethod
    def __str__(self):
        """Return string formatted for console output."""

    @abstractmethod
    def value_to_hash(self):
        """Return string to hash for transaction validation."""

    @abstractmethod
    def qr_string(self):
        """Return string to convert to QR code."""


class RawTransactionFinalOutput(FinalOutput):
    """Represent completed raw transaction."""

    def __init__(self, *, fee, rawxact):
        """Construct new object."""
        self.fee = fee
        self.rawxact = rawxact

    def __str__(self):
        """Return string formatted for console output."""
        final_decoded = bitcoin_cli.json("decoderawtransaction", self.rawxact)
        feerate = self.fee / SATOSHI_PLACES / final_decoded['vsize']
        return "Final fee rate: {:0.2f} satoshis per vbyte\n\n".format(feerate) \
            + "Raw signed transaction (hex):\n" + self.rawxact

    def value_to_hash(self):
        """Return string to hash for transaction validation."""
        return self.rawxact

    def qr_string(self):
        """Return string to convert to QR code."""
        # Raw hex values are case-insensitive, and QR codes are more
        # efficient when all upper-case.
        return self.rawxact.upper()


class PsbtFinalOutput(FinalOutput):
    """Represent incompletely-signed PSBT."""

    def __init__(self, *, psbt):
        """Construct new object."""
        self.psbt = psbt

    def __str__(self):
        """Return string formatted for console output."""
        return "Incomplete PSBT (base64):\n" + self.psbt

    def value_to_hash(self):
        """Return string to hash for transaction validation."""
        return self.psbt

    def qr_string(self):
        """Return string to convert to QR code."""
        return self.psbt


################################################################################################
#
# Withdrawal transaction construction class
#
################################################################################################

class BaseWithdrawalXact:
    """Class representing withdrawal transaction, either via input TXs or PSBT."""

    def __init__(self, source_address, redeem_script):
        """
        Construct a new withdrawal.
        """
        self.source_address = source_address
        self.redeem_script = redeem_script
        self.keys = []  # tuples of (privkey, pubkey)
        self.segwit = self._validate_address()
        self.sigsrequired, self._pubkeys = self._find_pubkeys()
        self.fee = None  # not yet known

    def add_key(self, privkey):
        """
        Use the (WIF format) private key for signing this withdrawal.
        """
        pubkey = get_pubkey_for_wif_privkey(privkey)
        self.keys.append((privkey, pubkey))
        if pubkey not in self._pubkeys:
            raise GlacierFatal("that key does not belong to this source address")
        return pubkey

    def _validate_address(self):
        """
        Validate the supplied cold storage address and redemption script.

        Given our source cold storage address and redemption script,
        make sure the redeem script is valid and matches the address.

        Returns True iff address is segwit (either p2wsh-in-p2sh or p2wsh).
        """
        decoded_script = bitcoin_cli.json("decodescript", self.redeem_script)
        if decoded_script["type"] != "multisig":
            raise GlacierFatal("Unrecognized redemption script. Doublecheck for typos")
        if self.source_address == decoded_script["p2sh"]:
            return False
        if "segwit" in decoded_script:
            if self.source_address in [decoded_script["segwit"]["p2sh-segwit"],
                                       decoded_script["segwit"].get("address", None),
                                       *(decoded_script["segwit"].get("addresses", []))]:
                return True
        raise GlacierFatal("Redemption script does not match cold storage address. Doublecheck for typos")

    def teach_address_to_wallet(self):
        """
        Teach the bitcoind wallet about our multisig address.

        So it can use that knowledge to sign the transaction we're
        about to create.

        """
        decoded_script = bitcoin_cli.json("decodescript", self.redeem_script)
        address_format = 'p2sh' if decoded_script["p2sh"] == self.source_address \
            else 'p2sh-p2wsh' if self.source_address == decoded_script["segwit"]["p2sh-segwit"] \
            else 'p2wsh'
        # Replace pubkeys with privkeys where available
        priv_for_pub = {pubkey: privkey for privkey, pubkey in self.keys}
        keys = [priv_for_pub[key] if key in priv_for_pub else key
                for key in self._pubkeys]
        desc_with_privkeys, _ = build_descriptor(self.sigsrequired, keys, address_format)
        import_this = {
            "desc": desc_with_privkeys,
            "timestamp": "now",
        }
        if len(priv_for_pub) < len(keys):
            # Avoid warning about "Some private keys are missing[...]"
            import_this["watchonly"] = True
        results = bitcoin_cli.json("importmulti", jsonstr([import_this]))
        if len(results) != 1:
            raise Exception("How did wallet import not return exactly 1 result?")
        result = results[0]
        if not result["success"] or "warnings" in result:
            raise Exception("Problem importing address to wallet")  # pragma: no cover

    def _find_pubkeys(self):
        """
        Return (sigsrequired, pubkeys) associated with our source address.
        """
        decoded_script = bitcoin_cli.json("decodescript", self.redeem_script)
        match = re.match(r"multi\((\d+),([0-9a-fA-F,]+)\)", decoded_script["desc"])
        if decoded_script["type"] != "multisig" or not match:
            raise GlacierFatal("redeem script does not appear to be multisig")
        sigsrequired = int(match.group(1))
        pubkeys = match.group(2).split(",")
        return (sigsrequired, pubkeys)


class ManualWithdrawalXact(BaseWithdrawalXact):
    """
    Class for constructing a withdrawal transaction from manually provided UTXOs.

    Attributes
    ----------
    source_address: <string> input_txs will be filtered for utxos to this source address
    redeem_script: <string>

    """

    MAX_FEE = .005  # in btc.  hardcoded limit to protect against user typos

    def __init__(self, source_address, redeem_script):
        """
        Construct a new withdrawal from the specified source address.
        """
        super().__init__(source_address, redeem_script)
        self._seen_txhashes = set()  # only for detecting duplicates
        self._inputs = []
        self.fee_basis_satoshis_per_byte = None

    def create_signed_transaction(self, destinations):
        """
        Return a hex string representing a signed bitcoin transaction.

        returns => <dict> from signrawtransactionwithwallet, with keys
        'hex' and 'complete'

        destinations: {address <string>: amount<string>} dictionary mapping destination addresses to amount in BTC
        """
        prev_txs = jsonstr(self._inputs)
        tx_unsigned_hex = bitcoin_cli.checkoutput(
            "createrawtransaction",
            prev_txs,
            jsonstr(destinations),
            "0",  # locktime
            "false",  # replaceable
        ).strip()
        signed_tx = bitcoin_cli.json(
            "signrawtransactionwithwallet",
            tx_unsigned_hex, prev_txs)
        return signed_tx

    def create_final_output(self, destinations, _expect_complete):
        """Return FinalOutput object with withdrawal transaction."""
        signed_tx = self.create_signed_transaction(destinations)
        if not signed_tx['complete']:
            raise GlacierFatal("Expected transaction to be complete by now")  # pragma: no cover
        return RawTransactionFinalOutput(fee=self.fee, rawxact=signed_tx["hex"])

    def unspent_total(self):
        """
        Return the total amount of BTC available to spend from the input UTXOs.
        """
        return sum(utxo["amount"] for utxo in self._inputs).quantize(SATOSHI_PLACES)

    def add_input_xact(self, hex_tx):
        """
        Use the raw hex transaction provided as an input for this withdrawal.

        Look for outputs in the supplied transaction which match our cold storage address.
        Save them for later use in constructing the withdrawal.

        hex_tx (string): hex-encoded transaction whose outputs we want to spend
        """
        # For each UTXO used as input, we need the txid, vout index, scriptPubKey, amount, and redeemScript
        # to generate a signature
        xact = bitcoin_cli.json("decoderawtransaction", hex_tx)
        if xact['hash'] in self._seen_txhashes:
            raise GlacierFatal("duplicated input transactions")
        self._seen_txhashes.add(xact['hash'])

        utxos = self._get_utxos(xact)
        if not utxos:
            raise GlacierFatal("transaction data not found for source address: {}".format(self.source_address))

        txid = xact["txid"]
        for utxo in utxos:
            self._inputs.append(OrderedDict([
                ("txid", txid),
                ("vout", int(utxo["n"])),
                ("amount", utxo["value"]),
                ("scriptPubKey", utxo["scriptPubKey"]["hex"]),
                ("redeemScript", self.redeem_script),
            ]))

    def _get_utxos(self, xact):
        """
        Given a transaction, find all the outputs that were sent to an address.

        returns => List<Dictionary> list of UTXOs in bitcoin core format

        xact - <Dictionary> in bitcoin core format
        """
        utxos = []

        for output in xact["vout"]:
            if self.source_address == address_from_vout(output):
                utxos.append(output)

        return utxos

    def calculate_fee(self, destinations):
        """
        Given a list of destinations, calculate the total fee in BTC at the given basis.

        returns => Decimal total fee in BTC

        destinations - <Dictionary> pairs of {addresss:amount} to send
        """
        signed_tx = self.create_signed_transaction(destinations)

        decoded_tx = bitcoin_cli.json("decoderawtransaction", signed_tx["hex"])
        size = decoded_tx["vsize"]

        self.fee = satoshi_to_btc(size * self.fee_basis_satoshis_per_byte)
        if self.fee > self.MAX_FEE:
            raise GlacierExcessiveFee("Calculated fee ({}) is too high. Must be under {}".format(self.fee, self.MAX_FEE))
        return self.fee


class PsbtWithdrawalXact(BaseWithdrawalXact):
    """
    Class for constructing a withdrawal transaction from PSBT.

    Attributes
    ----------
    psbt_raw: <string> base64-encoded input PSBT from user
    psbt: <object> output of `decodepsbt`
    destinations: <OrderedDict> address => amount for each output
    source_address: <string> our cold storage address
    redeem_script: <string>
    keys: <list of strings>: private keys to sign with

    """

    def __init__(self, psbt_raw):
        """
        Construct transaction based on the provided base64 psbt.
        """
        self.psbt_raw = psbt_raw
        self.psbt = bitcoin_cli.json("decodepsbt", self.psbt_raw)
        self.sanity_check_psbt()
        source_address, redeem_script = self._find_source_address()
        super().__init__(source_address, redeem_script)
        self.destinations = self._find_output_addresses()
        self.fee = self.psbt['fee']

    def _input_iter(self):
        """
        Iterate over (address, amount) for each input.
        """
        for index, inp in enumerate(self.psbt['inputs']):
            if 'witness_utxo' in inp:
                addr = inp['witness_utxo']['scriptPubKey']['address']
                amount = inp['witness_utxo']['amount']
            else:
                inp0_n = self.psbt['tx']['vin'][index]['vout']
                vout = inp['non_witness_utxo']['vout'][inp0_n]
                addr = address_from_vout(vout)
                amount = vout['value']
            yield addr, amount

    def _find_source_address(self):
        """
        Analyze PSBT and return our detected address and redeem script.
        """
        inp0 = self.psbt['inputs'][0]
        script = inp0['witness_script']['hex'] if 'witness_script' in inp0 \
            else inp0['redeem_script']['hex']
        myaddr, _ = next(self._input_iter())
        return myaddr, script

    def _find_output_addresses(self):
        """
        Analyze PSBT and return OrderedDict of (address:amount) pairs.
        """
        out = OrderedDict()
        for vout in self.psbt['tx']['vout']:
            addr = address_from_vout(vout)
            out[addr] = vout['value']
        return out

    def unspent_total(self):
        """
        Return the total amount of BTC available to spend from the input UTXOs.
        """
        return sum(amount for _, amount in self._input_iter())

    def create_final_output(self, destinations, expect_complete):
        """
        Return a FinalOutput object describing the withdrawal transaction.

        returns => <dict> from signrawtransactionwithwallet, with keys
        'hex' and 'complete'

        destinations: {address <string>: amount<string>} dictionary
        mapping destination addresses to amount in BTC

        The destinations param is a holdover from
        ManualWithdrawalXact, and should match self.destinations.
        """
        if destinations != self.destinations:
            raise GlacierFatal("unable to change destinations of PSBT")  # pragma: no cover
        prcs = bitcoin_cli.json("walletprocesspsbt", self.psbt_raw, 'true', 'ALL', 'false')
        if expect_complete != prcs['complete']:
            if expect_complete:
                raise GlacierFatal("Expected PSBT to be complete by now")  # pragma: no cover
            raise GlacierFatal("How is this transaction complete when I didn't have enough keys?")  # pragma: no cover
        if expect_complete:
            final = bitcoin_cli.json('finalizepsbt', prcs['psbt'])
            return RawTransactionFinalOutput(fee=self.fee, rawxact=final['hex'])
        return PsbtFinalOutput(psbt=prcs['psbt'])

    def partial_sig_pubkeys(self):
        """
        Return a list of pubkeys (hex strings) for which we already have signatures.
        """
        # We've already checked (in sanity_check_psbt()) that each
        # input has the same number of partial signatures, so looking
        # at only the first one here is safe.
        pubkeys = self.psbt['inputs'][0].get('partial_signatures', {})
        return pubkeys.keys()

    def add_key(self, privkey):
        """
        Use the (WIF format) private key for signing this withdrawal.
        """
        pubkey = super().add_key(privkey)
        if pubkey in self.partial_sig_pubkeys():
            raise GlacierFatal("this PSBT has already been signed by that key")

    def sanity_check_psbt(self):
        """
        Make sure psbt is as we expect.

        This is perhaps overly defensive, but I want to make sure we
        don't sign anything we don't completely understand.

        We want to avoid an attack of this nature:

        https://medium.com/shiftcrypto/a-remote-theft-attack-on-trezor-model-t-44127cd7fb5a

        """
        # decodepsbt has already checked that the length of psbt['inputs']
        # matches length of psbt['tx']['vin'].

        psbt_version = self.psbt.get('psbt_version', 0)
        if psbt_version != 0:
            raise GlacierFatal("unknown PSBT version of {}".format(psbt_version))

        # Every input must be populated with utxo info.
        for inp in self.psbt['inputs']:
            if 'witness_utxo' not in inp and 'non_witness_utxo' not in inp:
                raise GlacierFatal("expected PSBT to describe every input")

        # Either all inputs must have witness_utxo, or all inputs must
        # have non_witness_utxo. Because we assume all inputs are from
        # our one single cold storage address.
        have_witness = 'witness_utxo' in self.psbt['inputs'][0]
        have_non_witness = 'non_witness_utxo' in self.psbt['inputs'][0]
        for inp in self.psbt['inputs']:
            if have_witness and 'witness_utxo' not in inp:
                raise GlacierFatal("expected all inputs to be from same address")
            if have_non_witness and 'non_witness_utxo' not in inp:
                raise GlacierFatal("expected all inputs to be from same address")

        # Every input must have redeem_script and/or witness_script.
        # Otherwise we can't possibly sign. And one of them must be of
        # type multisig.
        for inp in self.psbt['inputs']:
            if have_witness and 'witness_script' not in inp:
                raise GlacierFatal("expected PSBT to include witness_script")
            if have_witness and inp['witness_script']['type'] != 'multisig':
                raise GlacierFatal("expected witness_script to be multisig")
            if not have_witness and 'redeem_script' not in inp:
                raise GlacierFatal("expected PSBT to include redeem_script")
            if not have_witness and inp['redeem_script']['type'] != 'multisig':
                raise GlacierFatal("expected redeem_script to be multisig")

        # If we have both witness_utxo and non_witness_utxo, they need
        # to match.
        if have_witness and have_non_witness:
            for index, inp in enumerate(self.psbt['inputs']):
                witness_script = inp['witness_utxo']['scriptPubKey']['hex']
                witness_amount = inp['witness_utxo']['amount']

                inp0_n = self.psbt['tx']['vin'][index]['vout']
                vout = inp['non_witness_utxo']['vout'][inp0_n]
                non_witness_script = vout['scriptPubKey']['hex']
                non_witness_amount = vout['value']
                if witness_script != non_witness_script or \
                   witness_amount != non_witness_amount:
                    raise GlacierFatal("witness_utxo did not match non_witness_utxo")

        # Every input must come from same address (so we can assume
        # it's ours without having to ask user to type in cold storage
        # address). We need to identify our own address in order to
        # identify the change output.
        if len(set(addr for addr, _ in self._input_iter())) > 1:
            raise GlacierFatal("expected all inputs to be from same address")

        # Each input must have the same set of partial signatures (or
        # none). Otherwise our calculations about how many additional
        # signatures required will be inaccurate.
        if len(set(frozenset(x for x in inp.get('partial_signatures', {}))
                   for inp in self.psbt['inputs'])) > 1:
            raise GlacierFatal("expected all inputs to have same partial_signatures")

        # Die if anything unusual or unrecognized. We don't want to
        # sign something that we don't fully understand.
        allowed_global_keys = ['fee', 'inputs', 'outputs', 'tx', 'unknown',
                               'global_xpubs', 'psbt_version', 'proprietary']
        for key in self.psbt:
            if key not in allowed_global_keys:
                raise GlacierFatal("Unknown PSBT key '{}'".format(key))

        if 'unknown' in self.psbt and self.psbt['unknown']:
            raise GlacierFatal("Unknown global fields in PSBT: {}".format(
                repr(self.psbt['unknown'])))

        allowed_input_keys = [
            'redeem_script',
            'witness_script',
            'witness_utxo',
            'non_witness_utxo',
            'partial_signatures',
        ]
        for inp in self.psbt['inputs']:
            for key in inp:
                if key not in allowed_input_keys:
                    raise GlacierFatal("Unknown PSBT input key '{}'".format(key))

        # Bitcoin-cli's decodepsbt will check that
        # inputs[0].non_witness_utxo.txid matches the tx.vin[0].txid,
        # so I don't need to do that here. See
        # t/sign-psbt.corrupted-value-nonsegwit.run.


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
    somehow qrencode can do up to 4302, and one time it failed with more
    than 4295.

    Theoretical limit of PSBTs (which must use binary mode) is 2952
    but qrencode chokes with more than 2937 or 2935.

    """
    # Remove any stale files, so we don't confuse user if a previous
    # withdrawal created 3 files (or 1 file) and this one only has 2
    base, ext = os.path.splitext(filename)
    for deleteme in glob.glob("{}*{}".format(base, ext)):
        os.remove(deleteme)
    all_upper_case = data.upper() == data
    MAX_QR_LEN = 4200 if all_upper_case else 2800
    if len(data) <= MAX_QR_LEN:
        write_qr_code(filename, data)
        filenames = [filename]
    else:
        idx = 1
        filenames = []
        intdata = data
        while intdata:
            thisdata = intdata[0:MAX_QR_LEN]
            intdata = intdata[MAX_QR_LEN:]
            thisfile = "{}-{:02d}{}".format(base, idx, ext)
            filenames.append(thisfile)
            write_qr_code(thisfile, thisdata)
            idx += 1

    qrdata = decode_qr(filenames)
    if qrdata != data:
        print("********************************************************************")  # pragma: no cover
        print("WARNING: {} QR code could not be verified properly. This could be a sign of a security breach.".format(name))  # pragma: no cover
        print("********************************************************************")  # pragma: no cover

    print("QR code for {0} written to {1}".format(name, ','.join(filenames)))


################################################################################################
#
# User sanity checking
#
################################################################################################

def yes_no_interactive():
    """
    Prompt user for a yes/no confirmation and repeat until valid answer is received.
    """
    while True:
        confirm = input("Confirm? (y/n): ")
        if confirm.upper() == "Y":
            return True
        if confirm.upper() == "N":
            return False
        print("You must enter y (for yes) or n (for no).")


def safety_checklist():
    """
    Prompt user with annoying safety checks and make sure they answer yes to all.
    """
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
            raise GlacierFatal("safety check failed")


################################################################################################
#
# Main "entropy" function
#
################################################################################################


def unchunk(string):
    """
    Remove spaces in string.
    """
    return string.replace(" ", "")


def chunk_string(string, length):
    """
    Split a string into chunks of [length] characters, for easy human readability.

    Source: https://stackoverflow.com/a/18854817
    """
    return (string[0 + i:length + i] for i in range(0, len(string), length))


def entropy(count, length):
    """
    Generate n random strings for the user from /dev/random.
    """
    safety_checklist()

    print("\n\n")
    print("Making {} random data strings....".format(count))
    print("If strings don't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.\n")

    idx = 0
    while idx < count:
        seed = subprocess.check_output(["xxd", "-l", str(length), "-p", "/dev/random"])
        idx += 1
        seed = seed.decode('ascii').replace('\n', '')
        print("Computer entropy #{0}: {1}".format(idx, " ".join(chunk_string(seed, 4))))


################################################################################################
#
# Main "deposit" function
#
################################################################################################

def create_key_interactive(dice_seed_length, rng_seed_length):
    """
    Create one key based on dice & computer entropy entered by user.

    dice_seed_length: <int> minimum number of dice rolls required
    rng_seed_length: <int> minimum length of random seed required

    Returns => WIF private key
    """
    dice_seed_string = read_dice_seed_interactive(dice_seed_length)
    dice_seed_hash = hash_sha256(dice_seed_string)

    rng_seed_string = read_rng_seed_interactive(rng_seed_length)
    rng_seed_hash = hash_sha256(rng_seed_string)

    # back to hex string
    hex_private_key = xor_hex_strings(dice_seed_hash, rng_seed_hash)
    return hex_private_key_to_wif_private_key(hex_private_key)


def deposit_interactive(nrequired, nkeys, dice_seed_length=62, rng_seed_length=20, p2wsh=False):
    """
    Generate data for a new cold storage address (private keys, address, redemption script).

    nrequired: <int> number of multisig keys required for withdrawal
    nkeys: <int> total number of multisig keys
    dice_seed_length: <int> minimum number of dice rolls required
    rng_seed_length: <int> minimum length of random seed required
    p2wsh: if True, generate p2wsh instead of p2wsh-in-p2sh
    """
    safety_checklist()
    ensure_bitcoind_running(descriptors=True)

    print("\n")
    print("Creating {0}-of-{1} cold storage address.\n".format(nrequired, nkeys))

    keys = []

    while len(keys) < nkeys:
        index = len(keys) + 1
        print("\nCreating private key #{}".format(index))
        keys.append(create_key_interactive(dice_seed_length, rng_seed_length))

    print("Private keys created.")
    print("Generating {0}-of-{1} cold storage address...\n".format(nrequired, nkeys))

    desc_with_privkeys, desc_with_pubkeys = \
        build_descriptor(nrequired, keys, 'p2wsh' if p2wsh else 'p2sh-p2wsh')
    address = bitcoin_cli.json("deriveaddresses", desc_with_pubkeys)[0]

    # We still need the wallet in order to find the redeem script.
    # Even though user doesn't really need redeem script anymore if they're
    # using a PSBT flow.
    bitcoin_cli.json("importdescriptors", jsonstr([{
        'desc': desc_with_privkeys,
        'timestamp': 'now',
        'watchonly': True,
    }]))
    ainfo = bitcoin_cli.json("getaddressinfo", address)
    script = ainfo["embedded"]["hex"] if "embedded" in ainfo else ainfo["hex"]

    print("Private keys:")
    for idx, key in enumerate(keys):
        print("Key #{0}: {1}".format(idx + 1, key))

    print("\nCold storage address:")
    print(address)

    print("\nRedemption script:")
    print(script)
    print()

    print("\nWallet descriptor:")
    print(desc_with_pubkeys)
    print()

    write_and_verify_qr_code("cold storage address", "address.png", address)
    write_and_verify_qr_code("redemption script", "redemption.png", script)
    write_and_verify_qr_code("wallet descriptor", "descriptor.png", desc_with_pubkeys)


################################################################################################
#
# Main "withdraw" function
#
################################################################################################

class BaseWithdrawalBuilder(metaclass=ABCMeta):
    """Interactively construct a withdrawal transaction, either via input TXs or PSBT."""

    def __init__(self):
        """Create new object."""
        self.expect_complete = True

    @abstractmethod
    def construct_withdrawal_interactive(self):
        """
        Get details from user input and construct *WithdrawalXact object.

        Returns => (xact, addresses) where xact is *WithdrawalXact, and
        addresses is a dict of {address: amount} of destinations.
        """

    @abstractmethod
    def too_few_keys(self, sigsrequired):
        """Inform user they are not providing enough keys."""

    def get_keys(self, xact, sigsrequired):
        """Prompt user for private keys and add them to the withdrawal transaction."""
        print("\nHow many private keys will you be signing this transaction "
              "with (at least {} required to complete transaction)?".format(sigsrequired))
        key_count = int(input("#: "))
        if key_count < sigsrequired:
            self.too_few_keys(sigsrequired)
        for key_idx in range(key_count):
            privkey = input("Key #{0}: ".format(key_idx + 1))
            xact.add_key(privkey)
        xact.teach_address_to_wallet()

    @staticmethod
    def print_tx(xact, addresses):
        """
        Print transaction details in human-readable format.
        """
        print("{0} BTC in unspent inputs from cold storage address {1}".format(
            xact.unspent_total(), xact.source_address))
        for address, value in addresses.items():
            if address == xact.source_address:
                print("{0} BTC going back to cold storage address {1}".format(value, address))
            else:
                print("{0} BTC going to destination address {1}".format(value, address))
        # Sanity check that our fee calculation worked as expected
        if xact.fee != xact.unspent_total() - sum(addresses.values()):
            raise Exception("something went wrong in our fee calculation")  # pragma: no cover
        print("Fee amount: {0}".format(xact.fee))

    def withdraw_interactive(self):
        """
        Construct and sign a transaction to withdraw funds from cold storage.

        All data required for transaction construction is input at the terminal
        """
        safety_checklist()
        ensure_bitcoind_running()

        approve = False

        while not approve:
            xact, addresses = self.construct_withdrawal_interactive()

            # check data
            print("\nIs this data correct?")
            print("*** WARNING: Incorrect data may lead to loss of funds ***\n")
            self.print_tx(xact, addresses)
            print("\nSigning with private keys: ")
            for privkey, _ in xact.keys:
                print("{}".format(privkey))
            print("\n")
            confirm = yes_no_interactive()

            if confirm:
                approve = True
            else:
                print("\nProcess aborted. Starting over....")

        # Calculate Transaction
        print("\nCalculating transaction...\n")

        final = xact.create_final_output(addresses, self.expect_complete)
        print(final)

        print("\nTransaction fingerprint (md5):")
        print(hash_md5(final.value_to_hash()))

        write_and_verify_qr_code("transaction", "transaction.png", final.qr_string())


class ManualWithdrawalBuilder(BaseWithdrawalBuilder):
    """Interactively construct a withdrawal transaction via input TXs."""

    @staticmethod
    def too_few_keys(sigsrequired):
        """Inform user they are not providing enough keys."""
        raise GlacierFatal("not enough private keys to complete transaction (need {})".format(sigsrequired))

    @staticmethod
    def get_tx_interactive(num):
        """
        Prompt user for an unspent transaction to use as an input.

        num: index of this input (used only for prompt)

        Returns => string with hex transaction
        """
        print("\nPlease paste raw transaction #{} (hexadecimal format) with unspent outputs at the source address".format(num))
        print("OR")
        print("input a filename located in the current directory which contains the raw transaction data")
        print("(If the transaction data is over ~4000 characters long, you _must_ use a file.):")

        hex_tx = input()
        if os.path.isfile(hex_tx):
            with open(hex_tx) as hexfile:
                hex_tx = hexfile.read().strip()
        return hex_tx

    def construct_withdrawal_interactive(self):
        """
        Get details from user input and construct ManualWithdrawalXact object.

        Returns => (xact, addresses) where xact is ManualWithdrawalXact, and
        addresses is a dict of {address: amount} of destinations.
        """
        addresses = OrderedDict()

        print("\nYou will need to enter several pieces of information to create a withdrawal transaction.")
        print("\n\n*** PLEASE BE SURE TO ENTER THE CORRECT DESTINATION ADDRESS ***\n")

        source_address = input("\nSource cold storage address: ")
        addresses[source_address] = 0

        redeem_script = input("\nRedemption script for source cold storage address: ")
        xact = ManualWithdrawalXact(source_address, redeem_script)

        dest_address = input("\nDestination address: ")
        addresses[dest_address] = 0

        num_tx = int(input("\nHow many unspent transactions will you be using for this withdrawal? "))

        for txcount in range(num_tx):
            xact.add_input_xact(self.get_tx_interactive(txcount + 1))

        print("\nTransaction data found for source address.")

        input_amount = xact.unspent_total()

        print("TOTAL unspent amount for this raw transaction: {} BTC".format(input_amount))
        self.get_keys(xact, xact.sigsrequired)

        # fees, amount, and change

        fee = get_fee_interactive(xact, addresses)
        if fee > input_amount:
            raise GlacierFatal("Your fee is greater than the sum of your unspent transactions.  Try using larger unspent transactions")

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
            raise GlacierFatal("fee + withdrawal amount greater than total amount available from unspent transactions")

        change_amount = input_amount - withdrawal_amount - fee

        if change_amount > 0:
            print("{0} being returned to cold storage address address {1}.".format(change_amount, xact.source_address))
            addresses[xact.source_address] = change_amount
        else:
            del addresses[xact.source_address]
            fee = xact.calculate_fee(addresses)  # Recompute fee with no change output
            withdrawal_amount = input_amount - fee
            print("With no change output, the transaction fee is reduced, and {0} BTC will be sent to your destination.".format(withdrawal_amount))

        addresses[dest_address] = withdrawal_amount
        return (xact, addresses)


class PsbtWithdrawalBuilder(BaseWithdrawalBuilder):
    """Interactively construct a withdrawal transaction via PSBT."""

    def too_few_keys(self, _sigsrequired):
        """Inform user they are not providing enough keys."""
        print("Output will be a partially signed bitcoin transaction (PSBT).")
        self.expect_complete = False

    @staticmethod
    def _load_psbt():
        """
        Prompt user for filename, load PSBT from that file.
        """
        print("Input a filename located in the current directory which contains the PSBT:")
        psbt_filename = input()
        with open(psbt_filename) as psbtfile:
            psbt = psbtfile.read().strip()
        return psbt

    def construct_withdrawal_interactive(self):
        """
        Get details from user input and construct WithdrawalXact object.

        Returns => (xact, addresses) where xact is WithdrawalXact, and
        addresses is a dict of {address: amount} of destinations.
        """
        psbt_raw = self._load_psbt()
        xact = PsbtWithdrawalXact(psbt_raw)
        self.print_tx(xact, xact.destinations)
        if not yes_no_interactive():
            raise GlacierFatal("aborting")
        sigs_already = len(xact.partial_sig_pubkeys())
        sigsrequired = xact.sigsrequired - sigs_already
        self.get_keys(xact, sigsrequired)
        return (xact, xact.destinations)


def set_network_params(testnet, regtest):
    """
    Set global vars cli_args and wif_prefix based on which network we are targeting.

    testnet: integer: port for testnet RPC, or None if not testnet
    regtest: integer: port for regtest RPC, or None if not regtest
    """
    global wif_prefix
    if testnet:
        network = 'testnet'
    elif regtest:
        network = 'regtest'
    else:
        network = 'mainnet'

    bitcoin_cli.cli_args = {
        'mainnet': [],
        'testnet': ["-testnet", "-rpcport={}".format(testnet), "-datadir=../bitcoin-data/{}".format(testnet)],
        'regtest': ["-regtest", "-rpcport={}".format(regtest), "-datadir=../bitcoin-data/{}".format(regtest)],
    }[network]

    wif_prefix = {
        'mainnet': "80",
        'testnet': "EF",
        'regtest': "EF",
    }[network]


################################################################################################
#
# main function
#
# Show help, or execute one of the three main routines: entropy, deposit, withdraw
#
################################################################################################

def main():
    """
    Execute main interactive script.
    """
    parser = argparse.ArgumentParser(epilog="For more help, include a subcommand, e.g. `./glacierscript.py entropy --help`")
    parser.add_argument('--testnet', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--regtest', type=int, help=argparse.SUPPRESS)
    parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')

    subs = parser.add_subparsers(title='Subcommands', dest='program')

    def add_rng(parser):
        """Add the --rng option to the supplied parser."""
        parser.add_argument(
            "-r", "--rng", type=int, help="Minimum number of 8-bit bytes to use for computer entropy when generating private keys (default: 20)", default=20)

    parser_entropy = subs.add_parser('entropy', help="Generate computer entropy")
    parser_entropy.add_argument(
        "--num-keys", type=int, help="The number of keys to create random entropy for", default=1)
    add_rng(parser_entropy)

    parser_deposit = subs.add_parser('create-deposit-data', help="Create cold storage address")
    parser_deposit.add_argument(
        "-m", type=int, help="Number of signing keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=1)
    parser_deposit.add_argument(
        "-n", type=int, help="Number of total keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=2)
    parser_deposit.add_argument(
        "-d", "--dice", type=int, help="The minimum number of dice rolls to use for entropy when generating private keys (default: 62)", default=62)
    parser_deposit.add_argument(
        "--p2wsh", action="store_true", help="Generate p2wsh (native segwit) deposit address, instead of p2wsh-in-p2sh")
    add_rng(parser_deposit)

    subs.add_parser('create-withdrawal-data', help="Construct withdrawal transaction")

    subs.add_parser('sign-psbt', help="Sign PSBT (Partially Signed Bitcoin Transaction, BIP 174)")

    args = parser.parse_args()
    if not args.program:
        parser.print_usage()
        raise GlacierFatal("you must specify a subcommand")

    bitcoin_cli.verbose_mode = args.verbose

    set_network_params(args.testnet, args.regtest)

    if args.program == "entropy":
        entropy(args.num_keys, args.rng)

    if args.program == "create-deposit-data":
        deposit_interactive(args.m, args.n, args.dice, args.rng, args.p2wsh)

    if args.program == "create-withdrawal-data":
        builder = ManualWithdrawalBuilder()
        builder.withdraw_interactive()

    if args.program == "sign-psbt":
        builder = PsbtWithdrawalBuilder()
        builder.withdraw_interactive()


@contextlib.contextmanager
def subprocess_catcher():
    """
    Catch any subprocess errors and show process output before re-raising.

    Catch fatal errors and issue nice error message.
    """
    try:
        yield
    except subprocess.CalledProcessError as exc:
        if hasattr(exc, 'output'):
            print("Output from subprocess:", exc.output, file=sys.stderr)
        raise
    except GlacierFatal as exc:
        raise SystemExit("ERROR: {}. Exiting...".format(exc))


if __name__ == "__main__":
    with subprocess_catcher():
        main()
