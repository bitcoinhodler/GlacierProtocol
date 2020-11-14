#!/usr/bin/env python3
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'trim-psbt'))
from bitcoin import psbt
from bitcoin.networks import NETWORKS
# base64 encoding
from binascii import a2b_base64, b2a_base64



def main():
    # parse psbt transaction
    # From sign-psbt.p2wsh.psbt:
    orig_psbt = "cHNidP8BAFICAAAAATrA+nAjorbvWhg+VE1ql6DnmRMibJRuJjHVq1I1b72fAQAAAAD/////AQxKTAAAAAAAFgAUpBDHZKyNoStXigYCfxHgLwe34dMAAAAAAAEAfQIAAAABEw04mQpL5Ny5AZwHaJeEoqjk51OwcCOHc7VnnAD9294AAAAAAP////8C2goOAAAAAAAWABRPf0Rx/SsT/Uez2y+ve3H6+M4a/UBLTAAAAAAAIgAgZchjx1AzHMA++02sohfnklz/h/XpypknVkI0vg1ieOgAAAAAAQErQEtMAAAAAAAiACBlyGPHUDMcwD77TayiF+eSXP+H9enKmSdWQjS+DWJ46AEFi1IhA9FN3PtoF/VXlpW7s+s+GFiHvylCsDHm9xY0O4/n6ejiIQKPzUb4YUssvzGAlpaCQqHiK8+22PK23JOcjCfDR7KTeyEDFay1UBIPTNy0YNXEkICrUIykzNje3srCL+6sjNAX1MEhAisGPuLyL54ZgsFA/neGcsaDERp5bczNvUe7ZePWCKmDVK4AAA=="

    # first convert it to binary
    raw = a2b_base64(orig_psbt)
    # then parse
    tx = psbt.PSBT.parse(raw)

    # Since PSBT has both witness and non-witness input descriptions:
    if not all(x.non_witness_utxo for x in tx.inputs):
        raise ValueError("Expected every input to have non_witness_utxo")
    if not all(x.witness_utxo for x in tx.inputs):
        raise ValueError("Expected every input to have witness_utxo")

    def amount_for(idx):
        """Return satoshis on input {idx}. Uses non-witness inputs."""
        vout = tx.tx.vin[idx].vout
        outp = tx.inputs[idx].non_witness_utxo.vout[vout]
        return outp.value

    # Calculate and display transaction fee.
    input_total = sum(amount_for(idx) for idx in range(len(tx.tx.vin)))
    output_total = sum(out.value for out in tx.tx.vout)

    print("Inputs total", input_total, "sats from", len(tx.tx.vin), "inputs")
    print("Outputs total", output_total, "sats")
    print("Fee equals", input_total - output_total, "sats")

    # print how much we are spending and where
    for out in tx.tx.vout:
        print(out.value,"to",out.script_pubkey.address(NETWORKS["test"]))

    # Corrupt the PSBT by modifying the amount on the first input
    tx.inputs[0].witness_utxo.value = 1

    save_to_file(tx, 'sign-psbt.corrupted-witness-utxo.psbt')


def save_to_file(psbt, filename):
    """Given a PSBT object, write it in base64 to filename."""
    raw = psbt.serialize()
    # convert to base64
    b64_psbt = b2a_base64(raw)
    # somehow b2a ends with \n...
    if b64_psbt[-1:] == b"\n":
        b64_psbt = b64_psbt[:-1]
    # print
    new_psbt = b64_psbt.decode('utf-8')
    print("Creating", filename)
    with open(filename, 'wt') as outfile:
        print(new_psbt, file=outfile)


if __name__ == '__main__':
    main()
