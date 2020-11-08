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
    # From sign-psbt.segwit-inputs.psbt:
    orig_psbt = "cHNidP8BAM4CAAAABFAqXQa2PFg8pAnCVBZEiWjWiT9kCtvhtFL789qp9txJAQAAAAD/////FIiqv5nPcATIXvaPyvXKTHdvvZ4Lx/hcq7eB5JCMoWsAAAAAAP////+WskoLtxYV1tlohvYVa1+LaDA7VJVXOImftYpHs/WL4AAAAAAA/////xhRnXo1X5jbt57UFzdk97EVrsku74Mt6pqpdizQEcG/AAAAAAD/////AeH1IQoAAAAAF6kUhUbnR8gJQ3awoK9EvFu7jdTwIY2HAAAAAAABAIoCAAAAAcC/NJJsUqFeod2Avd7/ssZzjybwFIYqGmEvQmuHYyPVAQAAABcWABTQB03a+UQVNYAF1jYLqSn2KKi6wf////8CEH6IAgAAAAAXqRSp4cLcMuRItnG9EaM4hGn3pIcmX4egf4gCAAAAABepFL05lruabEAdp+ZdTbs6m5eM0EXshwAAAAABBItSIQPRTdz7aBf1V5aVu7PrPhhYh78pQrAx5vcWNDuP5+no4iECj81G+GFLLL8xgJaWgkKh4ivPttjyttyTnIwnw0eyk3shAxWstVASD0zctGDVxJCAq1CMpMzY3t7Kwi/urIzQF9TBIQIrBj7i8i+eGYLBQP53hnLGgxEaeW3Mzb1Hu2Xj1gipg1SuAAEAcgIAAAAB2T89qSgOt9YXHadGJn70ael9dGX3nqRqReB0ld/Cd1MBAAAAAP////8CCEuHAgAAAAAXqRS9OZa7mmxAHafmXU27OpuXjNBF7Idws4kCAAAAABYAFEdvx77Y6Nd+j/cMVGveWto3zc7GAAAAAAEEi1IhA9FN3PtoF/VXlpW7s+s+GFiHvylCsDHm9xY0O4/n6ejiIQKPzUb4YUssvzGAlpaCQqHiK8+22PK23JOcjCfDR7KTeyEDFay1UBIPTNy0YNXEkICrUIykzNje3srCL+6sjNAX1MEhAisGPuLyL54ZgsFA/neGcsaDERp5bczNvUe7ZePWCKmDVK4AAQBqAgAAAAFtxht/2X8gayzOn51bht9UhI9RgjHNFt6KzM1CxtZ3yAEAAAAXFgAUrhC9pL7tuNF0nizVDDiqX/yG5hP/////AYh9iAIAAAAAF6kUvTmWu5psQB2n5l1Nuzqbl4zQReyHAAAAAAEEi1IhA9FN3PtoF/VXlpW7s+s+GFiHvylCsDHm9xY0O4/n6ejiIQKPzUb4YUssvzGAlpaCQqHiK8+22PK23JOcjCfDR7KTeyEDFay1UBIPTNy0YNXEkICrUIykzNje3srCL+6sjNAX1MEhAisGPuLyL54ZgsFA/neGcsaDERp5bczNvUe7ZePWCKmDVK4AAQBTAgAAAAEFKFZCgO502jYEGbmHynXbzDhML6IoNspAe1cPldUKoAEAAAAA/////wH/sokCAAAAABepFL05lruabEAdp+ZdTbs6m5eM0EXshwAAAAABBItSIQPRTdz7aBf1V5aVu7PrPhhYh78pQrAx5vcWNDuP5+no4iECj81G+GFLLL8xgJaWgkKh4ivPttjyttyTnIwnw0eyk3shAxWstVASD0zctGDVxJCAq1CMpMzY3t7Kwi/urIzQF9TBIQIrBj7i8i+eGYLBQP53hnLGgxEaeW3Mzb1Hu2Xj1gipg1SuAAA="

    # first convert it to binary
    raw = a2b_base64(orig_psbt)
    # then parse
    tx = psbt.PSBT.parse(raw)

    # Since cold storage address in question is non-segwit for this case:
    if not all(x.non_witness_utxo for x in tx.inputs):
        raise ValueError("Expected all non-witness inputs")

    def amount_for(idx):
        """Return satoshis on input {idx}. Assumes non-witness inputs."""
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

    # Corrupt the PSBT by deleting the last input
    del tx.inputs[-1]

    save_to_file(tx, 'sign-psbt.corrupted-inputs.psbt')


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
