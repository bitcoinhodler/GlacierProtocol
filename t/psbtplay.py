#!/usr/bin/env python3
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'trim-psbt'))
from bitcoin import psbt
from bitcoin.networks import NETWORKS
from binascii import unhexlify, hexlify
# base64 encoding
from binascii import a2b_base64, b2a_base64



def main():
    # parse psbt transaction
    # From sign-psbt.uncompressed.psbt:
    orig_psbt = "cHNidP8BAHUCAAAAAfJhL6kG42b89bDWlMdPRNrE4Qi6f76NITsZ2t5UJjFmAQAAAAD/////AtSeAAAAAAAAF6kUdi/qMkbcTOGc/T8aqWheiDhgUFeHoA8AAAAAAAAZdqkU+1tniKM2wM9JuQ5RrUJvLom/Q/uIrAAAAAAAAQDfAgAAAAFWDAzZ/CRJrj03Jln8hoA9cdlz0Oj407ZoKoHGYRYjJAEAAABqRzBEAiAxVkTRJzpriWN+BaJPIFRnSRkJeVXmMgYTuI4PABLQawIgcrKtCtmObWGWqMrH3K8zVvw1P+zWYQgQJHwdPC5mEhgBIQOGX/ISA/a2uTUJ5AvT0bQtfOGUYadEqc0kqOF5O39YWP////8CMAz1BQAAAAAZdqkUPM59uAX0QZX8OcQ8DFJkPG7aE4KIrFDDAAAAAAAAF6kUdi/qMkbcTOGc/T8aqWheiDhgUFeHAAAAAAEE/QsBUkEEd/FfIq7/rz87xIooCnZ/fGryEnZ4PAn/O8qrvs4XgRNc8PKPZD08YKdcKdsIGdVEK66D2PdOfETO0yVWZZmOUkEEA/ZCIjvHUeElq2BO0gxUTpM+uCoZIB+QvaYjap3b7ayTHBCMfDGJt/x+pwl7AiF9gZ6GaphBKRxSL2kXOhJSSkEEaJXz7QHAkCW6nPq3tn1pnj66zq2gvv9wvHLH8Q3y0cZ033Q7u1jOohFwgxM05NbZZe00ziMklVcJH0QDBaucAEEEnzyxUhMMJB4BuSIKFH9p9xEbgw3vNbUQlzq0e7mvf/byH8talYg5/uACLo6l3cbXH8YkqEvcQoNRk6v+4SWxw1SuAAEA/QsBUkEEd/FfIq7/rz87xIooCnZ/fGryEnZ4PAn/O8qrvs4XgRNc8PKPZD08YKdcKdsIGdVEK66D2PdOfETO0yVWZZmOUkEEA/ZCIjvHUeElq2BO0gxUTpM+uCoZIB+QvaYjap3b7ayTHBCMfDGJt/x+pwl7AiF9gZ6GaphBKRxSL2kXOhJSSkEEaJXz7QHAkCW6nPq3tn1pnj66zq2gvv9wvHLH8Q3y0cZ033Q7u1jOohFwgxM05NbZZe00ziMklVcJH0QDBaucAEEEnzyxUhMMJB4BuSIKFH9p9xEbgw3vNbUQlzq0e7mvf/byH8talYg5/uACLo6l3cbXH8YkqEvcQoNRk6v+4SWxw1SuAAA="

    # first convert it to binary
    raw = a2b_base64(orig_psbt)
    # then parse
    tx = psbt.PSBT.parse(raw)

    # print how much we are spending and where
    for out in tx.tx.vout:
        print(out.value,"to",out.script_pubkey.address(NETWORKS["test"]))
    save_to_file(tx, 'test.psbt')


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
