#!/usr/bin/env python3
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'trim-psbt'))
from bitcoin import psbt
from bitcoin.script import Script
# base64 encoding
from binascii import a2b_base64, b2a_base64



def main():
    # parse psbt transaction
    # From sign-psbt.malicious-psbt.psbt:
    orig_psbt = "cHNidP8BAFICAAAAAetf0SI46CMb9RtUg2zSfdBdLcN2bXgePxh32DErZXs1AQAAAAD/////AQxKTAAAAAAAFgAUpBDHZKyNoStXigYCfxHgLwe34dMAAAAAAAEBK0BLTAAAAAAAIgAgZchjx1AzHMA++02sohfnklz/h/XpypknVkI0vg1ieOgBBYtSIQPRTdz7aBf1V5aVu7PrPhhYh78pQrAx5vcWNDuP5+no4iECj81G+GFLLL8xgJaWgkKh4ivPttjyttyTnIwnw0eyk3shAxWstVASD0zctGDVxJCAq1CMpMzY3t7Kwi/urIzQF9TBIQIrBj7i8i+eGYLBQP53hnLGgxEaeW3Mzb1Hu2Xj1gipg1SuAAA="

    # first convert it to binary
    raw = a2b_base64(orig_psbt)
    # then parse
    tx = psbt.PSBT.parse(raw)

    # Modify destination address in vout[0] to be bcrt1qrwxllgvtc0ns624dlped894kkfq608jmye2k50
    # which is a scriptPubKey of 00141b8dffa18bc3e70d2aadf872d396b6b241a79e5b
    scripthex = "00141b8dffa18bc3e70d2aadf872d396b6b241a79e5b"
    scriptbin = bytes.fromhex(scripthex)

    tx.tx.vout[0].script_pubkey = Script(scriptbin)

    save_to_file(tx, 'attacker.psbt')


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
