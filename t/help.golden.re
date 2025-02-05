usage: glacierscript.py [-h] [-v]
                        {entropy,create-deposit-data,create-withdrawal-data,sign-psbt}
                        ...

option<(al argument)?>s:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity

Subcommands:
  {entropy,create-deposit-data,create-withdrawal-data,sign-psbt}
    entropy             Generate computer entropy
    create-deposit-data
                        Create cold storage address
    create-withdrawal-data
                        Construct withdrawal transaction
    sign-psbt           Sign PSBT (Partially Signed Bitcoin Transaction, BIP
                        174)

For more help, include a subcommand, e.g. `./glacierscript.py entropy --help`
usage: glacierscript.py entropy [-h] [--num-keys NUM_KEYS] [-r RNG]

option<(al argument)?>s:
  -h, --help           show this help message and exit
  --num-keys NUM_KEYS  The number of keys to create random entropy for
  -r RNG, --rng RNG    Minimum number of 8-bit bytes to use for computer
                       entropy when generating private keys (default: 20)
usage: glacierscript.py create-deposit-data [-h] [-m M] [-n N] [-d DICE]
                                            [--p2wsh] [-r RNG]

option<(al argument)?>s:
  -h, --help            show this help message and exit
  -m M                  Number of signing keys required in an m-of-n multisig
                        address creation (default m-of-n = 1-of-2)
  -n N                  Number of total keys required in an m-of-n multisig
                        address creation (default m-of-n = 1-of-2)
  -d DICE, --dice DICE  The minimum number of dice rolls to use for entropy
                        when generating private keys (default: 62)
  --p2wsh               Generate p2wsh (native segwit) deposit address,
                        instead of p2wsh-in-p2sh
  -r RNG, --rng RNG     Minimum number of 8-bit bytes to use for computer
                        entropy when generating private keys (default: 20)
usage: glacierscript.py create-withdrawal-data [-h]

option<(al argument)?>s:
  -h, --help  show this help message and exit
