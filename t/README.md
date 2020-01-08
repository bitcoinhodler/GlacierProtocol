# Testing GlacierScript

This directory contains tests for the developers of GlacierScript to
ensure high quality and backward compatibility.

# Running Tests

## Running all tests
```
$ make
```

## Running one test
```
$ make t/create-withdrawal-data.2-of-3-segwit.test
```
Note there is no actual file by that name.

## Measuring code coverage
```
$ make COVERAGE=1; firefox coverage-report/index.html
```

# Writing Tests

1. Create a `t/foo.run` bash script; make sure it is `chmod +x`.

2. Create a matching `t/foo.golden` file; `touch t/foo.golden` is
   sufficient to start

3. Run the test using `make t/foo.test`; it will fail since it doesn't
   match golden

4. Manually check `t/foo.out` to ensure desired output

5. `mv t/foo.{out,golden}`

6. Ensure test passes now

7. Commit!


# Test Catalog

## Tests for `create-deposit-data`

| Filename | Coverage goal |
| -------- | ------------- |
| `create-deposit-data.run` | Basic flow (p2wsh-in-p2sh) |
| `create-deposit-data.input-checks.run` | Input validation |
| `create-deposit-data.p2wsh.run` | Basic flow (p2wsh) |
| `create-deposit-data.safety-check-fails.run` | Failed safety checks |

## Tests for withdrawals (`create-withdrawal-data` and `sign-psbt`)

*There are two ways to withdraw: `create-withdrawal-data` or
`sign-psbt`. Many of the test cases overlap.*

| Test case                  | Subcommand | Issue | Coverage goal |
| -------------------------- | ---------- | ----- | ------------- |
| `2-of-3-nonsegwit`         | Both     | | 2-of-3 p2sh |
| `2-of-3-segwit`            | Both     | | 2-of-3 p2wsh-in-p2sh |
| `3-of-5-nonsegwit`         | Both     | | 3-of-5 p2sh |
| `3-of-5-segwit`            | Both     | | 3-of-5 p2wsh-in-p2sh |
| `address-needs-correction` | CWD only | | Mistyped destination address |
| `bad-cold-storage-address` | CWD only | [#57](https://github.com/GlacierProtocol/GlacierProtocol/issues/57)| Mistyped cold storage address |
| `bad-redeem-script`        | CWD only | [#57](https://github.com/GlacierProtocol/GlacierProtocol/issues/57)| Mistyped redemption script |
| `bech32`                   | Both     | | p2wpkh destination address |
| `compressed`               | Both     | | p2sh with compressed keys |
| `corrupted-value-nonsegwit`| PSBT only| | psbt with malicious modification |
| `dup-inputs`               | CWD only | [#75](https://github.com/GlacierProtocol/GlacierProtocol/issues/75) | Same input pasted twice |
| `extra-keys-nonsegwit`     | Both     | [#20](https://github.com/GlacierProtocol/GlacierProtocol/issues/20)| Validation of extra keys (p2sh) |
| `extra-keys-segwit`        | Both     | [#20](https://github.com/GlacierProtocol/GlacierProtocol/issues/20)| Validation of extra keys (p2wsh-in-p2sh) |
| `fails`                    | CWD only | | Invalid destination address |
| `insufficient-funds`       | CWD only | [#21](https://github.com/GlacierProtocol/GlacierProtocol/issues/21)| Withdrawal amount too large; correction of entered fee rate |
| `large-withdrawal`         | Both     | [#78](https://github.com/GlacierProtocol/GlacierProtocol/issues/78)| Transaction too big for single QR code |
| `not-enough-for-fee`       | CWD only | | Fee larger than unspent |
| `one-wrong-input`          | CWD only | [#23](https://github.com/GlacierProtocol/GlacierProtocol/issues/23)| Unrelated input TX pasted |
| `p2sh-segwit`              | Both     | | Basic withdrawal from p2wsh-in-p2sh address |
| `p2wsh`                    | Both     | | Basic withdrawal from p2wsh address -- also tests PSBT with both witness and non-witness UTXOs |
| `segwit-inputs`            | Both     | [#14](https://github.com/GlacierProtocol/GlacierProtocol/issues/14)| Inputs with a variety of output types |
| `too-few-keys`             | Both     | | Not enough private keys provided |
| `uncompressed`             | Both     | | Basic p2sh with uncompressed keys (original Glacier release) |
| `wrong-input`              | CWD only | | Input TX with no output to us |
| `wrong-keys-nonsegwit`     | Both     | | Validation of extra keys (p2sh) |
| `wrong-keys-segwit`        | Both     | | Validation of extra keys (p2wsh-in-p2sh) |
| `xact-file`                | CWD only | | Input xact from file |

## Tests for other miscellaneous

| Filename | Coverage goal |
| -------- | ------------- |
| `entropy.run` | Entropy subcommand |
| `help.run` | GlacierScript help screens |


# Online Regtest Wallet

The program `online_regtest_wallet.py` is used by the `Makefile` to
mimic an online node, in order to validate that the withdrawal
transactions produced by GlacierScript are valid.

It constructs a regtest blockchain, including the input transactions
as expected by the tests, then mines the generated withdrawal
transactions into blocks.

The file `tx.json` describes the input transactions as expected by the
tests.
