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

*Coming soon*

# Online Regtest Wallet

The program `online_regtest_wallet.py` is used by the `Makefile` to
mimic an online node, in order to validate that the withdrawal
transactions produced by GlacierScript are valid.

It constructs a regtest blockchain, including the input transactions
as expected by the tests, then mines the generated withdrawal
transactions into blocks.

The file `tx.json` describes the input transactions as expected by the
tests.
