# HodlerGlacier
Glacier was a protocol for secure cold storage of bitcoins.

This is BitcoinHodler's fork of the [canonical
repo](https://github.com/GlacierProtocol/GlacierProtocol) which as of
October 2020 is abandoned and broken.

# Who is this repo for?

Nobody except myself and those who know me and trust me. I could steal
your bitcoins.

# So how can I withdraw my Glacier coins?

Don't use this repo unless you know me personally.

Instead, use the [0.94
release](https://github.com/GlacierProtocol/GlacierProtocol/releases)
but hand-modify the doc according to [this
gist](https://gist.github.com/bitcoinhodler/8be823fae7b46e924caa594abdde3bd0)
in order to fix [this
issue](https://github.com/GlacierProtocol/GlacierProtocol/issues/38).

# What's changed from the upstream Glacier project?

## Features

*Merged branch names in parentheses.*

* (psbt) Added PSBT withdrawal support (part of
  [#54](https://github.com/GlacierProtocol/GlacierProtocol/issues/54))

* (sequential-sign) Added sequential PSBT signing, so you never have
  to bring all keys to one location to sign a transaction.

* (p2wsh) Added `--p2wsh` flag to create native segwit deposit
  addresses. [PR
  #76](https://github.com/GlacierProtocol/GlacierProtocol/pull/76)

## Bug fixes

* (fix-large-withdrawal) Split withdrawal transaction into multiple QR
  codes if it gets too large for one. [PR
  #79](https://github.com/GlacierProtocol/GlacierProtocol/pull/79),
  issue
  [#78](https://github.com/GlacierProtocol/GlacierProtocol/issues/78).

* (validate-keys) Make sure if user provides more keys than needed,
  they are really the correct keys for this wallet. [PR
  #73](https://github.com/GlacierProtocol/GlacierProtocol/pull/73)

  * Ensure if user enters address that doesn't correspond to redeem
    script, we don't freak out. Issue
    [#57](https://github.com/GlacierProtocol/GlacierProtocol/issues/57)

  * Add a test for extra keys using both legacy and segwit. Issue
    [#20](https://github.com/GlacierProtocol/GlacierProtocol/issues/20)

* (dup-inputs) Ensure if user enters same input transaction twice, we
  don't quietly generate an invalid withdrawal transaction. Issue
  [#75](https://github.com/GlacierProtocol/GlacierProtocol/issues/75)

* (fix-fee) Correct transaction fee when no change made. Issue
  [#19](https://github.com/GlacierProtocol/GlacierProtocol/issues/19)

  * Also contains some major refactoring to make the actual fix easy.

* (no-floats) Avoid any floating point for BTC values

* (subparsers) Use python argparse's subparsers
  ([#63](https://github.com/GlacierProtocol/GlacierProtocol/issues/63))

  * Also solves [#69](https://github.com/GlacierProtocol/GlacierProtocol/issues/69)

* (default-wallet) Create default wallet for bitcoind if one doesn't
  yet exist. Needed for compatibility with future Bitcoin Core 0.21
  release. See [#15454](https://github.com/bitcoin/bitcoin/pull/15454).

* (bitcoin-core-22) Added compatibility with Bitcoin Core 22.0.

* (no-descriptors) Avoid creating descriptor wallet; needed for
  compatibility with Bitcoin Core 23.0.

* (bitcoin-core-23) Added compatibility with Bitcoin Core 23.0.

* (recreate-all-tests) Added system to recreate all tests when Bitcoin
  Core changes.

* (bitcoin-core-24) Added compatibility with Bitcoin Core 24.0.

* (desc-offline) Convert offline wallet (glacierscript.py) to use
  descriptor wallets.

## Improvements for Glacier developers

* (tidypy) Clean up source code using linters from
  [TidyPy](https://pypi.org/project/tidypy/)

  * Run `tidypy check` to run linter

  * Also enabled coverage; run `make COVERAGE=1; firefox
    coverage-report/index.html`

  * Added several new tests to plug coverage holes

  * Still several lint failures; I'm not sure of the best way to fix
    them

* (regtest) Switch developer tests from testnet to regtest
  ([#72](https://github.com/GlacierProtocol/GlacierProtocol/issues/72))

  * This is a necessary precursor to using PSBT, since the developer
    tests will need an "online" node to construct and validate the
    withdrawal transactions

  * Allows us to validate all withdrawal transactions generated by
    GlacierScript as an automated part of the developer tests.

* (corrupted-psbts) New developer tests to demonstrate that
  GlacierScript will not generate valid transactions from maliciously
  malformed PSBTs

# Future

Now that PSBT signing is in place, I need to design and document the
online node flow to create the PSBTs for signing.

Once that's in place, I'd like to upgrade the system to use HDM
(hierarchical deterministic multisig), a simplified form of
[BIP45](https://github.com/bitcoin/bips/blob/master/bip-0045.mediawiki),
to put an end to the current address reuse. With HDM, every deposit
will be to a unique address, and every one of those deposits can be
withdrawn using the same M-of-N set of master keys. PSBT can already
handle this nicely, though we will need to generate receiving
addresses using the quarantined laptops.

This creates new dangers of obsolescence, unfortunately. If this
wallet software isn't maintained, it might be very difficult to
withdraw Glacier-stored coins in the distant future. We already have
enough trouble maintaining the current Glacier.
