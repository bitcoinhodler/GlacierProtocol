# Future (fork?) of Glacier

*Proposal by BitcoinHodler*

Assuming we get a PSBT flow implemented ([issue
#54](https://github.com/GlacierProtocol/GlacierProtocol/issues/54)),
what's next?

I'd like to solve the address reuse issue. There's a couple of ways to
achieve this, with various tradeoffs in complexity and security.

# Design

## Goals

* Hard-core high security personal bitcoin storage

* Recovery possible with only M-of-N paper packets

* Low-security withdrawal process documented for heirs

* Recovery likely by heirs with only M-of-N paper packets and no
  knowledge of the wallet system, assuming Bitcoin expert consultation


### Non-goals

* Institutional storage

* Easy

* Inexpensive

* Friendly to Bitcoin newbies

* Friendly to people who fear a command line

* Shitcoins

## Assumptions

* Any online PC or printer may be compromised.

* Any hardware used may die at any time. All hardware might die
  simultaneously. (Seedless hardware wallets are out.)

* User is technically proficient and can set up a Bitcoin Core full
  node (or already has one).

## Who is this for?

* Nobody, today; it's a work-in-progress proposal for a future system.


# Options

We could create a single HD key, and split it up with Shamir's Secret
Sharing System. Or we could create many HD keys and do an HDM system
like BIP45.

## Tradeoffs

Process      | Expense | Difficulty | Security
------------ | ------- | ---------- | --------
Glacier+PSBT | Medium  | Medium     | Medium
Shamir       | Medium  | Medium     | Medium
HDM          | Higher  | Higher     | Higher

Today's Glacier concentrates all keys on one laptop, which is not the
safest way to do multisig. A sequential signing process with one key
per laptop would be a security improvement, but this has not been
implemented for Glacier. Therefore, security-wise, Shamir would not be
any worse. If we want the additional security of sequential signing
then we can go full HDM and get additional security beyond today's
Glacier.

# Shamir

## Principles

For an M-of-N system, we create N packets, each with one shard of a
single extended private key (xprv). We also create an output script
descriptor describing the wallet and print it as a QR code, to be held
by the owner and used for any wallet activities on the quarantined
laptops (since they are stateless).

Each packet contains:

* One shard of the extended private key (xprv)
  * Hand-written on paper
  * Converted to mnemonics using SLIP39 (in M-of-N mode)

In the event the output script descriptor is lost or otherwise
unavailable, it can be recreated using any M packets.

With the output script descriptor, we can (1) import the wallet as
watch-only into Bitcoin Core; (2) generate new receive addresses.

With any M-of-N packets, we can (1) recreate the output script
descriptor; (2) sign a transaction.

## Output script descriptor

`wpkh(xpub.../0/*)`; change goes to `wpkh(xpub.../1/*)`. Or should we
use a BIP84 derivation path for better wallet compatibility?

## Process descriptions

### Process: Key generation

*Use case: new user wishing to put bitcoins into cold storage*

Using the quarantined laptops, generate a single xprv using entropy
from dice & Bitcoin Core. Shamir that into mnemonics using SLIP39
(M-of-N), each 59 words. Write each set of 59 words on a separate
piece of paper. Write today's date on each page.

Generate the descriptor containing the xpub into a QR code. Scan with
phone. Power down quarantined laptops.

Import: On an online PC, paste the descriptor. Construct a PDF with
one QR code of the descriptor. Also print today's date on the page.

Verification: On a clean boot of the quarantined laptops, scan in the
printed QR code, then type in all N of the 59-word xprv shards. Script
will verify that the N shards can be recombined any of P(M,N) ways to
make an xprv that matches the xpub in the descriptor. This verifies
that the QR code has not been altered on its way through the
phone/printer, and verifies that each xprv shard has been copied down
correctly.

Display the first 10 receive addresses. Show BIP32 path for first, and
index for each. Take photo with instant film or non-wireless digital
camera.

Should we do a test deposit? So the user can prove to himself that
everything works? Part of the process is not just to confirm the
user's actions, but for the user to confirm the process.

After verification, create N packets, each with one hand-written xprv
shard. Save the master descriptor QR code separately in its own sealed
packet at home. Distribute the packets.

Follow the "Import watch-only wallet into Bitcoin Core" subprocess.

### Process: Deposit bitcoins to wallet

*Use case: placing bitcoins into cold storage*

If user doesn't have watch-only wallet in Bitcoin Core, follow "Import
watch-only wallet into Bitcoin Core" subprocess.

Get next unused receive address from Bitcoin Core, with index. Don't
show user! Tell user the index and have them type in the first 8
digits or so from photo. (If no photo, or this index is not in photo,
follow the "Generate receiving addresses" subprocess.) Once first 8
digits match, show entire address and confirm with user. Copy/paste
address and send bitcoins.

Should we go easier: just show the user and trust they actually verify
it vs photo?

Should we go harder: require user to enter the entire address and
validate that it matches that generated locally?

### Subprocess: Generate receiving addresses

*Use case: when placing bitcoins into cold storage, user has
 previously used all validated addresses*

Find next index beyond last group of photographed addresses. Using
quarantined laptop, scan descriptor QR code and type in starting
index. Take photo of next 10 addresses, displayed. Should we confirm
on the second quarantined laptop?

### Subprocess: Import watch-only wallet into Bitcoin Core

*Use case: owner has created a new vault*

*Use case: owner has a new PC and/or new install of Bitcoin Core*

*Use case: heirs have only paper packets, and want to find balance or initiate withdrawal*

Scan in the descriptor QR to the online PC. (No descriptor QR? Follow
subprocess "Recreate descriptor QR".)

Script will prompt user for creation date (printed on descriptor QR
page), create a new wallet in Bitcoin Core named after the creation
date, then import the descriptor (and its change equivalent) as
watch-only, which will scan the blockchain back to the creation date,
then display the current balance.

### Subprocess: Recreate descriptor QR

*Use case: owner has lost master descriptor QR packet*

*Use case: heirs have M-of-N packets but nothing else*

Using quarantined laptop, type in M shards of xprv. Use SLIP39 to
recreate xprv and from that, the descriptor. Display as QR code. Scan
with phone. Power down the quarantined laptops. Note the date written
on the xprv shards.

Import: On online PC, import using special import process. Ask user
for date written on papers. Print QR with descriptor and date.

Verification: on a clean boot of the quarantined laptops, scan in the
newly-created descriptor QR and type in all available xprv
shards. Verify the descriptor matches that which can be recreated
using the shards. (Must we power down the quarantined laptops during
importing & printing? As long as they're in another room, they can
stay on, right? Then we won't have to type in the xprvs again.) This
verifies that the descriptor QR has not been altered by the online PC
or printer.

Explain to user that if they don't still have access to all packets,
they should soon withdraw all bitcoins from this wallet. (This
shortcut import covers two different use cases: owner lost descriptor
QR; heirs recovering using only a subset of packets. In the former use
case, all packets are presumably accessible.)

### Process: Withdraw bitcoins from wallet

*Use case: obvious*

If user doesn't have master descriptor QR, first follow "Recreate
descriptor QR" subprocess.

If user doesn't have watch-only wallet in Bitcoin Core, follow "Import
watch-only wallet into Bitcoin Core" subprocess.

Using the online Bitcoin Core wallet, create PSBT for
withdrawal. Create change address (if needed) using change
descriptor. Create PDF with QR code(s) containing PSBT. Print the PDF.

Using the quarantined laptop, scan in the descriptor QR first. Then
scan in the PSBT QR code(s) and recreate the PSBT. Check that all
inputs and change outputs match our expected descriptor. Display tx
details to user and confirm. Then user types in M xprv shards via
mnemonics. Sign transaction. Display raw signed transaction (or
finalized PSBT?) as QR code. Scan with phone. (Might take multiple QR
codes again.)

On the online PC, display transaction details again. After
confirmation, broadcast.

(This has the same security concerns as my [current PSBT
investigation](https://github.com/bitcoinhodler/glacier-psbt) has.)

# HDM

Above and beyond: if we use N separate laptops, generate one key per
laptop, and sign transactions using sequential signing, then we never
need to have complete signature capability in any one place.

Withdrawal requires knowing the xpubs for all N keys. To ensure
recovery with only M-of-N keys, we save the output script descriptor
(with all xpubs) with each packet. To ensure privacy from nosy
signatories, we shard this with Shamir.

## Principles

For an M-of-N system, we create N packets, each with one extended
private key (xprv). We also create a simple JSON data structure
describing the wallet and print it as a QR code, to be held by the
owner and used for any wallet activities on the quarantined laptops
(since they are stateless).

The JSON contains:

* Output script descriptor, containing all N xpubs
* Password for each of the N xprvs

Each packet contains:

* One extended private key (xprv)
  * Hand-written on paper
  * Converted to mnemonics using SLIP39 (in 1-of-1 mode)
  * Encrypted so nosy signatories can't find past withdrawals
* One printed QR code containing a shard of the descriptor JSON
  * Sharded into M-of-N using SLIP39
  * Used only if master descriptor QR is lost or otherwise unavailable

With the descriptor JSON, we can (1) import the wallet as watch-only
into Bitcoin Core; (2) generate new receive addresses; and (3) decrypt
any xprv to enable signing.

With any M-of-N packets, we can (1) recreate the descriptor JSON,
containing the output script descriptor and all N xprv passwords; (2)
sign a transaction.

## Output script descriptor

`wsh(sortedmulti(2, xpub1/0/*, xpub2/0/*, xpub3/0/*, xpub4/0/*))`

Describes our deposit addresses. Change will be in a similar descriptor:

`wsh(sortedmulti(2, xpub1/1/*, xpub2/1/*, xpub3/1/*, xpub4/1/*))`

So is it safe to print out only the first descriptor in the QR code?
I'll leave a note in the JSON about change.

## Change output validation

When signing, we also need to verify that change address is valid.

Does the PSBT contain the output scripts for p2wsh outputs? It better,
for our change output to be properly validated. We need to validate
that the output address matches the accompanying script, in case the
PSBT has been tampered with.

## Process descriptions

### Process: Key generation

*Use case: new user wishing to put bitcoins into cold storage*

Using each quarantined laptop in turn, generate 1 xprv on each laptop
using entropy from dice & Bitcoin Core. Generate a random string of
gibberish as a password, and convert each xprv to mnemonics using
SLIP39 (1-of-1), each 59 words. (Or is it more, if I include the
entire bip32 data? 78 bytes instead of 64.) Write each set of 59 words
on a separate piece of paper. Write today's date on each page. (Is
this crazy? Should we just do 24 words via BIP39 and encrypt with
BIP38?) Label each laptop Q1/Q2/Q3/Q4 and label each xprv
Q1/Q2/Q3/Q4. Never type in an xprv except on its matching
laptop. (Unless exigent circumstances.) Convert each xprv's matching
xpub, plus the xprv password, to a QR code and scan with phone. (Can
we assume the owner has all N quarantined laptops in a single
location? Or do we need to seal up each xprv packet immediately upon
creation, before all N are created? We need to store a descriptor
shard with each, too, and that requires all N xpubs.)

Import: On an online PC, paste all N xpubs and construct descriptor
(including all N xprv passwords). Construct a PDF with N+1 pages, each
with one QR code: the descriptor JSON, then an M-of-N sharded SLIP39'd
set of QR coded mnemonics (500+ words each). Also print the date on
each page, and label the shards as Q1/Q2/Q3/Q4. (Order isn't really
important but we want to distinguish the shards from the master
descriptor.)

Verification: Run on each laptop in turn. Verification script will ask
user which laptop this is (Q1, Q2, etc.) If Q1 or Q2, scan in all N+1
of the generated QR codes. Script will verify that the N shards can be
recombined any of P(M,N) ways to recreate the descriptor
successfully. This verifies that the sharded QR codes have not been
altered on their way through the phone/printer. If Q3 or higher,
assume shards are good, and scan in only the master descriptor.

Type in that laptop's corresponding 59-word xprv. Script will verify
that this key matches the same-numbered xpub in the descriptor. This
verifies that each xprv has been copied down correctly, and that the
xprv password stored with the descriptor has not been altered.

If Q1, display the first 10 receive addresses. Show BIP32 path for
first, and index for each. Take photo with instant film or
non-wireless digital camera. If Q2, display the first 10 receive
addresses, and user must verify that they match the earlier photo. If
Q3 or higher, assume addresses are good, and skip this step.

Should we do a test deposit? So the user can prove to himself that
everything works? Part of the process is not just to confirm the
user's actions, but for the user to confirm the process.

After verification, create N packets, each with one hand-written xprv
and one descriptor shard QR code. Save the master descriptor QR code
with the Q1 laptop. Distribute the packets. Ideally, save each laptop
near its corresponding packet. (Just in case it's stored key
information somehow.) Don't put packets inside laptop boxes, because
it would be too easy to miss and get thrown away by someone assuming
the laptop was obsolete or its WiFi broken.

Follow the "Import watch-only wallet into Bitcoin Core" subprocess.

### Process: Deposit bitcoins to wallet

*Use case: placing bitcoins into cold storage*

If user doesn't have watch-only wallet in Bitcoin Core, follow "Import
watch-only wallet into Bitcoin Core" subprocess.

Get next unused receive address from Bitcoin Core, with index. Don't
show user! Tell user the index and have them type in the first 8
digits or so from photo. (If no photo, or this index is not in photo,
follow the "Generate receiving addresses" subprocess.) Once first 8
digits match, show entire address and confirm with user. Copy/paste
address and send bitcoins.

Should we go easier: just show the user and trust they actually verify
it vs photo?

Should we go harder: require user to enter the entire address and
validate that it matches that generated locally?

### Subprocess: Generate receiving addresses

*Use case: when placing bitcoins into cold storage, user has
 previously used all validated addresses*

Find next index beyond last group of photographed addresses. Using
quarantined laptop, scan descriptor QR code and type in starting
index. Take photo of next 10 addresses, displayed. Should we validate
on a second quarantined laptop?

### Subprocess: Import watch-only wallet into Bitcoin Core

*Use case: owner has created a new vault*

*Use case: owner has a new PC and/or new install of Bitcoin Core*

*Use case: heirs have only paper packets, and want to find balance or
 initiate withdrawal*

Scan in the descriptor QR to the online PC. (No descriptor QR? Follow
subprocess "Recreate descriptor QR".) Detect mistaken scan of
mnemonics and guide user to recovery (either rescan correct QR, or
execute the "Recreate descriptor QR" subprocess.)

Script will prompt user for creation date (printed on descriptor QR
page), create a new wallet in Bitcoin Core named after the creation
date, then import the descriptor (and its change equivalent) as
watch-only, which will scan the blockchain back to the creation date,
then display the current balance.

### Subprocess: Recreate descriptor QR

*Use case: owner has lost master descriptor QR packet*

*Use case: heirs have M-of-N packets but nothing else*

Using online PC, scan in M shards of descriptor. Use SLIP39 to
recreate descriptor. Ask user for date printed on papers. Print QR
with descriptor and date.

Verification: on a clean boot of one quarantined laptop, scan in the
newly-created descriptor QR as well as all available shards. Verify
the descriptor matches that which can be recreated using the
shards. This verifies that the descriptor QR code has not been altered
by the online PC or printer. Should we confirm on a second quarantined
laptop?

Explain to user that if they don't still have access to all packets,
they should soon withdraw all bitcoins from this wallet. (This
shortcut import covers two different use cases: owner lost descriptor
QR; heirs recovering using only a subset of packets. In the former use
case, all packets are presumably accessible.)

### Process: Withdraw bitcoins from wallet

*Use case: obvious*

If user doesn't have master descriptor QR, first follow "Recreate
descriptor QR" subprocess.

If user doesn't have watch-only wallet in Bitcoin Core, follow "Import
watch-only wallet into Bitcoin Core" subprocess.

Using the online Bitcoin Core wallet, create PSBT for
withdrawal. Create change address (if needed) using change
descriptor. Create PDF with QR code(s) containing PSBT. Print the PDF.

For each available xprv, use the corresponding quarantined laptop. (If
not available, buy and prepare a new quarantined laptop for that
xprv.) Scan in the descriptor QR first. Then scan in the PSBT QR
code(s) and recreate the PSBT. Check that all inputs and change
outputs match our expected descriptor. Display tx details to user and
confirm. Then user types in xprv key via mnemonics. Sign
transaction. Display updated PSBT as QR code. Scan with phone. (Might
take multiple QR codes again.) Could we possibly display only the new
signature and have the online node stuff that into the PSBT? Just so
we don't have scan back the entire (possibly large) PSBT?

On the online PC, import each PSBT, combine and finalize. Display
transaction details again. After user confirmation, broadcast.

(This has the same security concerns as my [current PSBT
investigation](https://github.com/bitcoinhodler/glacier-psbt) has.)

Do we need or want to validate the global xpubs in the PSBT? I don't
think we care, since we have them all from the descriptor already. And
we need the descriptor for the xprv passwords anyway.

## QR code efficiency

The descriptor JSON was designed such that someone with deep technical
knowledge of Bitcoin but limited or no knowledge of my wallet scheme
will still have a good chance of recovering the bitcoins. Ideally,
someone who recognizes the mnemonics as SLIP39 should be able to
recover the descriptor JSON and go from there.

The sharded JSON consists of 530+ mnemonic words at ~3700
characters. Encoded in QR's alphanumeric mode (which is base 45), this
is very inefficient, and limits us to L-level error correction in the
largest QR version 40. But as long as the quarantined laptop scanners
can scan it, we should be okay?

With the PSBTs, we will need the ability to split them into
multiple. We can offer the user a density option if they're having
trouble scanning the highest-density codes. But we don't want to split
up the descriptor JSON shards into multiple codes unless we really
have to.

Some options for higher-efficiency encoding of the wallet data:

* Use a binary format for the descriptor (miniscript?)

* Use a binary format for the xpubs and describe the output script in
  some other way

* Instead of JSON, use a binary format for the data structure (Google
  protobuf?)

* Truncate each mnemonic into its unique first 4 chars, and remove all
  spaces

# Questions

1. Can we find a more robust SLIP39 decoder? To help the user with a
mistyped mnemonic: report suggested corrections instead of simply
failing. Otherwise the fancy error-correcting checksum is pointless.

2. Instead of sharding the 512-bit xprv, should we do what Trezor does
with SLIP39 and use a PBKDF2-based key generation process like BIP39?
They only need 20 or 33 words, instead of 59.
