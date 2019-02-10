Are you running this on a computer WITHOUT a network connection of any kind? (y/n)?Have the wireless cards in this computer been physically removed? (y/n)?Are you running on battery power? (y/n)?Are you running on an operating system booted from a USB drive? (y/n)?Is your screen hidden from view of windows, cameras, and other people? (y/n)?Are smartphones and all other nearby devices turned off and in a Faraday bag? (y/n)?
You will need to enter several pieces of information to create a withdrawal transaction.


*** PLEASE BE SURE TO ENTER THE CORRECT DESTINATION ADDRESS ***


Source cold storage address: 
Redemption script for source cold storage address: 
Destination address: 
How many unspent transactions will you be using for this withdrawal? 
Please paste raw transaction #1 (hexadecimal format) with unspent outputs at the source address
OR
input a filename located in the current directory which contains the raw transaction data
(If the transaction data is over ~4000 characters long, you _must_ use a file.):

Transaction data found for source address.
TOTAL unspent amount for this raw transaction: 0.10000000 BTC

How many private keys will you be signing this transaction with? 
#: Key #1: Key #2: 
Enter fee rate.
Satoshis per vbyte: Traceback (most recent call last):
  File "../../glacierscript.py", line <.*> in bitcoin_cli_checkoutput
    if retcode != 0: raise subprocess.CalledProcessError(retcode, cmd_list, output=output)
subprocess.CalledProcessError: Command '['bitcoin-cli', '-testnet', '-rpcport=<\d+>', '-datadir=bitcoin-test-data', 'createrawtransaction', '[{"txid": "e0e9bb25fb873c4caccdc8ab743c4350310031f2cc077bb90c3f495458860157", "vout": 1, "amount": 0.1, "scriptPubKey": "a914ad50fb2489353008e75b0193011ff1f4b76f798c87", "redeemScript": "522103d14ddcfb6817f5579695bbb3eb3e185887bf2942b031e6f716343b8fe7e9e8e221028fcd46f8614b2cbf318096968242a1e22bcfb6d8f2b6dc939c8c27c347b2937b210315acb550120f4cdcb460d5c49080ab508ca4ccd8dedecac22feeac8cd017d4c121022b063ee2f22f9e1982c140fe778672c683111a796dcccdbd47bb65e3d608a98354ae"}]', '{"2N93du8YobdgsHyu3qgBvSyhGUT52utMNeA": 0, "myP4xdJNwAW9iMakvCjnozg814ewgn8apx": 0}']' returned non-zero exit status 5<\.?>
