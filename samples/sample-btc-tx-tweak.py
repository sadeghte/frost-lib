"""

Run from project root directory:
$ python samples/sample-btc-tx-tweak.py <key-file-name>

Sample:
$ python samples/sample-btc-tx-tweak.py key-file-1

"""

from frost_lib import secp256k1_tr as frost
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, TxWitnessInput
from bitcoinutils.keys import PublicKey
from bitcoinutils.constants import TAPROOT_SIGHASH_ALL
import utils
import os, sys, json

[_, key_file_name] = sys.argv

key_file_path = f'{key_file_name}.json'
if os.path.exists(key_file_name):
    raise Exception("Key file not found. pass correct file name.")


with open(key_file_path, "r") as file:
    json_data = json.load(file)
    threshold = json_data['threshold']
    n = json_data['n']
    participants = json_data['participants']
    key_packages = json_data['keyPackages']
    pubkey_package = json_data['pubkeyPackage']


tweak_by = b"sample merkle root".hex()
nonces_map = {}
commitments_map = {}
"""
==========================================================================
Round 1: generating nonces and signing commitments for each participant
==========================================================================
"""
for identifier in participants[:threshold]:
    key_package_tweaked = frost.key_package_tweak(key_packages[identifier], tweak_by)
    result = frost.round1_commit(
        key_package_tweaked['signing_share'],
    )
    nonces_map[identifier] = result['nonces']
    commitments_map[identifier] = result['commitments']

"""
==========================================================================
Round 2: creating transaction
==========================================================================
"""

pubkey_package_tweaked = frost.pubkey_package_tweak(pubkey_package, tweak_by)
public_key = PublicKey(pubkey_package['verifying_key'])
public_key_tweaked = PublicKey(pubkey_package_tweaked['verifying_key'])
# print("publicKey:", public_key.to_hex())

taproot_address = public_key_tweaked.get_taproot_address()
print("address:", taproot_address.to_string())

utxo = utils.get_utxos(taproot_address.to_string())[0]
# print("utxo:", json.dumps(utxo, indent=2))

amount = utxo["value"]
fee = 150

txin = TxInput(utxo['txid'], utxo['vout'])
# print("txin:", txin)

# create transaction output
txout = TxOutput(amount - fee, taproot_address.to_script_pub_key())
# print("txout", txout)

tx = Transaction([txin], [txout], has_segwit=True)
# print("tx: ", tx)
utxos_scriptPubkeys = [taproot_address.to_script_pub_key()]
amounts = [amount]
tx_digest = tx.get_transaction_taproot_digest(
    0, utxos_scriptPubkeys, amounts, 0, sighash=TAPROOT_SIGHASH_ALL
)
print("tx digest:", tx_digest.hex())

"""
==========================================================================
Round 2: each participant generates their signature share
==========================================================================
"""
signature_shares = {}
signing_package = frost.signing_package_new(commitments_map, tx_digest.hex())
# print(json.dumps(signing_package, indent=2))

for identifier, _ in nonces_map.items():
    signature_share = frost.round2_sign_with_tweak(
        signing_package,
        nonces_map[identifier],
        frost.key_package_tweak(key_packages[identifier], tweak_by),
        None
    )
    signature_shares[identifier] = signature_share
# print(signature_shares)
"""
==========================================================================
Aggregation: collects the signing shares from all participants,
generates the final signature.
==========================================================================
"""
group_signature = frost.aggregate_with_tweak(
    signing_package, signature_shares, pubkey_package_tweaked, None)

verified = frost.verify_group_signature(
    group_signature, 
    tx_digest.hex(), 
    frost.pubkey_package_tweak(pubkey_package_tweaked, None)
)
assert verified, "group signature not verified"

"""
==========================================================================
TX broadcast
==========================================================================
"""

tx.witnesses.append(TxWitnessInput([group_signature]))

tx_hash = utils.broadcast_tx(tx.serialize())
print("TX Hash: ", tx_hash)
