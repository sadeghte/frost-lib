from frost_lib import secp256k1_tr as frost
import json


min_signers = 2
max_signers = 3

result = frost.keys_split(
    'c01a8db2b719feda0025eee7f74b0632c2d0ef9d44960cb806485abc043742d0', 
    max_signers, 
    min_signers
)

shares = result['shares']
pubkey_package = result['pubkey_package']

participants = []
key_packages = {}
for id, share in shares.items():
    participants.append(id)
    key_packages[id] = {
        "header": share['header'],
        "identifier": share['identifier'],
        "signing_share": share['signing_share'],
        "verifying_share": share['signing_share'],
        "verifying_share": pubkey_package['verifying_shares'][id],
        "verifying_key": pubkey_package['verifying_key'],
        "min_signers": min_signers,
    }

with open(f"{pubkey_package['verifying_key']}.json", "w") as file:
    text = json.dumps({
        "threshold": min_signers,
        "n": max_signers,
        "participants": participants,
        "keyPackages": key_packages,
        "pubkeyPackage": pubkey_package
    }, indent=4)
    file.write(text)

print('key: ', pubkey_package["verifying_key"])
