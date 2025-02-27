"""

Run from project root directory:
$ python samples/sample-frost-dkg.py <key-file-name> <threshold> <num-signers>

Sample:
$ python samples/sample-frost-dkg.py key-file-1 2 3

"""

from frost_lib import secp256k1_tr as frost
import json, os, sys


[_, key_file_name, _threshold, _max] = sys.argv

min_signers = int(_threshold)
max_signers = int(_max)

participants: list[str] = [frost.num_to_id(id) for id in range(1, max_signers+1)]
# print(json.dumps(participants, indent=4))

round1_secret_packages = {}
received_round1_packages = {}

"""
============================================================================
| Key generation, Round 1
============================================================================
"""
for identifier in participants:
    result_part1 = frost.dkg_part1(
        identifier,
        max_signers,
        min_signers,
    )
    # print("result: ", result_part1);

    round1_secret_packages[identifier] = result_part1["secret_package"]

    for receiver_identifier in participants:
        if receiver_identifier == identifier:
            continue
        if received_round1_packages.get(receiver_identifier) is None:
            received_round1_packages[receiver_identifier] = {}
        received_round1_packages[receiver_identifier][identifier] = result_part1["package"]

"""
============================================================================
| Key generation, Round 2
============================================================================
"""
round2_secret_packages = {}
received_round2_packages = {}

for identifier in participants:
    # print("Identifier: ", identifier)
    round1_secret_package = round1_secret_packages[identifier]
    round1_packages = received_round1_packages[identifier]
    # print("round1_secret_package: ", json.dumps(round1_secret_package, indent=4))
    result_part2 = frost.dkg_part2(round1_secret_package, round1_packages)
    (round2_secret_package,
     round2_packages) = result_part2["secret_package"], result_part2["packages"]
    # print("result: ", json.dumps(result_part2, indent=2));
    round2_secret_packages[identifier] = round2_secret_package

    for receiver_identifier, round2_package in round2_packages.items():
        if received_round2_packages.get(receiver_identifier) is None:
            received_round2_packages[receiver_identifier] = {}
        received_round2_packages[receiver_identifier][identifier] = round2_package

"""
============================================================================
| Key generation, final computation
============================================================================
"""

key_packages = {}
pubkey_packages = {}

for participant_identifier in participants:
    round2_secret_package = round2_secret_packages[participant_identifier]
    round1_packages = received_round1_packages[participant_identifier]
    round2_packages = received_round2_packages[participant_identifier]

    result_part3 = frost.dkg_part3(
        round2_secret_package,
        round1_packages,
        round2_packages,
    )

    (key_package,
     pubkey_package) = result_part3["key_package"], result_part3["pubkey_package"]

    key_packages[participant_identifier] = key_package
    pubkey_packages[participant_identifier] = pubkey_package
pubkey_package = pubkey_packages[participants[0]]

# print("key_packages", json.dumps(key_packages, indent=2))
# print("pubkey_packages", json.dumps(pubkey_packages, indent=2))

key_file_path = f"{key_file_name}.json"

if os.path.exists(key_file_path):
    raise Exception("Key file exist. rename it or pass another name.")

with open(key_file_path, "w") as file:
    text = json.dumps({
        "threshold": min_signers,
        "n": max_signers,
        "participants": participants,
        "keyPackages": key_packages,
        "pubkeyPackage": pubkey_package
    }, indent=4)
    file.write(text)

print('key: ', pubkey_package["verifying_key"])
