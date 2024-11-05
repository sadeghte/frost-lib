import frost_ed25519 as frost;


min_signers = 2
max_signers = 3

result = frost.keys_generate_with_dealer(min_signers, max_signers)
shares = result['shares']
pubkey_package = result['pubkey_package']
print("publicKey: ", pubkey_package["verifying_key"])
# print("Result:", result)

key_packages = {};
for identifier, secret_share in result["shares"].items():
	key_packages[identifier] = frost.key_package_from(secret_share)

nonces_map = {}
commitments_map = {}
"""
==========================================================================
Round 1: generating nonces and signing commitments for each participant
==========================================================================
"""
for identifier,_ in list(result["shares"].items())[:min_signers]:
	result = frost.round1_commit(
		key_packages[identifier]['signing_share'],
	);
	nonces_map[identifier] = result['nonces']
	commitments_map[identifier] = result['commitments']

signature_shares = {}
message = b"message to sign"
print("message: ", message)
signing_package = frost.signing_package_new(commitments_map, message.hex());
"""
==========================================================================
Round 2: each participant generates their signature share
==========================================================================
"""
for identifier, _ in nonces_map.items():
	signature_share = frost.round2_sign(
		signing_package,
		nonces_map[identifier],
		key_packages[identifier]
	)
	signature_shares[identifier] = signature_share
"""
==========================================================================
Aggregation: collects the signing shares from all participants,
generates the final signature.
==========================================================================
"""
group_signature = frost.aggregate(signing_package, signature_shares, pubkey_package)
print("signature: ", group_signature)

verified1 = frost.verify_group_signature(group_signature, message.hex(), pubkey_package);
verified2 = frost.verify_group_signature(group_signature, b"wrong message".hex(), pubkey_package);

print("correct message verified: ", verified1);
print("  wrong message verified: ", verified2);