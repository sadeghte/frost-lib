import hashlib
from frost_lib import secp256k1_tr as frost;

def sha256(data):
    return hashlib.sha256(data).digest()

def check_tweaked_sign_with_dealer():
    merkle_root = bytes([12] * 32)
    
    max_signers = 5
    min_signers = 3
    
    result = frost.keys_generate_with_dealer(max_signers, min_signers)
    shares = result['shares']
    pubkey_package = result['pubkey_package']
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
    
    message = b"message to sign"
    print("message: ", message)
    signature_shares = {}
    signing_package = frost.signing_package_new(commitments_map, message.hex());
    """
    ==========================================================================
    Round 2: each participant generates their signature share
    ==========================================================================
    """
    for identifier, _ in nonces_map.items():
        signature_share = frost.round2_sign_with_tweak(
            signing_package,
            nonces_map[identifier],
            key_packages[identifier],
            merkle_root.hex()
        )
        signature_shares[identifier] = signature_share
    """
    ==========================================================================
    Aggregation: collects the signing shares from all participants,
    generates the final signature.
    ==========================================================================
    """
    group_signature = frost.aggregate_with_tweak(
        signing_package, 
        signature_shares, 
        pubkey_package, 
        merkle_root.hex()
    )
    print("aggregated signature: ", group_signature)
    
    verified = frost.verify_group_signature(group_signature, message.hex(), pubkey_package);
    print("normal pubkey verified: ", verified)
    
    pubkey_package_tweaked = frost.pubkey_package_tweak(pubkey_package, merkle_root.hex());
    verified = frost.verify_group_signature(group_signature, message.hex(), pubkey_package_tweaked);
    print("tweaked pubkey verified: ", verified)




check_tweaked_sign_with_dealer()
