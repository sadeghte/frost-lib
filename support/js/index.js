const ed25519_addon = require('./build/Release/addon-ed25519.node');
const secp256k1_addon = require('./build/Release/addon-secp256k1.node');
const secp256k1_tr_addon = require('./build/Release/addon-secp256k1-tr.node');

function dictToBuff (obj) {let jsonStr = JSON.stringify(obj);
	let length = jsonStr.length;

	// Create a buffer with 2 bytes for the length and the rest for the string
	let buffer = Buffer.alloc(2 + length);

	// Write the length as a 16-bit integer (2 bytes) in big-endian format
	buffer.writeUInt16BE(length, 0);

	// Copy the JSON string into the buffer starting from the 3rd byte
	buffer.write(jsonStr, 2, 'utf-8');

	return buffer;
}

function buildModule(addon) {
	// return (function() {
		return {
			__nativeModule: addon,
			
			numToId: function(num) {
				return addon.num_to_id(num);
			},
			
			dkgPart1: function(identifier, maxSigners, minSigners) {
				return addon.dkg_part1(
					dictToBuff(identifier),
					maxSigners,
					minSigners
				)
			},
			
			verifyProofOfKnowledge: function(identifier, commitments, signature) {
				return addon.verify_proof_of_knowledge(
					dictToBuff(identifier),
					dictToBuff(commitments),
					dictToBuff(signature),
				)
			},
			
			dkgPart2: function(round1SecretPackage, round1Packages) {
				return addon.dkg_part2(
					dictToBuff(round1SecretPackage),
					dictToBuff(round1Packages)
				)
			},
			
			dkgVerifySecretShare: function(identifier, secretShare, commitment) {
				return addon.dkg_verify_secret_share(
					dictToBuff(identifier),
					dictToBuff(secretShare),
					dictToBuff(commitment),
				)
			},
			
			dkgPart3: function(round2SecretPackage, round1Packages, round2Packages) {
				return addon.dkg_part3(
					dictToBuff(round2SecretPackage),
					dictToBuff(round1Packages),
					dictToBuff(round2Packages)
				)
			},
			
			keysGenerateWithDealer: function(maxSigners, minSigners) {
				return addon.keys_generate_with_dealer(maxSigners, minSigners);
			},
			
			keysSplit: function(secret, maxSigners, minSigners) {
				return addon.keys_split(
					dictToBuff(secret), 
					maxSigners, 
					minSigners
				);
			},
			
			keysReconstruct: function(secretShares, minSigners) {
				return addon.keys_reconstruct(
					dictToBuff(secretShares), 
					minSigners
				);
			},
			
			getPubkey: function(secret) {
				return addon.get_pubkey(
					dictToBuff(secret)
				);
			},
			
			keyPackageFrom: function(secretShare) {
				return addon.key_package_from(
					dictToBuff(secretShare)
				);
			},
			
			round1Commit: function(signingShare) {
				return addon.round1_commit(
					dictToBuff(signingShare)
				);
			},
			
			signingPackageNew: function(commitmentsMap, message) {
				return addon.signing_package_new(
					dictToBuff(commitmentsMap), 
					dictToBuff(message)
				);
			},
			
			round2Sign: function(signingPackage, nonces, keyPackage) {
				return addon.round2_sign(
					dictToBuff(signingPackage),
					dictToBuff(nonces),
					dictToBuff(keyPackage)
				)
			},
			
			aggregate: function(signingPackage, signatureShares, pubkeyPackage) {
				return addon.aggregate(
					dictToBuff(signingPackage),
					dictToBuff(signatureShares),
					dictToBuff(pubkeyPackage)
				)
			},
			
			verifyGroupSignature: function(groupSignature, message, pubkeyPackage) {
				return addon.verify_group_signature(
					dictToBuff(groupSignature),
					dictToBuff(message),
					dictToBuff(pubkeyPackage)
				)
			},
		}
	// })()
}

const ed25519 = buildModule(ed25519_addon);
const secp256k1 = buildModule(secp256k1_addon);
const secp256k1_tr = buildModule(secp256k1_tr_addon);

Object.assign(ed25519, {
    pubkeyTweak: function(pubkey, tweak_by) {
        return this.__nativeModule.pubkey_tweak(
            dictToBuff(pubkey), 
            dictToBuff(tweak_by)
        )
    },

    pubkeyPackageTweak: function(pubkeyPackage, tweak_by) {
        return this.__nativeModule.pubkey_package_tweak(
            dictToBuff(pubkeyPackage), 
            dictToBuff(tweak_by)
        )
    },
    
    keyPackageTweak: function(keyPackage, tweak_by) {
        return this.__nativeModule.key_package_tweak(
            dictToBuff(keyPackage), 
            dictToBuff(tweak_by)
        )
    },
});

Object.assign(secp256k1, {
    pubkeyTweak: function(pubkey, tweak_by) {
        return this.__nativeModule.pubkey_tweak(
            dictToBuff(pubkey), 
            dictToBuff(tweak_by)
        )
    },

    pubkeyPackageTweak: function(pubkeyPackage, tweak_by) {
        return this.__nativeModule.pubkey_package_tweak(
            dictToBuff(pubkeyPackage), 
            dictToBuff(tweak_by)
        )
    },
    
    keyPackageTweak: function(keyPackage, tweak_by) {
        return this.__nativeModule.key_package_tweak(
            dictToBuff(keyPackage), 
            dictToBuff(tweak_by)
        )
    },
});

Object.assign(secp256k1_tr, {	
    round2SignWithTweak: function(signingPackage, nonces, keyPackage, merkle_root) {
        return this.__nativeModule.round2_sign_with_tweak(
            dictToBuff(signingPackage),
            dictToBuff(nonces),
            dictToBuff(keyPackage), 
            !!merkle_root ? dictToBuff(merkle_root) : null
        )
    },
    
    aggregateWithTweak: function(signingPackage, signatureShares, pubkeyPackage, merkle_root) {
        return this.__nativeModule.aggregate_with_tweak(
            dictToBuff(signingPackage),
            dictToBuff(signatureShares),
            dictToBuff(pubkeyPackage), 
            !!merkle_root ? dictToBuff(merkle_root) : null
        )
    },
    
    pubkeyPackageTweak: function(pubkeyPackage, merkle_root) {
        return this.__nativeModule.pubkey_package_tweak(
            dictToBuff(pubkeyPackage), 
            !!merkle_root ? dictToBuff(merkle_root) : null
        )
    },
    
    keyPackageTweak: function(keyPackage, merkle_root) {
        return this.__nativeModule.key_package_tweak(
            dictToBuff(keyPackage), 
            !!merkle_root ? dictToBuff(merkle_root) : null
        )
    },
});

module.exports = {
	ed25519,
	secp256k1,
	secp256k1_tr,
};