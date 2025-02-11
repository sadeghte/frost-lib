let frost = require("frost-ed25519");

let minSigners = 3;
let maxSigners = 5;
const participants = Array.from({length: maxSigners}, (v, i) => frost.numToId(i+1));

let {shares, pubkey_package: pubkeyPackage} = frost.keysGenerateWithDealer(maxSigners, minSigners);
console.log("publicKey: ", pubkeyPackage["verifying_key"])

// Verifies the secret shares from the dealer and store them in a BTreeMap.
// In practice, the KeyPackages must be sent to its respective participants
// through a confidential and authenticated channel.
let keyPackages = {};

for(let [identifier, secretShare] of Object.entries(shares)) {
	
    let keyPackage = frost.keyPackageFrom(secretShare);
	
    keyPackages[identifier] = keyPackage;
}

let noncesMap = {};
let commitmentsMap = {};

//==========================================================================
// Round 1: generating nonces and signing commitments for each participant
//==========================================================================

// In practice, each iteration of this loop will be executed by its respective participant.
for (let participantIdentifier of participants) {
    let keyPackage = keyPackages[participantIdentifier];
    // Generate one (1) nonce and one SigningCommitments instance for each
    // participant, up to _threshold_.
	
    let {nonces, commitments} = frost.round1Commit(keyPackage.signing_share);
	
    // In practice, the nonces must be kept by the participant to use in the
    // next round, while the commitment must be sent to the coordinator
    // (or to every other participant if there is no coordinator) using
    // an authenticated channel.
    noncesMap[participantIdentifier] = nonces;
    commitmentsMap[participantIdentifier] = commitments;
}

// This is what the signature aggregator / coordinator needs to do:
// - decide what message to sign
// - take one (unused) commitment per signing participant
let signatureShares = {};

let message = Buffer.from("message to sign", 'utf-8').toString('hex');
console.log(`message: "${message.toString()}"`, );
// In practice, the SigningPackage must be sent to all participants
// involved in the current signing (at least min_signers participants),
// using an authenticate channel (and confidential if the message is secret).
let signingPackage = frost.signingPackageNew(commitmentsMap, message);

//==========================================================================
// Round 2: each participant generates their signature share
//==========================================================================

// In practice, each iteration of this loop will be executed by its respective participant.
for (let participantIdentifier of Object.keys(noncesMap)) {
    let keyPackage = keyPackages[participantIdentifier];

    let nonces = noncesMap[participantIdentifier];

    // Each participant generates their signature share.
    let signatureShare = frost.round2Sign(signingPackage, nonces, keyPackage);

    // In practice, the signature share must be sent to the Coordinator
    // using an authenticated channel.
    signatureShares[participantIdentifier] = signatureShare;
}

//==========================================================================
// Aggregation: collects the signing shares from all participants,
// generates the final signature.
//==========================================================================

// Aggregate (also verifies the signature shares)
let groupSignature = frost.aggregate(signingPackage, signatureShares, pubkeyPackage);
console.log("signature: ", groupSignature);

// Check that the threshold signature can be verified by the group public
// key (the verification key).
let verified1 = frost.verifyGroupSignature(groupSignature, message, pubkeyPackage);
let verified2 = frost.verifyGroupSignature(groupSignature, Buffer.from("wrong message", 'utf-8').toString('hex'), pubkeyPackage);
	
console.log("correct message verified: ", verified1);
console.log("  wrong message verified: ", verified2);