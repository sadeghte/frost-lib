let frost = require("frost-ed25519");

const minSigners = 2;
const maxSigners = 3;
const participants = Array.from({length: maxSigners}, (v, i) => frost.numToIdentifier(i+1));

//============================================================================
// Key generation, Round 1
//============================================================================

// Keep track of each participant's round 1 secret package.
// In practice each participant will keep its copy; no one
// will have all the participant's packages.
const round1SecretPackages = {};

// Keep track of all round 1 packages sent to the given participant.
// This is used to simulate the broadcast; in practice the packages
// will be sent through some communication channel.
const receivedRound1Packages = {};

// For each participant, perform the first part of the DKG protocol.
// In practice, each participant will perform this on their own environments.
for(let participantIdentifier of participants) {
	let {secret_package, package} = frost.dkgPart1(
		participantIdentifier,
		maxSigners,
		minSigners
	)
	
	// Store the participant's secret package for later use.
    // In practice each participant will store it in their own environment.
	round1SecretPackages[participantIdentifier] = secret_package;

    // "Send" the round 1 package to all other participants. In this
    // test this is simulated using a BTreeMap; in practice this will be
    // sent through some communication channel.
	for(let receiverParticipantIdentifier of participants) {
        if(receiverParticipantIdentifier == participantIdentifier) {
            continue;
        }
		if(!receivedRound1Packages[receiverParticipantIdentifier])
			receivedRound1Packages[receiverParticipantIdentifier] = {};
        receivedRound1Packages[receiverParticipantIdentifier][participantIdentifier] = package;
    }
}

//============================================================================
// Key generation, Round 2
//============================================================================

// Keep track of each participant's round 2 secret package.
// In practice each participant will keep its copy; no one
// will have all the participant's packages.
const round2SecretPackages = {};

// Keep track of all round 2 packages sent to the given participant.
// This is used to simulate the broadcast; in practice the packages
// will be sent through some communication channel.
const receivedRound2Packages = {};

// For each participant, perform the second part of the DKG protocol.
// In practice, each participant will perform this on their own environments.
for(let participantIdentifier of participants) {
    let round1SecretPackage = round1SecretPackages[participantIdentifier]
    let round1Packages = receivedRound1Packages[participantIdentifier];
    
    let {secret_package, packages} = frost.dkgPart2(round1SecretPackage, round1Packages);

    // Store the participant's secret package for later use.
    // In practice each participant will store it in their own environment.
    round2SecretPackages[participantIdentifier] = secret_package;

    // "Send" the round 2 package to all other participants. In this
    // test this is simulated using a BTreeMap; in practice this will be
    // sent through some communication channel.
    // Note that, in contrast to the previous part, here each other participant
    // gets its own specific package.
    for(let [receiverIdentifier, round2Package] of Object.entries(packages)) {
		if(!receivedRound2Packages[receiverIdentifier])
			receivedRound2Packages[receiverIdentifier] = {}
        receivedRound2Packages[receiverIdentifier][participantIdentifier] = round2Package;
    }
}

//============================================================================
// Key generation, final computation
//============================================================================

// Keep track of each participant's long-lived key package.
// In practice each participant will keep its copy; no one
// will have all the participant's packages.
let keyPackages = {};

// Keep track of each participant's public key package.
// In practice, if there is a Coordinator, only they need to store the set.
// If there is not, then all candidates must store their own sets.
// All participants will have the same exact public key package.
let pubkeyPackages = {};

// For each participant, perform the third part of the DKG protocol.
// In practice, each participant will perform this on their own environments.
for(let participantIdentifier of participants) {
    let round2SecretPackage = round2SecretPackages[participantIdentifier];
    let round1Packages = receivedRound1Packages[participantIdentifier];
    let round2Packages = receivedRound2Packages[participantIdentifier];
    
    let {key_package, pubkey_package} = frost.dkgPart3(
        round2SecretPackage,
        round1Packages,
        round2Packages,
    );
    
    keyPackages[participantIdentifier] = key_package;
    pubkeyPackages[participantIdentifier] = pubkey_package;
}

console.log({keyPackages, pubkeyPackages})

// With its own key package and the pubkey package, each participant can now proceed
// to sign with FROST.