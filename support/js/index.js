const addon = require('./build/Release/addon.node');

function dictToBuff(obj) {let jsonStr = JSON.stringify(obj);
    let length = jsonStr.length;

    // Create a buffer with 2 bytes for the length and the rest for the string
    let buffer = Buffer.alloc(2 + length);

    // Write the length as a 16-bit integer (2 bytes) in big-endian format
    buffer.writeUInt16BE(length, 0);

    // Copy the JSON string into the buffer starting from the 3rd byte
    buffer.write(jsonStr, 2, 'utf-8');

    return buffer;
}

function numToId(num) {
    let buffer = Buffer.alloc(32); // Create a buffer of 32 bytes
    
	buffer.writeBigUInt64LE(BigInt(num), 0);

    return buffer.toString('hex').toLowerCase();
}

function dkgPart1(identifier, maxSigners, minSigners) {
	return addon.dkg_part1(
		dictToBuff(identifier),
		maxSigners,
		minSigners
	)
}

function dkgPart2(round1SecretPackage, round1Packages) {
	return addon.dkg_part2(
		dictToBuff(round1SecretPackage),
		dictToBuff(round1Packages)
	)
}

function dkgPart3(round2SecretPackage, round1Packages, round2Packages) {
	return addon.dkg_part3(
		dictToBuff(round2SecretPackage),
		dictToBuff(round1Packages),
		dictToBuff(round2Packages)
	)
}

function keysGenerateWithDealer(maxSigners, minSigners) {
	return addon.keys_generate_with_dealer(maxSigners, minSigners);
}

function keysSplit(secret, maxSigners, minSigners) {
	return addon.keys_split(
		dictToBuff(secret), 
		maxSigners, 
		minSigners
	);
}

function keyPackageFrom(secretShare) {
	return addon.key_package_from(
		dictToBuff(secretShare)
	);
}

function round1Commit(signingShare) {
	return addon.round1_commit(
		dictToBuff(signingShare)
	);
}

function signingPackageNew(commitmentsMap, message) {
	return addon.signing_package_new(
		dictToBuff(commitmentsMap), 
		dictToBuff(message)
	);
}

function round2Sign(signingPackage, nonces, keyPackage) {
	return addon.round2_sign(
		dictToBuff(signingPackage),
		dictToBuff(nonces),
		dictToBuff(keyPackage)
	)
}

function aggregate(signingPackage, signatureShares, pubkeyPackage) {
	return addon.aggregate(
		dictToBuff(signingPackage),
		dictToBuff(signatureShares),
		dictToBuff(pubkeyPackage)
	)
}

function verifyGroupSignature(groupSignature, message, pubkeyPackage) {
	return addon.verify_group_signature(
		dictToBuff(groupSignature),
		dictToBuff(message),
		dictToBuff(pubkeyPackage)
	)
}

module.exports = {
	numToId,
	dkgPart1,
	dkgPart2,
	dkgPart3,
	keysGenerateWithDealer,
	keysSplit,
	keyPackageFrom,
	round1Commit,
	signingPackageNew,
	round2Sign,
	aggregate,
	verifyGroupSignature,
};