import ctypes
import json
import os


lib = ctypes.CDLL(os.path.abspath("./target/release/libfrost_ed25519.so"))

lib.keys_generate_with_dealer.restype = ctypes.POINTER(ctypes.c_uint8)
lib.key_package_from.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
lib.key_package_from.restype = ctypes.POINTER(ctypes.c_uint8)
lib.round1_commit.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
lib.round1_commit.restype = ctypes.POINTER(ctypes.c_uint8)
lib.signing_package_new.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.signing_package_new.restype = ctypes.POINTER(ctypes.c_uint8)
lib.round2_sign.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.round2_sign.restype = ctypes.POINTER(ctypes.c_uint8)
lib.aggregate.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.aggregate.restype = ctypes.POINTER(ctypes.c_uint8)
lib.verify_group_signature.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.verify_group_signature.restype = ctypes.c_bool
lib.mem_free.argtypes = [ctypes.POINTER(ctypes.c_uint8)]

def get_json_and_free_mem(ptr):
	u16_buffer = ctypes.string_at(ptr, 2)  # Read the first two bytes
	json_len = (u16_buffer[0] << 8) | u16_buffer[1]
	json_buffer = ctypes.string_at(ctypes.addressof(ptr.contents) + 2, json_len)
	try:
		return json.loads(json_buffer)
	finally:
		lib.mem_free(ptr)  
   
def dict_to_buffer(data):
	json_str = json.dumps(data)
	json_bytes = json_str.encode('utf-8')
	json_len = len(json_bytes)

	buffer = ctypes.create_string_buffer(2 + json_len)
	buffer[0] = (json_len >> 8) & 0xFF  
	buffer[1] = json_len & 0xFF         
	buffer[2:] = json_bytes            

	return ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))

def keys_generate_with_dealer(min_signers, max_signers):
	ptr = lib.keys_generate_with_dealer(ctypes.c_uint16(min_signers), ctypes.c_uint16(max_signers))
	data = get_json_and_free_mem(ptr)
	return data

def key_package_from(key_share):
	ptr = lib.key_package_from(dict_to_buffer(key_share))
	data = get_json_and_free_mem(ptr)
	return data

def round1_commit(key_share):
	ptr = lib.round1_commit(dict_to_buffer(key_share))
	data = get_json_and_free_mem(ptr)
	return data

def signing_package_new(signing_commitments, msg):
	ptr = lib.signing_package_new(
		dict_to_buffer(signing_commitments), 
		dict_to_buffer(msg)
	)
	data = get_json_and_free_mem(ptr)
	return data

def round2_sign(signing_package, signer_nonces, key_package):
	ptr = lib.round2_sign(
		dict_to_buffer(signing_package), 
		dict_to_buffer(signer_nonces), 
		dict_to_buffer(key_package)
	)
	data = get_json_and_free_mem(ptr)
	return data

def aggregate(signing_package, signature_shares, pubkey_package):
	ptr = lib.aggregate(
		dict_to_buffer(signing_package), 
		dict_to_buffer(signature_shares), 
		dict_to_buffer(pubkey_package)
	)
	data = get_json_and_free_mem(ptr)
	return data

def verify_group_signature(signature, msg, pubkey_package):
	verified = lib.verify_group_signature(
		dict_to_buffer(signature), 
		dict_to_buffer(msg), 
		dict_to_buffer(pubkey_package)
	)
	return verified

if __name__ == "__main__":
	min_signers = 2
	max_signers = 3
	
	result = keys_generate_with_dealer(min_signers, max_signers)
	shares = result['shares']
	pubkey_package = result['pubkey_package']
	# print("Result:", result)
	
	key_packages = {};
	for identifier, secret_share in result["shares"].items():
		key_packages[identifier] = key_package_from(secret_share)
	
	nonces_map = {}
	commitments_map = {}
	"""
	==========================================================================
	Round 1: generating nonces and signing commitments for each participant
	==========================================================================
	"""
	for identifier,_ in list(result["shares"].items())[:min_signers]:
		result = round1_commit(
			key_packages[identifier]['signing_share'],
		);
		nonces_map[identifier] = result['nonces']
		commitments_map[identifier] = result['commitments']
	
	signature_shares = {}
	message = b"message to sign"
	signing_package = signing_package_new(commitments_map, message.hex());
	"""
	==========================================================================
	Round 2: each participant generates their signature share
	==========================================================================
	"""
	for identifier, _ in nonces_map.items():
		signature_share = round2_sign(
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
	group_signature = aggregate(signing_package, signature_shares, pubkey_package)

	verified1 = verify_group_signature(group_signature, message.hex(), pubkey_package);
	verified2 = verify_group_signature(group_signature, b"wrong message".hex(), pubkey_package);

	print("publicKey: ", pubkey_package)
	print("signature: ", group_signature)
	print("correct message verified: ", verified1);
	print("  wrong message verified: ", verified2);


