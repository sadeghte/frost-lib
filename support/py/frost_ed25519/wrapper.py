import ctypes
import json
import os
from .types import Part1ResultT, Part2ResultT, Part3ResultT


package_dir = os.path.dirname(__file__)
lib = ctypes.CDLL(os.path.join(package_dir, 'libfrost_ed25519.so'))
# lib = ctypes.CDLL(os.path.join(package_dir, '../../../lib/target/release/libfrost_ed25519.so'))

lib.get_id.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
lib.get_id.restype = ctypes.POINTER(ctypes.c_uint8)

lib.dkg_part1.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16, ctypes.c_uint16]
lib.dkg_part1.restype = ctypes.POINTER(ctypes.c_uint8)

lib.dkg_part2.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.dkg_part2.restype = ctypes.POINTER(ctypes.c_uint8)

lib.dkg_part3.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.dkg_part3.restype = ctypes.POINTER(ctypes.c_uint8)

lib.keys_generate_with_dealer.restype = ctypes.POINTER(ctypes.c_uint8)

lib.keys_split.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16, ctypes.c_uint16]
lib.keys_split.restype = ctypes.POINTER(ctypes.c_uint8)

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
lib.verify_group_signature.restype = ctypes.POINTER(ctypes.c_uint8)

lib.mem_free.argtypes = [ctypes.POINTER(ctypes.c_uint8)]

def get_json_and_free_mem(ptr):
	u16_buffer = ctypes.string_at(ptr, 2)  # Read the first two bytes
	json_len = (u16_buffer[0] << 8) | u16_buffer[1]
	json_buffer = ctypes.string_at(ctypes.addressof(ptr.contents) + 2, json_len)
	try:
		data = json.loads(json_buffer)
		if isinstance(data, dict) and 'error' in data and data['error'] is not None:
			raise ValueError(data['error'])
		return data;
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

def get_id(identifier):
	ptr = lib.get_id(dict_to_buffer(identifier));
	data = get_json_and_free_mem(ptr)
	return data

def dkg_part1(identifier, max_signers, min_signers) -> Part1ResultT:
	ptr = lib.dkg_part1(dict_to_buffer(identifier), ctypes.c_uint16(max_signers), ctypes.c_uint16(min_signers));
	data = get_json_and_free_mem(ptr)
	return data

def dkg_part2(round1_secret_package, round1_packages) -> Part2ResultT:
	ptr = lib.dkg_part2(dict_to_buffer(round1_secret_package), dict_to_buffer(round1_packages));
	data = get_json_and_free_mem(ptr)
	return data

def dkg_part3(round2_secret_package, round1_packages, round2_packages) -> Part3ResultT:
	ptr = lib.dkg_part3(
		dict_to_buffer(round2_secret_package), 
		dict_to_buffer(round1_packages),
		dict_to_buffer(round2_packages)
	);
	data = get_json_and_free_mem(ptr)
	return data

def keys_generate_with_dealer(max_signers, min_signers):
	ptr = lib.keys_generate_with_dealer(ctypes.c_uint16(max_signers), ctypes.c_uint16(min_signers))
	data = get_json_and_free_mem(ptr)
	return data

def keys_split(secret, max_signers, min_signers):
	ptr = lib.keys_split(
		dict_to_buffer(secret),
		ctypes.c_uint16(max_signers), 
		ctypes.c_uint16(min_signers)
	)
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
	ptr = lib.verify_group_signature(
		dict_to_buffer(signature), 
		dict_to_buffer(msg), 
		dict_to_buffer(pubkey_package)
	)
	data = get_json_and_free_mem(ptr)
	return data

if __name__ == "__main__":
	pass


