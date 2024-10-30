import ctypes
import json
import os


lib = ctypes.CDLL(os.path.abspath("./target/release/libfrost_ed25519.so"))

lib.keys_generate_with_dealer.restype = ctypes.POINTER(ctypes.c_uint8)
lib.mem_free.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

def get_json_and_free_mem(ptr):
    u16_buffer = ctypes.string_at(ptr, 2)  # Read the first two bytes
    json_len = (u16_buffer[0] << 8) | u16_buffer[1]
    json_buffer = ctypes.string_at(ctypes.addressof(ptr.contents) + 2, json_len)
    try:
        return json.loads(json_buffer)
    finally:
        lib.mem_free(ptr, json_len + 2)

def keys_generate_with_dealer(min_signers, max_signers):
    ptr = lib.keys_generate_with_dealer(ctypes.c_uint16(min_signers), ctypes.c_uint16(max_signers))
    data = get_json_and_free_mem(ptr)
    return data

if __name__ == "__main__":
	min_signers = 2
	max_signers = 3
	try:
		result = keys_generate_with_dealer(min_signers, max_signers)
		print("Result:", result)
	except Exception as e:
		print("An error occurred:", e)
