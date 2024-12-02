from .wrapper import (
	get_id,
	dkg_part1,
	dkg_part2,
	dkg_part3,
	keys_generate_with_dealer,
	keys_split,
	key_package_from,
	round1_commit,
	signing_package_new,
	round2_sign,
	aggregate,
	verify_group_signature,
)

def num_to_id(num):
	num_bytes = num.to_bytes(32, 'little')
	return num_bytes.hex().lower()