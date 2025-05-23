import ctypes
import json
import os, platform
from .types import Part1ResultT, Part2ResultT, Part3ResultT


package_dir = os.path.dirname(__file__)


def dict_to_buffer(data):
    json_str = json.dumps(data)
    json_bytes = json_str.encode('utf-8')
    json_len = len(json_bytes)

    buffer = ctypes.create_string_buffer(2 + json_len)
    buffer[0] = (json_len >> 8) & 0xFF
    buffer[1] = json_len & 0xFF
    buffer[2:] = json_bytes

    return ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))


class BaseCryptoModule:

    def __init__(self, curve_name):
        if curve_name not in self.get_curves():
            raise ValueError(
                f"Invalid curve name '{curve_name}'. valid curve names: {self.get_curves()}")

        ext = '.dylib' if platform.system() == 'Darwin' else '.so'
        lib = ctypes.CDLL(os.path.join(
            package_dir, f"libfrost_{curve_name}{ext}"))
        # lib = ctypes.CDLL(os.path.join(package_dir, f"../../../../../target/release/libfrost_{module_name}.so"))

        lib.num_to_id.argtypes = [ctypes.c_int64]
        lib.num_to_id.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.keypair_new.argtypes = []
        lib.keypair_new.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.single_sign.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.single_sign.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.single_verify.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        lib.single_verify.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.dkg_part1.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.c_uint16, ctypes.c_uint16]
        lib.dkg_part1.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.verify_proof_of_knowledge.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.verify_proof_of_knowledge.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.dkg_part2.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.dkg_part2.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.dkg_verify_secret_share.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.dkg_verify_secret_share.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.dkg_part3.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.dkg_part3.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.keys_generate_with_dealer.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.keys_split.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.c_uint16, ctypes.c_uint16]
        lib.keys_split.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.key_package_from.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
        lib.key_package_from.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.round1_commit.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
        lib.round1_commit.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.signing_package_new.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.signing_package_new.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.round2_sign.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.round2_sign.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.verify_share.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.verify_share.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.aggregate.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.aggregate.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.verify_group_signature.argtypes = [ctypes.POINTER(
            ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        lib.verify_group_signature.restype = ctypes.POINTER(ctypes.c_uint8)

        lib.mem_free.argtypes = [ctypes.POINTER(ctypes.c_uint8)]

        self.lib = lib

    @staticmethod
    def get_curves() -> list[str]:
        return ["ed25519", 'secp256k1', "secp256k1_tr"]

    def get_json_and_free_mem(self, ptr):
        u16_buffer = ctypes.string_at(ptr, 2)  # Read the first two bytes
        json_len = (u16_buffer[0] << 8) | u16_buffer[1]
        json_buffer = ctypes.string_at(
            ctypes.addressof(ptr.contents) + 2, json_len)
        try:
            # TODO: some times json_buffer is not valid json string. for example if you padd identifier instead of SigningPackage and deserialization error occuring
            data = json.loads(json_buffer)
            if isinstance(data, dict) and 'error' in data and data['error'] is not None:
                raise ValueError(data['error'])
            return data
        finally:
            self.lib.mem_free(ptr)

    def num_to_id(self, num):
        ptr = self.lib.num_to_id(num)
        data = self.get_json_and_free_mem(ptr)
        return data
    
    def keypair_new(self):
        ptr = self.lib.keypair_new()
        data = self.get_json_and_free_mem(ptr)
        return data
    
    def single_sign(self, secret: str, msg: str):
        ptr = self.lib.single_sign(
            dict_to_buffer(secret),
            dict_to_buffer(msg),
        )
        data = self.get_json_and_free_mem(ptr)
        return data
    
    def single_verify(self, signature: str, msg: str, pubkey):
        ptr = self.lib.single_verify(
            dict_to_buffer(signature),
            dict_to_buffer(msg),
            dict_to_buffer(pubkey),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_part1(self, identifier, max_signers, min_signers) -> Part1ResultT:
        ptr = self.lib.dkg_part1(dict_to_buffer(identifier), ctypes.c_uint16(
            max_signers), ctypes.c_uint16(min_signers))
        data = self.get_json_and_free_mem(ptr)
        return data

    def verify_proof_of_knowledge(self, identifier, commitments, signature) -> bool:
        ptr = self.lib.verify_proof_of_knowledge(
            dict_to_buffer(identifier),
            dict_to_buffer(commitments),
            dict_to_buffer(signature),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_part2(self, round1_secret_package, round1_packages) -> Part2ResultT:
        ptr = self.lib.dkg_part2(dict_to_buffer(
            round1_secret_package), dict_to_buffer(round1_packages))
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_verify_secret_share(self, identifier, secret_share, commitment) -> bool:
        ptr = self.lib.dkg_verify_secret_share(
            dict_to_buffer(identifier),
            dict_to_buffer(secret_share),
            dict_to_buffer(commitment)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_part3(self, round2_secret_package, round1_packages, round2_packages) -> Part3ResultT:
        ptr = self.lib.dkg_part3(
            dict_to_buffer(round2_secret_package),
            dict_to_buffer(round1_packages),
            dict_to_buffer(round2_packages)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def keys_generate_with_dealer(self, max_signers, min_signers):
        ptr = self.lib.keys_generate_with_dealer(
            ctypes.c_uint16(max_signers), ctypes.c_uint16(min_signers))
        data = self.get_json_and_free_mem(ptr)
        return data

    def keys_split(self, secret, max_signers, min_signers):
        ptr = self.lib.keys_split(
            dict_to_buffer(secret),
            ctypes.c_uint16(max_signers),
            ctypes.c_uint16(min_signers)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def key_package_from(self, key_share):
        ptr = self.lib.key_package_from(dict_to_buffer(key_share))
        data = self.get_json_and_free_mem(ptr)
        return data

    def round1_commit(self, key_share):
        ptr = self.lib.round1_commit(dict_to_buffer(key_share))
        data = self.get_json_and_free_mem(ptr)
        return data

    def signing_package_new(self, signing_commitments, msg):
        ptr = self.lib.signing_package_new(
            dict_to_buffer(signing_commitments),
            dict_to_buffer(msg)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def round2_sign(self, signing_package, signer_nonces, key_package):
        ptr = self.lib.round2_sign(
            dict_to_buffer(signing_package),
            dict_to_buffer(signer_nonces),
            dict_to_buffer(key_package)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def verify_share(self, identifier, verifying_share, signature_share, signing_package, verifying_key):
        ptr = self.lib.verify_share(
            dict_to_buffer(identifier),
            dict_to_buffer(verifying_share),
            dict_to_buffer(signature_share),
            dict_to_buffer(signing_package),
            dict_to_buffer(verifying_key)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def aggregate(self, signing_package, signature_shares, pubkey_package):
        ptr = self.lib.aggregate(
            dict_to_buffer(signing_package),
            dict_to_buffer(signature_shares),
            dict_to_buffer(pubkey_package)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def verify_group_signature(self, signature, msg, pubkey_package):
        ptr = self.lib.verify_group_signature(
            dict_to_buffer(signature),
            dict_to_buffer(msg),
            dict_to_buffer(pubkey_package)
        )
        data = self.get_json_and_free_mem(ptr)
        return data


class WithCustomTweak(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)
        
        self.lib.pubkey_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        self.lib.pubkey_tweak.restype = ctypes.POINTER(ctypes.c_uint8)
        
        self.lib.pubkey_package_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        self.lib.pubkey_package_tweak.restype = ctypes.POINTER(ctypes.c_uint8)

        self.lib.key_package_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
        self.lib.key_package_tweak.restype = ctypes.POINTER(ctypes.c_uint8)
        
    def pubkey_tweak(self, pubkey, tweak_by):
        ptr = self.lib.pubkey_tweak(
            dict_to_buffer(pubkey),
            dict_to_buffer(tweak_by)
        )
        data = self.get_json_and_free_mem(ptr)
        return data
        
    def pubkey_package_tweak(self, pubkey_package, tweak_by):
        ptr = self.lib.pubkey_package_tweak(
            dict_to_buffer(pubkey_package),
            dict_to_buffer(tweak_by)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def key_package_tweak(self, key_package, tweak_by):
        ptr = self.lib.key_package_tweak(
            dict_to_buffer(key_package),
            dict_to_buffer(tweak_by)
        )
        data = self.get_json_and_free_mem(ptr)
        return data


class Secp256k1_TR(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)

        self.lib.round2_sign_with_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.round2_sign_with_tweak.restype = ctypes.POINTER(
            ctypes.c_uint8)

        self.lib.aggregate_with_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.aggregate_with_tweak.restype = ctypes.POINTER(ctypes.c_uint8)

        self.lib.pubkey_package_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.pubkey_package_tweak.restype = ctypes.POINTER(ctypes.c_uint8)

        self.lib.key_package_tweak.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]
        self.lib.key_package_tweak.restype = ctypes.POINTER(ctypes.c_uint8)

    def round2_sign_with_tweak(self, signing_package, signer_nonces, key_package, merkle_root=None):
        ptr = self.lib.round2_sign_with_tweak(
            dict_to_buffer(signing_package),
            dict_to_buffer(signer_nonces),
            dict_to_buffer(key_package),
            None if merkle_root is None else dict_to_buffer(merkle_root)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def aggregate_with_tweak(self, signing_package, signature_shares, pubkey_package, merkle_root=None):
        ptr = self.lib.aggregate_with_tweak(
            dict_to_buffer(signing_package),
            dict_to_buffer(signature_shares),
            dict_to_buffer(pubkey_package),
            None if merkle_root is None else dict_to_buffer(merkle_root)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def pubkey_package_tweak(self, pubkey_package, merkle_root=None):
        ptr = self.lib.pubkey_package_tweak(
            dict_to_buffer(pubkey_package),
            None if merkle_root is None else dict_to_buffer(merkle_root)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def key_package_tweak(self, key_package, merkle_root=None):
        ptr = self.lib.key_package_tweak(
            dict_to_buffer(key_package),
            None if merkle_root is None else dict_to_buffer(merkle_root)
        )
        data = self.get_json_and_free_mem(ptr)
        return data


ed25519 = WithCustomTweak('ed25519')
secp256k1 = WithCustomTweak('secp256k1')
secp256k1_tr = Secp256k1_TR('secp256k1_tr')

__all__ = ['ed25519', 'secp256k1', 'secp256k1_tr']

if __name__ == "__main__":
    pass
