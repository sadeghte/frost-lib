import json

from .secp256k1_tr import ffi, lib
from .types import Part1ResultT, Part2ResultT, Part3ResultT


def dict_to_buffer(data):
    json_str = json.dumps(data)
    json_bytes = json_str.encode("utf-8")
    return ffi.new("char[]", json_bytes + b"\0")


class BaseCryptoModule:
    def __init__(self, curve_name):
        if curve_name not in self.get_curves():
            raise ValueError(
                f"Invalid curve name '{curve_name}'. valid curve names: {self.get_curves()}"
            )
        self.ffi = ffi
        self.lib = lib

    @staticmethod
    def get_curves() -> list[str]:
        return ["ed25519", "secp256k1", "secp256k1_tr"]

    def get_json_and_free_mem(self, ptr):
        if ptr == ffi.NULL:
            raise ValueError("Received null pointer from Rust function")

        try:
            # Read null-terminated C string
            json_buffer = ffi.string(ptr).decode("utf-8")
            if not json_buffer:
                raise ValueError("Empty JSON buffer returned")

            # Parse JSON
            data = json.loads(json_buffer)
            if isinstance(data, dict) and "error" in data and data["error"]:
                raise ValueError(f"Rust error: {data['error']}")
            return data
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid UTF-8 data: {e}")
        finally:
            lib.mem_free(ptr)

    def get_id(self, identifier):
        ptr = self.lib.get_id(dict_to_buffer(identifier))
        data = self.get_json_and_free_mem(ptr)
        return data

    def num_to_id(self, num):
        ptr = self.lib.num_to_id(num)
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_part1(self, identifier, max_signers, min_signers) -> Part1ResultT:
        ptr = self.lib.dkg_part1(
            dict_to_buffer(identifier),
            max_signers,
            min_signers,
        )
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
        ptr = self.lib.dkg_part2(
            dict_to_buffer(round1_secret_package), dict_to_buffer(round1_packages)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_verify_secret_share(self, identifier, secret_share, commitment) -> bool:
        ptr = self.lib.dkg_verify_secret_share(
            dict_to_buffer(identifier),
            dict_to_buffer(secret_share),
            dict_to_buffer(commitment),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def dkg_part3(
        self, round2_secret_package, round1_packages, round2_packages
    ) -> Part3ResultT:
        ptr = self.lib.dkg_part3(
            dict_to_buffer(round2_secret_package),
            dict_to_buffer(round1_packages),
            dict_to_buffer(round2_packages),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def keys_generate_with_dealer(self, max_signers, min_signers):
        ptr = self.lib.keys_generate_with_dealer(max_signers, min_signers)
        data = self.get_json_and_free_mem(ptr)
        return data

    def keys_split(self, secret, max_signers, min_signers):
        ptr = self.lib.keys_split(
            dict_to_buffer(secret),
            max_signers,
            min_signers,
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
            dict_to_buffer(signing_commitments), dict_to_buffer(msg)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def round2_sign(self, signing_package, signer_nonces, key_package):
        ptr = self.lib.round2_sign(
            dict_to_buffer(signing_package),
            dict_to_buffer(signer_nonces),
            dict_to_buffer(key_package),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def verify_share(
        self,
        identifier,
        verifying_share,
        signature_share,
        signing_package,
        verifying_key,
    ):
        ptr = self.lib.verify_share(
            dict_to_buffer(identifier),
            dict_to_buffer(verifying_share),
            dict_to_buffer(signature_share),
            dict_to_buffer(signing_package),
            dict_to_buffer(verifying_key),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def aggregate(self, signing_package, signature_shares, pubkey_package):
        ptr = self.lib.aggregate(
            dict_to_buffer(signing_package),
            dict_to_buffer(signature_shares),
            dict_to_buffer(pubkey_package),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def verify_group_signature(self, signature, msg, pubkey_package):
        ptr = self.lib.verify_group_signature(
            dict_to_buffer(signature),
            dict_to_buffer(msg),
            dict_to_buffer(pubkey_package),
        )
        data = self.get_json_and_free_mem(ptr)
        return data


class WithCustomTweak(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)

    def pubkey_tweak(self, pubkey, tweak_by):
        ptr = self.lib.pubkey_tweak(dict_to_buffer(pubkey), dict_to_buffer(tweak_by))
        data = self.get_json_and_free_mem(ptr)
        return data

    def pubkey_package_tweak(self, pubkey_package, tweak_by):
        ptr = self.lib.pubkey_package_tweak(
            dict_to_buffer(pubkey_package), dict_to_buffer(tweak_by)
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def key_package_tweak(self, key_package, tweak_by):
        ptr = self.lib.key_package_tweak(
            dict_to_buffer(key_package), dict_to_buffer(tweak_by)
        )
        data = self.get_json_and_free_mem(ptr)
        return data


class Secp256k1_TR(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)

    def round2_sign_with_tweak(
        self, signing_package, signer_nonces, key_package, merkle_root=None
    ):
        ptr = self.lib.round2_sign_with_tweak(
            dict_to_buffer(signing_package),
            dict_to_buffer(signer_nonces),
            dict_to_buffer(key_package),
            None if merkle_root is None else dict_to_buffer(merkle_root),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def aggregate_with_tweak(
        self, signing_package, signature_shares, pubkey_package, merkle_root=None
    ):
        ptr = self.lib.aggregate_with_tweak(
            dict_to_buffer(signing_package),
            dict_to_buffer(signature_shares),
            dict_to_buffer(pubkey_package),
            None if merkle_root is None else dict_to_buffer(merkle_root),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def pubkey_package_tweak(self, pubkey_package, merkle_root=None):
        ptr = self.lib.pubkey_package_tweak(
            dict_to_buffer(pubkey_package),
            "" if merkle_root is None else dict_to_buffer(merkle_root),
        )
        data = self.get_json_and_free_mem(ptr)
        return data

    def key_package_tweak(self, key_package, merkle_root=None):
        ptr = self.lib.key_package_tweak(
            dict_to_buffer(key_package),
            "" if merkle_root is None else dict_to_buffer(merkle_root),
        )
        data = self.get_json_and_free_mem(ptr)
        return data


# ed25519 = WithCustomTweak("ed25519")
# secp256k1 = WithCustomTweak("secp256k1")
secp256k1_tr = Secp256k1_TR("secp256k1_tr")

__all__ = [
    # "ed25519",
    # "secp256k1",
    "secp256k1_tr"
]

if __name__ == "__main__":
    pass
