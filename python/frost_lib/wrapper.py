import json

from .secp256k1_tr import ffi, lib
from .types import (
    BaseModel,
    DKGPart1Package,
    DKGPart1Result,
    DKGPart1Secret,
    DKGPart2Package,
    DKGPart2Result,
    DKGPart2Secret,
    DKGPart3Result,
    HexStr,
    KeyPair,
)


def dict_to_buffer(data):
    json_str = json.dumps(data)
    json_bytes = json_str.encode("utf-8")
    return ffi.new("char[]", json_bytes + b"\0")


def model_to_buffer(data: BaseModel):
    return dict_to_buffer(data.model_dump(mode="python"))


def nested_dict_to_buffer(data: dict[HexStr, BaseModel]):
    new_data = {}
    for key, value in data.items():
        new_data[key] = value.model_dump(mode="python")
    return dict_to_buffer(new_data)


class BaseCryptoModule:
    def __init__(self, curve_name):
        if curve_name not in self._get_curves():
            raise ValueError(
                f"Invalid curve name '{curve_name}'. valid curve names: {self._get_curves()}"
            )
        self.curve_name = curve_name
        self.ffi = ffi
        self.lib = lib

    @staticmethod
    def _get_curves() -> list[str]:
        return ["ed25519", "secp256k1", "secp256k1_tr"]

    def _get_json_and_free_mem(self, ptr) -> dict:
        if ptr == self.ffi.NULL:
            raise ValueError("Received null pointer from Rust function")

        try:
            # Read null-terminated C string
            json_buffer = self.ffi.string(ptr).decode("utf-8")
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

    def _call_cffi_function(self, func_name, *args):
        func = getattr(self.lib, func_name)
        ptr = func(*args)
        data = self._get_json_and_free_mem(ptr)
        return data

    def keypair_new(self) -> KeyPair:
        return self._call_cffi_function("keypair_new")

    def single_sign(self, secret: HexStr, msg: HexStr) -> HexStr:
        return self._call_cffi_function(
            "single_sign", dict_to_buffer(secret), dict_to_buffer(msg)
        )

    def single_verify(self, signature: HexStr, msg: HexStr, pubkey: HexStr) -> bool:
        return self._call_cffi_function(
            "single_verify",
            dict_to_buffer(signature),
            dict_to_buffer(msg),
            dict_to_buffer(pubkey),
        )

    def get_id(self, identifier):
        return self._call_cffi_function("get_id", dict_to_buffer(identifier))

    def num_to_id(self, num: int) -> HexStr:
        return self._call_cffi_function("num_to_id", num)

    def dkg_part1(
        self, identifier: HexStr, max_signers: int, min_signers: int
    ) -> DKGPart1Result:
        return DKGPart1Result.model_validate(
            self._call_cffi_function(
                "dkg_part1",
                dict_to_buffer(identifier),
                max_signers,
                min_signers,
            )
        )

    def verify_proof_of_knowledge(
        self, identifier: str, commitments, signature
    ) -> bool:
        return self._call_cffi_function(
            "verify_proof_of_knowledge",
            dict_to_buffer(identifier),
            dict_to_buffer(commitments),
            dict_to_buffer(signature),
        )

    def dkg_part2(
        self,
        round1_secret_package: DKGPart1Secret,
        round1_packages: dict[HexStr, DKGPart1Package],
    ) -> DKGPart2Result:
        return DKGPart2Result.model_validate(
            self._call_cffi_function(
                "dkg_part2",
                model_to_buffer(round1_secret_package),
                nested_dict_to_buffer(round1_packages),
            )
        )

    def dkg_verify_secret_share(self, identifier, secret_share, commitment) -> bool:
        return self._call_cffi_function(
            "dkg_verify_secret_share",
            dict_to_buffer(identifier),
            dict_to_buffer(secret_share),
            dict_to_buffer(commitment),
        )

    def dkg_part3(
        self,
        round2_secret_package: DKGPart2Secret,
        round1_packages: dict[HexStr, DKGPart1Package],
        round2_packages: dict[HexStr, DKGPart2Package],
    ) -> DKGPart3Result:
        return self._call_cffi_function(
            "dkg_part3",
            model_to_buffer(round2_secret_package),
            nested_dict_to_buffer(round1_packages),
            nested_dict_to_buffer(round2_packages),
        )

    def keys_generate_with_dealer(self, max_signers, min_signers):
        return self._call_cffi_function(
            "keys_generate_with_dealer", max_signers, min_signers
        )

    def keys_split(self, secret, max_signers, min_signers):
        return self._call_cffi_function(
            "keys_split",
            dict_to_buffer(secret),
            max_signers,
            min_signers,
        )

    def get_pubkey(self, secret: HexStr) -> HexStr:
        return self._call_cffi_function("get_pubkey", dict_to_buffer(secret))

    def key_package_from(self, key_share):
        return self._call_cffi_function("key_package_from", dict_to_buffer(key_share))

    def round1_commit(self, key_share):
        return self._call_cffi_function("round1_commit", dict_to_buffer(key_share))

    def signing_package_new(self, signing_commitments, msg):
        return self._call_cffi_function(
            "signing_package_new",
            dict_to_buffer(signing_commitments),
            dict_to_buffer(msg),
        )

    def round2_sign(self, signing_package, signer_nonces, key_package):
        return self._call_cffi_function(
            "round2_sign",
            dict_to_buffer(signing_package),
            dict_to_buffer(signer_nonces),
            dict_to_buffer(key_package),
        )

    def verify_share(
        self,
        identifier,
        verifying_share,
        signature_share,
        signing_package,
        verifying_key,
    ):
        return self._call_cffi_function(
            "verify_share",
            dict_to_buffer(identifier),
            dict_to_buffer(verifying_share),
            dict_to_buffer(signature_share),
            dict_to_buffer(signing_package),
            dict_to_buffer(verifying_key),
        )

    def aggregate(self, signing_package, signature_shares, pubkey_package):
        return self._call_cffi_function(
            "aggregate",
            dict_to_buffer(signing_package),
            dict_to_buffer(signature_shares),
            dict_to_buffer(pubkey_package),
        )

    def verify_group_signature(self, signature, msg, pubkey_package):
        return self._call_cffi_function(
            "verify_group_signature",
            dict_to_buffer(signature),
            dict_to_buffer(msg),
            dict_to_buffer(pubkey_package),
        )


class WithCustomTweak(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)

    def pubkey_tweak(self, pubkey, tweak_by):
        return self._call_cffi_function(
            "pubkey_tweak", dict_to_buffer(pubkey), dict_to_buffer(tweak_by)
        )

    def pubkey_package_tweak(self, pubkey_package, tweak_by):
        return self._call_cffi_function(
            "pubkey_package_tweak",
            dict_to_buffer(pubkey_package),
            dict_to_buffer(tweak_by),
        )

    def key_package_tweak(self, key_package, tweak_by):
        return self._call_cffi_function(
            "key_package_tweak", dict_to_buffer(key_package), dict_to_buffer(tweak_by)
        )


class Secp256k1_TR(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)

    def round2_sign_with_tweak(
        self, signing_package, signer_nonces, key_package, merkle_root=None
    ):
        return self._call_cffi_function(
            "round2_sign_with_tweak",
            dict_to_buffer(signing_package),
            dict_to_buffer(signer_nonces),
            dict_to_buffer(key_package),
            self.ffi.NULL if merkle_root is None else dict_to_buffer(merkle_root),
        )

    def aggregate_with_tweak(
        self, signing_package, signature_shares, pubkey_package, merkle_root=None
    ):
        return self._call_cffi_function(
            "aggregate_with_tweak",
            dict_to_buffer(signing_package),
            dict_to_buffer(signature_shares),
            dict_to_buffer(pubkey_package),
            self.ffi.NULL if merkle_root is None else dict_to_buffer(merkle_root),
        )

    def pubkey_package_tweak(self, pubkey_package, merkle_root=None):
        return self._call_cffi_function(
            "pubkey_package_tweak",
            dict_to_buffer(pubkey_package),
            self.ffi.NULL if merkle_root is None else dict_to_buffer(merkle_root),
        )

    def key_package_tweak(self, key_package, merkle_root=None):
        return self._call_cffi_function(
            "key_package_tweak",
            dict_to_buffer(key_package),
            self.ffi.NULL if merkle_root is None else dict_to_buffer(merkle_root),
        )


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
