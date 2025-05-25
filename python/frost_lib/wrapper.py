import json

from .secp256k1_tr import ffi, lib
from .types import (
    BaseModel,
    Commitment,
    DKGPart1Package,
    DKGPart1Result,
    DKGPart1Secret,
    DKGPart2Package,
    DKGPart2Result,
    DKGPart2Secret,
    DKGPart3Result,
    HexStr,
    KeyPair,
    Nonce,
    PrivateKeyPackage,
    PublicKeyPackage,
    Round1Commitment,
    SharePackage,
    SigningPackage,
)


def to_buffer(data):
    json_str = json.dumps(data)
    json_bytes = json_str.encode("utf-8")
    return ffi.new("char[]", json_bytes + b"\0")


def model_to_buffer(data: BaseModel):
    return to_buffer(data.model_dump(mode="python"))


def nested_dict_to_buffer(data: dict[HexStr, BaseModel]):
    new_data = {}
    for key, value in data.items():
        new_data[key] = value.model_dump(mode="python")
    return to_buffer(new_data)


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
            "single_sign", to_buffer(secret), to_buffer(msg)
        )

    def single_verify(self, signature: HexStr, msg: HexStr, pubkey: HexStr) -> bool:
        return self._call_cffi_function(
            "single_verify",
            to_buffer(signature),
            to_buffer(msg),
            to_buffer(pubkey),
        )

    def get_id(self, identifier):
        return self._call_cffi_function("get_id", to_buffer(identifier))

    def num_to_id(self, num: int) -> HexStr:
        return self._call_cffi_function("num_to_id", num)

    def dkg_part1(
        self, identifier: HexStr, max_signers: int, min_signers: int
    ) -> DKGPart1Result:
        return DKGPart1Result.model_validate(
            self._call_cffi_function(
                "dkg_part1",
                to_buffer(identifier),
                max_signers,
                min_signers,
            )
        )

    def verify_proof_of_knowledge(
        self, identifier: str, commitments, signature
    ) -> bool:
        return self._call_cffi_function(
            "verify_proof_of_knowledge",
            to_buffer(identifier),
            to_buffer(commitments),
            to_buffer(signature),
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
            to_buffer(identifier),
            to_buffer(secret_share),
            to_buffer(commitment),
        )

    def dkg_part3(
        self,
        round2_secret_package: DKGPart2Secret,
        round1_packages: dict[HexStr, DKGPart1Package],
        round2_packages: dict[HexStr, DKGPart2Package],
    ) -> DKGPart3Result:
        return DKGPart3Result.model_validate(
            self._call_cffi_function(
                "dkg_part3",
                model_to_buffer(round2_secret_package),
                nested_dict_to_buffer(round1_packages),
                nested_dict_to_buffer(round2_packages),
            )
        )

    def keys_generate_with_dealer(self, max_signers, min_signers):
        return self._call_cffi_function(
            "keys_generate_with_dealer", max_signers, min_signers
        )

    def keys_split(self, secret, max_signers, min_signers):
        return self._call_cffi_function(
            "keys_split",
            to_buffer(secret),
            max_signers,
            min_signers,
        )

    def get_pubkey(self, secret: HexStr) -> HexStr:
        return self._call_cffi_function("get_pubkey", to_buffer(secret))

    def key_package_from(self, key_share: HexStr) -> PrivateKeyPackage:
        return PrivateKeyPackage.model_validate(
            self._call_cffi_function("key_package_from", to_buffer(key_share))
        )

    def round1_commit(self, key_share: HexStr) -> Round1Commitment:
        return Round1Commitment.model_validate(
            self._call_cffi_function("round1_commit", to_buffer(key_share))
        )

    def signing_package_new(
        self, signing_commitments: dict[HexStr, Commitment], msg: HexStr
    ) -> SigningPackage:
        return SigningPackage.model_validate(
            self._call_cffi_function(
                "signing_package_new",
                nested_dict_to_buffer(signing_commitments),
                to_buffer(msg),
            )
        )

    def round2_sign(
        self,
        signing_package: SigningPackage,
        signer_nonces: Nonce,
        key_package: PrivateKeyPackage,
    ) -> SharePackage:
        return SharePackage.model_validate(
            self._call_cffi_function(
                "round2_sign",
                model_to_buffer(signing_package),
                model_to_buffer(signer_nonces),
                model_to_buffer(key_package),
            )
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
            to_buffer(identifier),
            to_buffer(verifying_share),
            to_buffer(signature_share),
            to_buffer(signing_package),
            to_buffer(verifying_key),
        )

    def aggregate(
        self,
        signing_package: SigningPackage,
        signature_shares: dict[HexStr, SharePackage],
        pubkey_package: PublicKeyPackage,
    ) -> HexStr:
        return self._call_cffi_function(
            "aggregate",
            model_to_buffer(signing_package),
            nested_dict_to_buffer(signature_shares),
            model_to_buffer(pubkey_package),
        )

    def verify_group_signature(
        self, signature: HexStr, msg: HexStr, pubkey_package: PublicKeyPackage
    ) -> bool:
        return self._call_cffi_function(
            "verify_group_signature",
            to_buffer(signature),
            to_buffer(msg),
            model_to_buffer(pubkey_package),
        )


class WithCustomTweak(BaseCryptoModule):
    def __init__(self, curve_name):
        super().__init__(curve_name)

    def pubkey_package_tweak(
        self, pubkey_package: PublicKeyPackage, merkle_root: HexStr | None = None
    ) -> PublicKeyPackage:
        return PublicKeyPackage.model_validate(
            self._call_cffi_function(
                "pubkey_package_tweak",
                model_to_buffer(pubkey_package),
                self.ffi.NULL if merkle_root is None else to_buffer(merkle_root),
            )
        )

    def key_package_tweak(
        self, key_package: PrivateKeyPackage, merkle_root: HexStr | None = None
    ) -> PrivateKeyPackage:
        return PrivateKeyPackage.model_validate(
            self._call_cffi_function(
                "key_package_tweak",
                to_buffer(key_package),
                self.ffi.NULL if merkle_root is None else to_buffer(merkle_root),
            )
        )

    def round2_sign_with_tweak(
        self,
        signing_package: SigningPackage,
        signer_nonces: Nonce,
        key_package: PrivateKeyPackage,
        merkle_root: HexStr | None = None,
    ) -> SharePackage:
        return SharePackage.model_validate(
            self._call_cffi_function(
                "round2_sign_with_tweak",
                model_to_buffer(signing_package),
                model_to_buffer(signer_nonces),
                model_to_buffer(key_package),
                self.ffi.NULL if merkle_root is None else to_buffer(merkle_root),
            )
        )

    def aggregate_with_tweak(
        self,
        signing_package: SigningPackage,
        signature_shares: dict[HexStr, SharePackage],
        pubkey_package: PublicKeyPackage,
        merkle_root: HexStr | None = None,
    ) -> HexStr:
        return self._call_cffi_function(
            "aggregate_with_tweak",
            model_to_buffer(signing_package),
            nested_dict_to_buffer(signature_shares),
            model_to_buffer(pubkey_package),
            self.ffi.NULL if merkle_root is None else to_buffer(merkle_root),
        )


# ed25519 = WithCustomTweak("ed25519")
# secp256k1 = WithCustomTweak("secp256k1")
secp256k1_tr = WithCustomTweak("secp256k1_tr")

__all__ = [
    # "ed25519",
    # "secp256k1",
    "secp256k1_tr"
]

if __name__ == "__main__":
    pass
