from typing import Literal, TypedDict

from pydantic import BaseModel

CurveType = Literal["ed25519", "secp256k1", "secp256k1_tr"]

type HexStr = str


class Header(BaseModel):
    model_config = {"frozen": True}
    version: int
    ciphersuite: str


class PrivateKeyPackage(BaseModel):
    header: Header
    identifier: HexStr
    signing_share: HexStr
    verifying_share: HexStr
    verifying_key: HexStr
    min_signers: int


class PublicKeyPackage(BaseModel):
    header: Header
    verifying_shares: dict[HexStr, HexStr]
    verifying_key: HexStr


class DKGPart1Package(BaseModel):
    header: Header
    commitment: list[HexStr]
    proof_of_knowledge: HexStr


class DKGPart1Secret(BaseModel):
    identifier: HexStr
    coefficients: list[HexStr]
    commitment: list[HexStr]
    min_signers: int
    max_signers: int


class DKGPart1Result(BaseModel):
    secret_package: DKGPart1Secret
    package: DKGPart1Package


class DKGPart2Secret(BaseModel):
    identifier: HexStr
    commitment: list[HexStr]
    secret_share: HexStr
    min_signers: int
    max_signers: int


class DKGPart2Package(BaseModel):
    header: Header
    signing_share: HexStr


class DKGPart2Result(BaseModel):
    secret_package: DKGPart2Secret
    packages: dict[HexStr, DKGPart2Package]


class SecretShare(BaseModel):
    # Serialization header
    header: Header
    # The participant identifier of this SecretShare (Owner Identifier)
    identifier: HexStr
    # Secret Key.
    signing_share: HexStr
    # The commitments distributed among signers.
    commitment: list[HexStr]


class DKGPart3Result(BaseModel):
    key_package: PrivateKeyPackage
    pubkey_package: PublicKeyPackage


class SignRound1Commitments(TypedDict):
    header: Header
    hiding: HexStr
    binding: HexStr


class SignRound1Nonces(TypedDict):
    header: Header
    hiding: HexStr
    binding: HexStr
    commitments: SignRound1Commitments


class SignRound1Result(TypedDict):
    nonces: SignRound1Nonces
    commitments: SignRound1Commitments


class KeyPair(TypedDict):
    signing_key: HexStr
    verifying_key: HexStr


class Commitment(BaseModel):
    header: Header
    hiding: HexStr
    binding: HexStr


class Nonce(BaseModel):
    header: Header
    hiding: HexStr
    binding: HexStr
    commitments: Commitment


class Round1Commitment(BaseModel):
    nonces: Nonce
    commitments: Commitment


class SigningPackage(BaseModel):
    header: Header
    signing_commitments: dict[HexStr, Commitment]
    message: HexStr


class SharePackage(BaseModel):
    header: Header
    share: HexStr
