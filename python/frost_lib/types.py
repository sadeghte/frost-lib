from typing import Literal, TypedDict

from pydantic import BaseModel

CurveType = Literal["ed25519", "secp256k1", "secp256k1_tr"]

type HexStr = str


class Header(BaseModel):
    version: int
    ciphersuite: str


class PrivateKeyPackage(BaseModel):
    header: Header
    identifier: str
    signing_share: str
    verifying_share: str
    verifying_key: str
    min_signers: int


class PublicKeyPackage(BaseModel):
    header: Header
    verifying_shares: dict[str, str]
    verifying_key: str


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


{
    "secret_package": {
        "identifier": "0000000000000000000000000000000000000000000000000000000000000003",
        "commitment": [
            "032f825305fca088a05b00a52254c1bd4891646dd06d6d2c96973678e7653f74d4",
            "035ba2ca570faa2a922770f99e484eee08482ca394acb20d144e35379b7fb9694f",
        ],
        "secret_share": "2cbd1ee0ffbda560af7cfa8d42c681eb0adeeadd3a1f547bc472c255ba278071",
        "min_signers": 2,
        "max_signers": 3,
    },
    "packages": {
        "0000000000000000000000000000000000000000000000000000000000000001": {
            "header": {"version": 0, "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"},
            "signing_share": "7cbb66bfc170e28267ce8910d608da9255b0a34a0cf7673d910353d9811d6fbb",
        },
        "0000000000000000000000000000000000000000000000000000000000000002": {
            "header": {"version": 0, "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"},
            "signing_share": "54bc42d0609743f18ba5c1cf0c67ae3eb047c713a38b5ddcaabb0b179da27816",
        },
    },
}


class DKGPart2Secret(BaseModel):
    identifier: HexStr
    commitment: list[HexStr]
    secret_share: HexStr
    min_signers: int
    max_signers: int


class DKGPart2Package(BaseModel):
    header: Header
    signing_share: str


class DKGPart2Result(BaseModel):
    secret_package: DKGPart2Secret
    packages: dict[str, DKGPart2Package]


class SecretShare(BaseModel):
    # Serialization header
    header: Header
    # The participant identifier of this SecretShare (Owner Identifier)
    identifier: str
    # Secret Key.
    signing_share: str
    # The commitments distributed among signers.
    commitment: list[str]


class Part3KeyPkg(BaseModel):
    header: Header
    identifier: str
    signing_share: str
    verifying_share: str
    verifying_key: str
    min_signers: int


class Part3PubkeyPkg(BaseModel):
    header: Header
    verifying_shares: dict[str, str]
    verifying_key: str


class DKGPart3Result(BaseModel):
    key_package: Part3KeyPkg
    pubkey_package: Part3PubkeyPkg


class SignRound1Commitments(TypedDict):
    header: Header
    hiding: str
    binding: str


class SignRound1Nonces(TypedDict):
    header: Header
    hiding: str
    binding: str
    commitments: SignRound1Commitments


class SignRound1Result(TypedDict):
    nonces: SignRound1Nonces
    commitments: SignRound1Commitments


class KeyPair(TypedDict):
    signing_key: HexStr
    verifying_key: str
