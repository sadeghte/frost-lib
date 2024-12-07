from typing import TypedDict

class HeaderT(TypedDict):
	version: int
	ciphersuite: str

class Part1SecretPkgT(TypedDict):
	identifier: str 
	coefficients: list[str] 
	commitment: list[str]
	min_signers: int 
	max_signers: int

class Part1PackageT(TypedDict):
	header: HeaderT
	commitment: list[str]
	proof_of_knowledge: str
      
class Part1ResultT(TypedDict):
    secret_package: Part1SecretPkgT
    package: Part1PackageT

class Part2SecretPkgT(TypedDict):
	identifier: str 
	commitment: dict[str, str]
	secret_share: str
	min_signers: int 
	max_signers: int

class Part2PackageT(TypedDict):
	header: HeaderT
	signing_share: str
 
class Part2ResultT(TypedDict):
    secret_package: Part2SecretPkgT
    packages: dict[str, Part2PackageT]

class Part3KeyPkgT(TypedDict):
	header: HeaderT 
	identifier: str 
	signing_share: str 
	verifying_share: str 
	verifying_key: str
	min_signers: int

class Part3PubkeyPkgT(TypedDict):
	header: HeaderT 
	verifying_shares: dict[str, str]
	verifying_key: str
 
class Part3ResultT(TypedDict):
    key_package: Part3KeyPkgT
    pubkey_package: Part3PubkeyPkgT

class SignRound1Commitments(TypedDict):
	header: HeaderT
	hiding: str
	binding: str

class SignRound1Nonces(TypedDict):
	header: HeaderT
	hiding: str
	binding: str
	commitments: SignRound1Commitments

class SignRound1Result(TypedDict):
	nonces: SignRound1Nonces
	commitments: SignRound1Commitments