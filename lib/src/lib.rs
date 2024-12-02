use frost_ed25519::{
	self as frost, keys:: {
		self, dkg, PublicKeyPackage, SecretShare, SigningShare
	}, round1, round2, Identifier, SigningKey, SigningPackage
};
use rand::thread_rng;
use structs::{SerializableR1SecretPackage, SerializableR2SecretPackage, SerializableScalar};
use std::collections::BTreeMap;
use hex;
use serde::{
	Serialize, 
	Deserialize,
};
use utils::{str_to_forgotten_buf, from_json_buff, to_json_buff, b2id};
mod structs;
mod utils;

macro_rules! RET_ERR {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                let error_message = format!(r#"{{"error": "{}"}}"#, err);
				return str_to_forgotten_buf(error_message);
            }
        }
    };
}

#[no_mangle]
pub extern "C" fn get_id(id: *const u8) -> *const u8 {
	let identifier: Identifier = RET_ERR!(from_json_buff(id));
	RET_ERR!(to_json_buff(&identifier))
}

#[derive(Serialize, Deserialize)]
pub struct DkgPart1Result{
	secret_package: structs::SerializableR1SecretPackage,
	package: keys::dkg::round1::Package
}

#[no_mangle]
pub extern "C" fn dkg_part1(id: *const u8, max_signers: u16, min_signers: u16) -> *const u8 {
	let id_hex: String = RET_ERR!(from_json_buff(id));
	let id_bytes: Vec<u8> = RET_ERR!(hex::decode(id_hex));
	let identifier: Identifier = RET_ERR!(b2id(id_bytes));
	
	let mut rng = thread_rng();
    let (secret_package, package) = RET_ERR!(frost::keys::dkg::part1(
        identifier,
        max_signers,
        min_signers,
        &mut rng,
    ));

	let result = DkgPart1Result { secret_package: secret_package.into(), package };
	RET_ERR!(to_json_buff(&result))
}

#[derive(Serialize, Deserialize)]
pub struct DkgPart2Result{
	secret_package: SerializableR2SecretPackage,
	packages: BTreeMap<Identifier, keys::dkg::round2::Package>,
}

#[allow(dead_code)]
fn print_u8_pointer(ptr: *const u8) {
    // Check for null pointer
    if ptr.is_null() {
        println!("Pointer is null");
        return;
    }

    unsafe {
        // Read the first two bytes to determine the buffer length
        let high_byte = *ptr as usize;
        let low_byte = *ptr.add(1) as usize;
        let length = (high_byte << 8) | low_byte;

        // Create a slice from the buffer starting after the first two bytes
        let data_slice = std::slice::from_raw_parts(ptr.add(2), length);

        // Convert the slice to a string and print it
        match std::str::from_utf8(data_slice) {
            Ok(string) => println!("[{}]:{}", length, string),
            Err(e) => println!("Failed to convert to string: {}", e),
        }
    }
}

#[no_mangle]
pub extern "C" fn dkg_part2(r1_skrt_pkg_buff: *const u8, r1_pkg_buff: *const u8) -> *const u8 {
	let round1_secret_package: SerializableR1SecretPackage = RET_ERR!(from_json_buff(r1_skrt_pkg_buff));
	let round1_packages: BTreeMap<Identifier, dkg::round1::Package> = RET_ERR!(from_json_buff(r1_pkg_buff));
	let (secret_package, packages) = RET_ERR!(frost::keys::dkg::part2(
		round1_secret_package.into(), 
		&round1_packages
	));

	let result = DkgPart2Result {
		secret_package: secret_package.into(), 
		packages
	};

	RET_ERR!(to_json_buff(&result))
}

#[derive(Serialize, Deserialize)]
pub struct DkgPart3Result{
	key_package: keys::KeyPackage,
	pubkey_package: keys::PublicKeyPackage,
}

#[no_mangle]
pub extern "C" fn dkg_part3(r2_sec_pkg_buf: *const u8, r1_pkgs_buf: *const u8, r2_pkgs_buf: *const u8) -> *const u8 {
	let round2_secret_package: SerializableR2SecretPackage = RET_ERR!(from_json_buff(r2_sec_pkg_buf));
	let round1_packages: BTreeMap<Identifier, dkg::round1::Package> = RET_ERR!(from_json_buff(r1_pkgs_buf));
	let round2_packages: BTreeMap<Identifier, dkg::round2::Package> = RET_ERR!(from_json_buff(r2_pkgs_buf));
	let (key_package, pubkey_package) = RET_ERR!(keys::dkg::part3(
        &round2_secret_package.into(),
        &round1_packages,
        &round2_packages,
    ));

	let result = DkgPart3Result {
		key_package, 
		pubkey_package
	};

	RET_ERR!(to_json_buff(&result))
}

#[derive(Serialize, Deserialize)]
pub struct DealerKeysResult {
	shares: BTreeMap<Identifier, SecretShare>,
	pubkey_package: PublicKeyPackage,
}

#[no_mangle]
pub extern "C" fn keys_generate_with_dealer(max_signers: u16, min_signers: u16) -> *const u8 {
	let rng = thread_rng();
	let (shares, pubkey_package) = RET_ERR!(frost::keys::generate_with_dealer(
		max_signers,
		min_signers,
		frost::keys::IdentifierList::Default,
		rng,
	));
	let result = DealerKeysResult { shares, pubkey_package };
	RET_ERR!(to_json_buff(&result))
}

#[no_mangle]
pub extern "C" fn keys_split(secret_buff: *const u8, max_signers: u16, min_signers: u16) -> *const u8 {
	let scalar: SerializableScalar = RET_ERR!(from_json_buff(secret_buff));
	let secret: SigningKey = RET_ERR!(SigningKey::from_scalar(scalar.0));
	let mut rng = thread_rng();
	let (shares, pubkey_package) = RET_ERR!(frost::keys::split(
		&secret,
		max_signers,
		min_signers,
		frost::keys::IdentifierList::Default,
		&mut rng,
	));
	let result = DealerKeysResult { shares, pubkey_package };
	RET_ERR!(to_json_buff(&result))
}

#[no_mangle]
pub extern "C" fn key_package_from(secret_share: *const u8) -> *const u8 {
	let share: SecretShare = RET_ERR!(from_json_buff(secret_share));
	let key_package = RET_ERR!(frost::keys::KeyPackage::try_from(share));
	RET_ERR!(to_json_buff(&key_package))
}

#[derive(Serialize, Deserialize)]
pub struct Round1CommitResult {
	nonces: frost::round1::SigningNonces,
	commitments: frost::round1::SigningCommitments,
}

#[no_mangle]
pub extern "C" fn round1_commit(secret_buf: *const u8) -> *const u8 {
	let secret: SigningShare = RET_ERR!(from_json_buff(secret_buf));
	let mut rng = thread_rng();
	let (nonces, commitments) = frost::round1::commit(&secret, &mut rng);
	let result = Round1CommitResult {nonces, commitments};
	RET_ERR!(to_json_buff(&result))
}

#[no_mangle]
pub extern "C" fn signing_package_new(signing_commitments_buf: *const u8, msg: *const u8) -> *const u8 {
	let signing_commitments: BTreeMap<Identifier, round1::SigningCommitments>;
	signing_commitments = RET_ERR!(from_json_buff(signing_commitments_buf));
	let message_hex: String = RET_ERR!(from_json_buff(msg));
	let message: Vec<u8> = RET_ERR!(hex::decode(message_hex));
	let signing_package = frost::SigningPackage::new(signing_commitments, &message);
	RET_ERR!(to_json_buff(&signing_package))
}

#[no_mangle]
pub extern "C" fn round2_sign(signing_package_buf: *const u8, signer_nonces_buf: *const u8, key_package_buf: *const u8) -> *const u8 {
	let signing_package: SigningPackage = RET_ERR!(from_json_buff(signing_package_buf));
	let signer_nonces: round1::SigningNonces = RET_ERR!(from_json_buff(signer_nonces_buf));
	let key_package: keys::KeyPackage = RET_ERR!(from_json_buff(key_package_buf));
	let signature_share: round2::SignatureShare = RET_ERR!(frost::round2::sign(&signing_package, &signer_nonces, &key_package));
	RET_ERR!(to_json_buff(&signature_share))
}

#[no_mangle]
pub  extern "C" fn aggregate(signing_package_buf: *const u8, signature_shares_buf: *const u8, pubkey_package_buf: *const u8) -> *const u8 {
	let signing_package: frost::SigningPackage = RET_ERR!(from_json_buff(signing_package_buf));
	let signature_shares: BTreeMap<Identifier, round2::SignatureShare> = RET_ERR!(from_json_buff(signature_shares_buf));
	let pubkey_package: keys::PublicKeyPackage = RET_ERR!(from_json_buff(pubkey_package_buf));
	let group_signature: frost::Signature = RET_ERR!(frost::aggregate(&signing_package, &signature_shares, &pubkey_package));
	RET_ERR!(to_json_buff(&group_signature))
}

#[no_mangle]
pub extern "C" fn verify_group_signature(signature_buf: *const u8, msg_buf: *const u8, pubkey_package_buf: *const u8) -> *const u8 {
	let group_signature:frost::Signature = RET_ERR!(from_json_buff(signature_buf));
	let message_hex: String = RET_ERR!(from_json_buff(msg_buf));
	let message: Vec<u8> = RET_ERR!(hex::decode(message_hex));
	let pubkey_package: PublicKeyPackage = RET_ERR!(from_json_buff(pubkey_package_buf));
	let verified: bool = pubkey_package
		.verifying_key()
		.verify(&message, &group_signature)
		.is_ok();
	RET_ERR!(to_json_buff(&verified))
}

#[no_mangle]
pub unsafe extern "C" fn mem_free(ptr: *const u8) {
	libc::free(ptr as *mut libc::c_void);
}