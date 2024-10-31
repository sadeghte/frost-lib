use frost_ed25519::{
	self as frost, 
	round1, 
	round2, 
	keys,
	keys:: {
		SigningShare, 
		SecretShare, 
		PublicKeyPackage
	},
	Identifier, 
	SigningPackage
};
use rand::thread_rng;
use std::ptr;
use std::collections::BTreeMap;
use hex;
use serde::{
	Serialize, 
	Deserialize,
	de::DeserializeOwned
};


macro_rules! RET_NONE {
    ($expr:expr) => {
        match $expr {
            Some(val) => val,
            None => return std::ptr::null(),
        }
    };
}

macro_rules! RET_ERR {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return std::ptr::null(),
        }
    };
}

macro_rules! RET_NONE_B {
    ($expr:expr) => {
        match $expr {
            Some(val) => val,
            None => return false,
        }
    };
}

macro_rules! RET_ERR_B {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return false,
        }
    };
}

fn to_json_buff<T: Serialize>(value: &T) -> *const u8 {
    // Serialize the value to JSON
    let json = match serde_json::to_string(value) {
        Ok(json) => json,
        Err(_) => return ptr::null_mut(), // Return null on serialization error
    };

    let json_bytes = json.as_bytes();
    let json_len = json_bytes.len();

    // Create a buffer with 2 bytes for length, followed by the JSON content
    let mut output = Vec::with_capacity(2 + json_len);
    output.push((json_len >> 8) as u8);  // High byte of length
    output.push(json_len as u8);         // Low byte of length
    output.extend_from_slice(json_bytes);

    let ptr = output.as_ptr();
    std::mem::forget(output);  // Prevent Rust from freeing the memory

    ptr
}

fn from_json_buff<T: DeserializeOwned>(buffer: *const u8) -> Option<T> {
    // Check for null pointer
    if buffer.is_null() {
        return None;
    }

    unsafe {
        // Read the first two bytes to determine the JSON length
        let high_byte = *buffer;
        let low_byte = *buffer.add(1);
        let json_len = ((high_byte as usize) << 8) | (low_byte as usize);

        // Create a slice from the buffer to hold the JSON data
        let json_slice = std::slice::from_raw_parts(buffer.add(2), json_len);

        // Convert the JSON slice to a string
        let json_str = match std::str::from_utf8(json_slice) {
            Ok(s) => s,
            Err(_) => return None, // Return None if the slice is not valid UTF-8
        };

        // Deserialize the JSON string into the specified type
        match serde_json::from_str::<T>(json_str) {
            Ok(value) => Some(value),
            Err(_) => None, // Return None if deserialization fails
        }
    }
}

#[allow(dead_code)]
fn print_struct<T: Serialize>(title: &str, value: &T) {
	let json_string = serde_json::to_string(&value)
		.expect("Failed to serialize SecretShare to JSON");
	println!("{} {}",title, json_string);
}

#[derive(Serialize, Deserialize)]
pub struct KeysResult {
	shares: BTreeMap<Identifier, SecretShare>,
	pubkey_package: PublicKeyPackage,
}

#[no_mangle]
// pub extern "C" fn keys_generate_with_dealer(min_signers: u16, max_signers: u16) -> *mut c_char {
pub extern "C" fn keys_generate_with_dealer(min_signers: u16, max_signers: u16) -> *const u8 {
	let rng = thread_rng();
	let (shares, pubkey_package) = RET_ERR!(frost::keys::generate_with_dealer(
		max_signers,
		min_signers,
		frost::keys::IdentifierList::Default,
		rng,
	));
	let result = KeysResult { shares, pubkey_package };
	to_json_buff(&result)
}

#[no_mangle]
pub extern "C" fn key_package_from(secret_share: *const u8) -> *const u8 {
	let share: SecretShare = RET_NONE!(from_json_buff(secret_share));
	let key_package = RET_ERR!(frost::keys::KeyPackage::try_from(share));
	to_json_buff(&key_package)
}

#[derive(Serialize, Deserialize)]
pub struct Round1CommitResult {
	nonces: frost::round1::SigningNonces,
	commitments: frost::round1::SigningCommitments,
}

#[no_mangle]
pub extern "C" fn round1_commit(secret_buf: *const u8) -> *const u8 {
	let secret: SigningShare = RET_NONE!(from_json_buff(secret_buf));
	let mut rng = thread_rng();
	let (nonces, commitments) = frost::round1::commit(&secret, &mut rng);
	let result = Round1CommitResult {nonces, commitments};
	to_json_buff(&result)
}

#[no_mangle]
pub extern "C" fn signing_package_new(signing_commitments_buf: *const u8, msg: *const u8) -> *const u8 {
	let signing_commitments: BTreeMap<Identifier, round1::SigningCommitments>;
	signing_commitments = RET_NONE!(from_json_buff(signing_commitments_buf));
	let message_hex: String = RET_NONE!(from_json_buff(msg));
	let message: Vec<u8> = RET_ERR!(hex::decode(message_hex));
	let signing_package = frost::SigningPackage::new(signing_commitments, &message);
	to_json_buff(&signing_package)
}

#[no_mangle]
pub extern "C" fn round2_sign(signing_package_buf: *const u8, signer_nonces_buf: *const u8, key_package_buf: *const u8) -> *const u8 {
	let signing_package: SigningPackage = RET_NONE!(from_json_buff(signing_package_buf));
	let signer_nonces: round1::SigningNonces = RET_NONE!(from_json_buff(signer_nonces_buf));
	let key_package: keys::KeyPackage = RET_NONE!(from_json_buff(key_package_buf));
	let signature_share: round2::SignatureShare = RET_ERR!(frost::round2::sign(&signing_package, &signer_nonces, &key_package));
	to_json_buff(&signature_share)
}

#[no_mangle]
pub  extern "C" fn aggregate(signing_package_buf: *const u8, signature_shares_buf: *const u8, pubkey_package_buf: *const u8) -> *const u8 {
	let signing_package: frost::SigningPackage = RET_NONE!(from_json_buff(signing_package_buf));
	let signature_shares: BTreeMap<Identifier, round2::SignatureShare> = RET_NONE!(from_json_buff(signature_shares_buf));
	let pubkey_package: keys::PublicKeyPackage = RET_NONE!(from_json_buff(pubkey_package_buf));
	let group_signature: frost::Signature = RET_ERR!(frost::aggregate(&signing_package, &signature_shares, &pubkey_package));
	to_json_buff(&group_signature)
}

#[no_mangle]
pub extern "C" fn verify_group_signature(signature_buf: *const u8, msg_buf: *const u8, pubkey_package_buf: *const u8) -> bool {
	let group_signature:frost::Signature = RET_NONE_B!(from_json_buff(signature_buf));
	let message_hex: String = RET_NONE_B!(from_json_buff(msg_buf));
	let message: Vec<u8> = RET_ERR_B!(hex::decode(message_hex));
	let pubkey_package: PublicKeyPackage = RET_NONE_B!(from_json_buff(pubkey_package_buf));
	pubkey_package
		.verifying_key()
		.verify(&message, &group_signature)
		.is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn mem_free(ptr: *const u8) {
	libc::free(ptr as *mut libc::c_void);
}