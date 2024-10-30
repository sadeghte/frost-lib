use frost_ed25519::{self as frost, Identifier};
use frost::keys::{SecretShare, PublicKeyPackage};
use rand::thread_rng;
use std::ptr;
use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};


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

#[derive(Serialize, Deserialize)]
pub struct KeysResult {
	shares: BTreeMap<Identifier, SecretShare>,
	pubkey_package: PublicKeyPackage,
}

#[no_mangle]
// pub extern "C" fn keys_generate_with_dealer(min_signers: u16, max_signers: u16) -> *mut c_char {
pub extern "C" fn keys_generate_with_dealer(min_signers: u16, max_signers: u16) -> *const u8 {
	let rng = thread_rng();
	let shares: BTreeMap<Identifier, SecretShare>;
	let pubkey_package: PublicKeyPackage;
	(shares, pubkey_package) = match frost::keys::generate_with_dealer(
		max_signers,
		min_signers,
		frost::keys::IdentifierList::Default,
		rng,
	){
        Ok(result) => result,
        Err(_) => return std::ptr::null_mut(), // Return null on error
    };

	let result = KeysResult { shares, pubkey_package };

	to_json_buff(&result)
}

#[no_mangle]
pub unsafe extern "C" fn mem_free(ptr: *const u8, len: usize) {
	libc::free(ptr as *mut libc::c_void);
}