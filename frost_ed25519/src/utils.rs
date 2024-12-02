use frost_core::{Ciphersuite, Identifier, Error};
use serde::{
	Serialize, 
	de::DeserializeOwned
};

pub fn str_to_forgotten_buf(str: String) -> *const u8 {
	let str_bytes = str.as_bytes();
    let str_len = str_bytes.len();

    // Create a buffer with 2 bytes for length, followed by the JSON content
    let mut output = Vec::with_capacity(2 + str_len);
    output.push((str_len >> 8) as u8);  // High byte of length
    output.push(str_len as u8);         // Low byte of length
    output.extend_from_slice(str_bytes);

    let ptr = output.as_ptr();
    std::mem::forget(output);  // Prevent Rust from freeing the memory

    ptr
}

pub fn to_json_buff<T: Serialize>(value: &T) -> Result<*const u8, serde_json::Error> {
    // Serialize the value to JSON
    let json = serde_json::to_string(value)?;
    Ok(str_to_forgotten_buf(json))
}

pub fn from_json_buff<T: DeserializeOwned>(buffer: *const u8) -> Result<T, Box<dyn std::error::Error>> {
	let type_name = std::any::type_name::<T>();
    // Check for null pointer
    if buffer.is_null() {
        return Err(format!("{}: Buffer pointer is null", type_name).into());
    }

    unsafe {
        // Read the first two bytes to determine the JSON length
        let high_byte = *buffer;
        let low_byte = *buffer.add(1);
        let json_len = ((high_byte as usize) << 8) | (low_byte as usize);

        // Create a slice from the buffer to hold the JSON data
        let json_slice = std::slice::from_raw_parts(buffer.add(2), json_len);

        // Convert the JSON slice to a string
        let json_str = std::str::from_utf8(json_slice).map_err(|e| format!("{}: Invalid UTF-8 sequence: {}", type_name, e))?;

        // Deserialize the JSON string into the specified type
        let value = serde_json::from_str::<T>(json_str).map_err(|e| format!("{}: Deserialization failed: {}", type_name, e))?;

		Ok(value)
    }
}

#[allow(dead_code)]
pub fn print_struct<T: Serialize>(title: &str, value: &T) {
	let json_string = serde_json::to_string(&value)
		.expect("Failed to serialize SecretShare to JSON");
	println!("{} {}",title, json_string);
}

#[allow(dead_code)]
pub fn print_u8_pointer(ptr: *const u8) {
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

pub fn b2id<C: Ciphersuite>(id: Vec<u8>) -> Result<Identifier<C>, Error<C>> {
    // Check if the length is within valid bounds
    if id.len() < 1 || id.len() > 32 {
        return Err(Error::MalformedIdentifier); // Assuming an appropriate error variant exists
    }

    // Create a fixed-size array with 32 bytes, initialized to 0
    let mut fixed_size_data: [u8; 32] = [0x00; 32];
    
    // Copy the contents of the bytes into the fixed-size array
    fixed_size_data[..id.len()].copy_from_slice(&id);

    // Create an Identifier from the fixed-size byte array
    Identifier::deserialize(&fixed_size_data).map_err(|_| Error::MalformedIdentifier)
}