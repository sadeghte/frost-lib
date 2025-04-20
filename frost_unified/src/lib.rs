// Re-export all C functions from the three crates
// No need to create new functions, just re-export the existing ones

// Re-export from frost-ed25519
pub use frost_ed25519::*;

// // Re-export from frost-secp256k1
// pub use frost_secp256k1::*;

// // Re-export from frost-secp256k1-tr
// pub use frost_secp256k1_tr::*;