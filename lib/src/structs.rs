use serde::{Serialize, Deserialize, Serializer, Deserializer};
use frost_ed25519::{
	Identifier,
	keys::{
		VerifiableSecretSharingCommitment,
		dkg::{
			round1::SecretPackage as R1SecretPackage,
			round2::SecretPackage as R2SecretPackage
		}
	},
	Ed25519Sha512 as E
};
use hex;


type Scalar = frost_core::Scalar<E>;

#[derive(Clone, PartialEq, Eq)]
pub struct SerializableScalar(Scalar);

impl Serialize for SerializableScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes();
        let hex_string = hex::encode(bytes);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for SerializableScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // let hex_string: String = String::deserialize(deserializer)?;
        // serde_json::from_str(&hex_string).map_err(serde::de::Error::custom)

		let hex_string: String = String::deserialize(deserializer)?; // Deserialize as String
        
        // Convert the hex string back to bytes
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
		let mut array = [0u8; 32];
		array.copy_from_slice(&bytes);
        
        // Construct the Scalar from the bytes
        let scalar = Scalar::from_bytes_mod_order(array);
        Ok(SerializableScalar(scalar))
		
		// let scalar: Scalar = Scalar::deserialize(bytes)?;
        // Ok(SerializableScalar(scalar))
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializableR1SecretPackage {
    pub identifier: Identifier,
    pub coefficients: Vec<SerializableScalar>,
    pub commitment: VerifiableSecretSharingCommitment,
    pub min_signers: u16,
    pub max_signers: u16,
}

impl From<R1SecretPackage> for SerializableR1SecretPackage {
    fn from(secret_package: R1SecretPackage) -> Self {
        SerializableR1SecretPackage {
            // identifier: id,
            identifier: secret_package.identifier().clone(),
            coefficients: secret_package.coefficients().iter().map(|s| SerializableScalar(*s)).collect(),
            commitment: secret_package.commitment().clone(),
            min_signers: secret_package.min_signers().clone(),
            max_signers: secret_package.max_signers().clone(),
        }
    }
}

impl From<SerializableR1SecretPackage> for R1SecretPackage {
    fn from(serializable: SerializableR1SecretPackage) -> R1SecretPackage {
        R1SecretPackage {
            identifier: serializable.identifier,
            coefficients: serializable.coefficients.into_iter().map(|s| s.0).collect(),
            commitment: serializable.commitment,
            min_signers: serializable.min_signers,
            max_signers: serializable.max_signers,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializableR2SecretPackage {
    pub identifier: Identifier,
    pub commitment: VerifiableSecretSharingCommitment,
	pub secret_share: SerializableScalar,
    pub min_signers: u16,
    pub max_signers: u16,
}

impl From<R2SecretPackage> for SerializableR2SecretPackage {
    fn from(secret_package: R2SecretPackage) -> Self {
        SerializableR2SecretPackage {
            // identifier: id,
            identifier: secret_package.identifier().clone(),
            // coefficients: secret_package.coefficients().iter().map(|s| SerializableScalar(*s)).collect(),
            commitment: secret_package.commitment().clone(),
			secret_share: SerializableScalar(secret_package.secret_share().clone()),
            min_signers: secret_package.min_signers().clone(),
            max_signers: secret_package.max_signers().clone(),
        }
    }
}

impl From<SerializableR2SecretPackage> for R2SecretPackage {
    fn from(serializable: SerializableR2SecretPackage) -> R2SecretPackage {
        R2SecretPackage {
            identifier: serializable.identifier,
            // coefficients: serializable.coefficients.into_iter().map(|s| s.0).collect(),
            commitment: serializable.commitment,
			secret_share: serializable.secret_share.0,
            min_signers: serializable.min_signers,
            max_signers: serializable.max_signers,
        }
    }
}
