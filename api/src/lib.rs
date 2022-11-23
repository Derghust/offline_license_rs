//! # Offline license rs
//!
//! **Offline license RS** license generator used for offline software license verification.

mod adler32;
mod license_key;

use sha3::{digest::{Update, ExtendableOutput, XofReader}, Shake256};
use crate::adler32::adler32_checksum;
use crate::license_key::LicenseKey;

#[derive(PartialEq, Clone, Debug)]
pub enum LicenseKeyStatus {
  Valid,
  Invalid,
  Blacklisted
}

pub trait LicenseKeySerializer {
  fn hash(&self, seed: u64, magic: Vec<u8>) -> u8;
  fn deserialize_key(&self, key: String) -> Vec<u8>;
  fn serialize_key(&self, key: Vec<u8>) -> String;
}

pub fn generate_license_key<T: LicenseKeySerializer>(
  seed: u64,
  magic: Vec<u8>,
  magic_size: usize,
  hash_size: usize,
  serializer: &T
) -> LicenseKey {
  let mut license_key = LicenseKey::default();
  let mut key = Vec::new();

  // Hash seed to license key
  let mut hasher = Shake256::default();
  hasher.update(&*seed.to_be_bytes().to_vec());
  let mut reader = hasher.finalize_xof();
  let mut buffer = vec![0u8; hash_size];
  reader.read(&mut buffer);

  for byte in buffer.to_vec().iter() {
    key.push(*byte);
    license_key.key.push(*byte);
  }
  license_key.properties.key_size = buffer.len();

  // Generate payload
  let payload_size = magic.len() / magic_size;
  for y in 0..payload_size {
    let mut magic_number_vec: Vec<u8> = Vec::new();
    for x in 0..magic_size {
      let magic_number = magic.get(x + (y * magic_size));
      if let Some(g_magic) = magic_number {
        magic_number_vec.push(*g_magic);
      }
    }

    let payload = serializer.hash(seed, magic_number_vec);
    key.push(payload);
    license_key.payload.push(payload);
  }
  license_key.properties.payload_size = payload_size;

  // Create checksum
  let checksum = adler32_checksum(key.clone(), 0xFA, 0xAA);
  for byte in checksum.to_be_bytes().iter() {
    key.push(*byte);
    license_key.checksum.push(*byte);
  }
  license_key.properties.checksum_size = checksum.to_be_bytes().len();

  license_key.serialized_key = Some(key.clone());
  license_key
}

pub fn license_validate_key(
  key: LicenseKey
) -> LicenseKeyStatus {
  let license_key = LicenseKey::deserialize(
    key.serialized_key.unwrap_or_default(),
    key.properties.key_size,
    key.properties.payload_size,
    key.properties.checksum_size
  ).unwrap_or_else(|_| LicenseKey::default());

  // Validate checksum
  let mut key_payload = Vec::new();
  key_payload.extend(license_key.key.clone());
  key_payload.extend(license_key.payload.clone());

  let checksum = adler32_checksum(key_payload, 0xFA, 0xAA).to_be_bytes().to_vec();
  if checksum != license_key.checksum {
    return LicenseKeyStatus::Invalid;
  }

  LicenseKeyStatus::Valid
}

#[cfg(test)]
mod tests {
  use std::borrow::Borrow;
  use crate::{generate_license_key, license_validate_key, LicenseKeySerializer, LicenseKeyStatus};
  use crate::license_key::LicenseKey;


  struct TestLicenseKeySerialization {}

  impl LicenseKeySerializer for TestLicenseKeySerialization {
    fn hash(&self, seed: u64, magic: Vec<u8>) -> u8 {
      0
    }

    fn deserialize_key(&self, key: String) -> Vec<u8> {
      Vec::new()
    }

    fn serialize_key(&self, key: Vec<u8>) -> String {
      String::new()
    }
  }

  #[test]
  fn validate_license_key_validation() {
    // Validate empty license key as invalid
    assert_eq!(license_validate_key(LicenseKey::default()), LicenseKeyStatus::Invalid);

    // Validate non empty license key which are valid as valid
    let license_serializer = TestLicenseKeySerialization{};
    let license_key = generate_license_key(
      123,
      Vec::from([1,2,3]),
      3,
      8,
      license_serializer.borrow()
    );
    assert_eq!(license_validate_key(license_key), LicenseKeyStatus::Valid);
  }
}
