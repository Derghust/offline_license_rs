//! # Offline license rs
//!
//! **Offline license RS** license generator used for offline software license verification.

mod adler32;
mod license_key;

use std::borrow::Borrow;
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
  fn hash(&self, seed: u64, magic: &[u8]) -> u8;
  fn deserialize_key(&self, key: String) -> Vec<u8>;
  fn serialize_key(&self, key: Vec<u8>) -> String;
}

#[inline(always)]
pub fn generate_license_key<T: LicenseKeySerializer>(
  seed: u64,
  magic: &Vec<Vec<u8>>,
  hash_size: usize,
  serializer: &T,
  checksum_init: (u32, u32)
) -> LicenseKey {
  let mut license_key = LicenseKey::default();
  let mut serialized_license_key = Vec::new();

  // Hash seed to license key
  let mut hasher = Shake256::default();
  hasher.update(seed.to_be_bytes().to_vec().borrow());
  let mut reader = hasher.finalize_xof();
  let mut buffer = vec![0u8; hash_size];
  reader.read(&mut buffer);

  for byte in buffer.to_vec().iter() {
    serialized_license_key.push(*byte);
    license_key.key.push(*byte);
  }
  license_key.properties.key_size = buffer.len();

  // Generate payload
  for m in magic.iter() {
    let payload = serializer.hash(seed, m);
    serialized_license_key.push(payload);
    license_key.payload.push(payload);
  }
  license_key.properties.payload_size = license_key.payload.len();

  // Create checksum
  let checksum = adler32_checksum(serialized_license_key.clone(), checksum_init.0, checksum_init.1);
  for byte in checksum.to_be_bytes().iter() {
    serialized_license_key.push(*byte);
    license_key.checksum.push(*byte);
  }
  license_key.properties.checksum_size = checksum.to_be_bytes().len();

  license_key.serialized_key = serialized_license_key.clone();
  license_key
}

#[inline(always)]
pub fn license_validate_key(
  key: &LicenseKey,
  blacklist: Vec<Vec<u8>>,
  byte_check: Vec<(usize, Vec<u8>)>,
  checksum_init: (u32, u32)
) -> LicenseKeyStatus {
  let license_key = LicenseKey::deserialize(
    &key.serialized_key,
    key.properties.key_size,
    key.properties.payload_size,
    key.properties.checksum_size
  ).unwrap_or_else(|_| LicenseKey::default());

  // Validate checksum
  let mut checksum_bytes = Vec::new();
  checksum_bytes.extend(license_key.key.clone());
  checksum_bytes.extend(license_key.payload.clone());

  let checksum = adler32_checksum(checksum_bytes, checksum_init.0, checksum_init.1).to_be_bytes().to_vec();
  if checksum != license_key.checksum {
    return LicenseKeyStatus::Invalid;
  }

  // Validate seed from blacklist
  if !blacklist.is_empty() {
    // TODO search with binary tree algorithm
    for bl in blacklist.iter() {
      if license_key.key == *bl {
        return LicenseKeyStatus::Blacklisted;
      }
    }
  }

  // Validate key with byte check
  for bc in byte_check {
    if license_key.key.get(bc.0).is_none() {
      return LicenseKeyStatus::Invalid
    }
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
    fn hash(&self, seed: u64, magic: &[u8]) -> u8 {
      let mut hash = seed;

      for m in magic.iter() {
        hash += *m as u64;
      }

      hash as u8
    }

    fn deserialize_key(&self, key: String) -> Vec<u8> {
      key.into_bytes()
    }

    fn serialize_key(&self, key: Vec<u8>) -> String {
      let mut output = String::new();

      for ch in key.iter() {
        output.push(char::from(ch.to_ascii_uppercase()));
      }

      output
    }
  }

  #[test]
  fn validate_license_key_validation() {
    // License key variables
    let seed = 123;
    let checksum_init = (0xFF, 0xAA);

    // Validate empty license key as invalid
    assert_eq!(license_validate_key(&LicenseKey::default(), Vec::new(), Vec::new(), checksum_init), LicenseKeyStatus::Invalid);

    // Validate non empty license key which are valid as valid
    let license_serializer = TestLicenseKeySerialization{};

    let mut magic: Vec<Vec<u8>> = Vec::new();
    magic.push(Vec::from([1,2,3]));

    let license_key = generate_license_key(
      seed,
      &magic,
      8,
      license_serializer.borrow(),
      checksum_init
    );
    assert_eq!(license_validate_key(&license_key, Vec::new(), Vec::new(), checksum_init), LicenseKeyStatus::Valid);
  }
}
