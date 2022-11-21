//! # Offline license rs
//!
//! **Offline license RS** license generator used for offline software license verification.

mod adler32;

use sha3::{digest::{Update, ExtendableOutput, XofReader}, Shake256};
use crate::adler32::adler32_checksum;

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

pub fn license_generate_key<T: LicenseKeySerializer>(
  seed: u64,
  magic: Vec<u8>,
  magic_size: usize,
  hash_size: usize,
  serializer: &T
) -> Vec<u8> {
  let mut key = Vec::new();

  // Hash seed to license key
  let mut hasher = Shake256::default();
  hasher.update(&*seed.to_be_bytes().to_vec());
  let mut reader = hasher.finalize_xof();
  let mut buffer = vec![0u8; hash_size];
  reader.read(&mut buffer);

  for byte in buffer.to_vec().iter() {
    key.push(*byte)
  }

  // Generate payload
  for y in 0..(magic.len() / magic_size) {
    let mut magic_number_vec: Vec<u8> = Vec::new();
    for x in 0..magic_size {
      let magic_number = magic.get(x + (y * magic_size));
      if let Some(g_magic) = magic_number {
        magic_number_vec.push(*g_magic);
      }
    }

    key.push(serializer.hash(seed, magic_number_vec));
  }

  // Create checksum
  let checksum = adler32_checksum(key.clone());
  for byte in checksum.to_be_bytes().iter() {
    key.push(*byte)
  }

  key
}

pub fn license_validate_key(key: Vec<u8>) -> LicenseKeyStatus {
  let raw_key = key[0..key.len() - 4].to_vec();

  // Validate checksum
  let checksum = adler32_checksum(raw_key).to_be_bytes().to_vec();
  let key_checksum = key[key.len() - 4..].to_vec();
  if checksum != key_checksum {
    return LicenseKeyStatus::Invalid;
  }

  LicenseKeyStatus::Valid
}
