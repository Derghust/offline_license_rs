//! # Offline license rs
//!
//! **Offline license RS** license generator used for offline software license verification.

mod adler32;
mod license_key;

use sha3::{digest::{Update, ExtendableOutput, XofReader}, Shake256};
use crate::adler32::adler32_checksum;
use crate::license_key::LicenseKey;

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
  let checksum = adler32_checksum(key.clone(), 0xFA, 0xAA);
  for byte in checksum.to_be_bytes().iter() {
    key.push(*byte)
  }

  key
}

pub fn license_validate_key(
  key: Vec<u8>,
  key_size: usize,
  payload_size: usize,
  checksum_size: usize
) -> LicenseKeyStatus {
  let license_key = LicenseKey::deserialize(
    key,
    key_size,
    payload_size,
    checksum_size
  ).unwrap_or_else(|_| LicenseKey::default());

  // Validate checksum
  let checksum = adler32_checksum(license_key.key, 0xFA, 0xAA).to_be_bytes().to_vec();
  if checksum != license_key.checksum {
    return LicenseKeyStatus::Invalid;
  }

  LicenseKeyStatus::Valid
}
