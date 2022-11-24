use std::borrow::Borrow;
use log::info;
use rand::Rng;
use rand::rngs::ThreadRng;
use sha3::{digest::{Update, ExtendableOutput, XofReader}, Shake256};
use crate::adler32::adler32_checksum;
use crate::license_key::LicenseKeyStatus;
use crate::license_magic::LicenseMagic;
use crate::license_serializer::{DefaultLicenseKeySerializer, LicenseKeySerializer};
use crate::LicenseKey;

pub struct LicenseOperator {
  rng: ThreadRng,

  magic: LicenseMagic,
  key_size: usize,
  checksum_init: (u32, u32),

  serializer: Box<dyn LicenseKeySerializer>
}

impl LicenseOperator {
  #[inline(always)]
  pub fn new(magic: LicenseMagic, key_size: usize, checksum_init: (u32, u32), serializer: Box<dyn LicenseKeySerializer>) -> LicenseOperator {
    LicenseOperator {
      rng: rand::thread_rng(),
      magic,
      key_size,
      checksum_init,
      serializer
    }
  }

  #[inline(always)]
  pub fn default() -> LicenseOperator {
    LicenseOperator {
      rng: rand::thread_rng(),
      magic: LicenseMagic::default(),
      key_size: 16,
      checksum_init: (0xFFAA, 0xAAFF),
      serializer: Box::new( DefaultLicenseKeySerializer { })
    }
  }

  #[inline(always)]
  pub fn randomize_magic(&mut self, magic_size: usize, magic_count: usize) -> &Self {
    for x in 0..magic_size {
      let mut magic: Vec<u8> = Vec::new();

      info!("Randomized magic:");
      for y in 0..magic_count {
        let random_value = self.rng.gen();
        magic.push(random_value);
        info!("\t {} - {}", y, random_value);
      }

      self.magic.push(magic);
    }

    self
  }

  #[inline(always)]
  pub fn get_serialized_key(&self, license_key: &LicenseKey) -> String {
    self.serializer.serialize_key(&license_key.serialized_key)
  }

  #[inline(always)]
  pub fn generate_license_key(&self, seed: &[u8]) -> LicenseKey {
    // Validate user parameters
    // Minimal 8 seed size, USER_PAYLOAD payload size and 4 checksum size
    let license_key_required_size: usize = 8 + self.magic.payload_size() + 4;
    if self.key_size <= license_key_required_size {
      info!(
      "Cannot generate license key with less than {} key size! [key_size={}]",
      license_key_required_size, self.key_size
    );
      return LicenseKey::default();
    }
    let license_key_hash_size = self.key_size - 4 - self.magic.payload_size();

    let mut license_key = LicenseKey::default();
    let mut serialized_license_key = Vec::new();

    // Hash seed to license key
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut buffer = vec![0u8; license_key_hash_size];
    reader.read(&mut buffer);

    for byte in buffer.to_vec().iter() {
      serialized_license_key.push(*byte);
      license_key.key.push(*byte);
    }
    license_key.properties.key_size = buffer.len();

    // Generate payload
    for m in self.magic.get_magic().iter() {
      let payload = self.serializer.hash(buffer.borrow(), m);
      serialized_license_key.push(payload);
      license_key.payload.push(payload);
    }
    license_key.properties.payload_size = license_key.payload.len();

    // Create checksum
    let checksum = adler32_checksum(serialized_license_key.clone(), self.checksum_init.0, self.checksum_init.1);
    for byte in checksum.to_be_bytes().iter() {
      serialized_license_key.push(*byte);
      license_key.checksum.push(*byte);
    }
    license_key.properties.checksum_size = checksum.to_be_bytes().len();

    license_key.serialized_key = serialized_license_key.clone();
    license_key
  }

  #[inline(always)]
  pub fn validate_license_key(
    &self,
    key: &LicenseKey,
    blacklist: Vec<Vec<u8>>,
    byte_check: Vec<(usize, Vec<u8>)>
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

    let checksum = adler32_checksum(checksum_bytes, self.checksum_init.0, self.checksum_init.1).to_be_bytes().to_vec();
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
}

#[cfg(test)]
mod tests {
  use crate::license_key::LicenseKeyStatus;
  use crate::license_operator::LicenseOperator;

  #[test]
  fn validate_license_key_validation() {
    let user_email = "sample.name@sample.domain.com";

    let mut license_op = LicenseOperator::default();
    license_op.randomize_magic(1, 3);

    let license_key = license_op.generate_license_key(user_email.as_bytes());

    assert_eq!(license_op.validate_license_key(
      &license_key,
      Vec::new(),
      Vec::new()
    ), LicenseKeyStatus::Valid)
  }
}
