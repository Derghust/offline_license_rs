#[derive(PartialEq, Clone, Debug)]
pub struct LicenseKey {
  pub key: Vec<u8>,
  pub payload: Vec<u8>,
  pub checksum: Vec<u8>
}

impl LicenseKey {
  pub fn deserialize(
    raw_key: Vec<u8>,
    key_size: usize,
    payload_size: usize,
    checksum_size: usize
  ) -> Result<LicenseKey, &'static str> {
    if raw_key.len() < (key_size + payload_size + checksum_size) {
      return Err("Cannot deserialize license key with larger properties than raw key itself!")
    }

    Ok(LicenseKey{
      key: raw_key[0..key_size].to_vec(),
      payload: raw_key[key_size..key_size+payload_size].to_vec(),
      checksum: raw_key[key_size+payload_size..key_size+payload_size+checksum_size].to_vec()
    })
  }

  pub fn default() -> LicenseKey {
    LicenseKey {
      key: Vec::new(),
      payload: Vec::new(),
      checksum: Vec::new()
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::license_key::LicenseKey;

  #[test]
  fn license_key_validate_deserialization() {
    let key: Vec<u8> = Vec::from([0x01, 0x02, 0x03, 0x04]);
    let payload: Vec<u8> = Vec::from([0x05, 0x06, 0x07, 0x08]);
    let checksum: Vec<u8> = Vec::from([0x09, 0x0A, 0x0B, 0x0C]);

    let mut raw_key: Vec<u8> = Vec::new();
    raw_key.extend(key.clone());
    raw_key.extend(payload.clone());
    raw_key.extend(checksum.clone());

    let deserialized_license_key = LicenseKey::deserialize(
      raw_key,
      4,
      4,
      4
    ).unwrap();

    let manual_license_key = LicenseKey {
      key,
      payload,
      checksum
    };

    assert_eq!(deserialized_license_key, manual_license_key);
  }
}