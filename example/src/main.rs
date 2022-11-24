use std::borrow::Borrow;
use log::{info, LevelFilter};
use simplelog::{ColorChoice, Config, TerminalMode, TermLogger};
use offline_license_rs::{generate_license_key, license_validate_key, LicenseKeySerializer, LicenseKeyStatus};

struct MyLicense {
  magic: Vec<Vec<u8>>,
  seed: u64,
  split: usize
}

impl LicenseKeySerializer for MyLicense {
  #[inline(always)]
  fn hash(&self, seed: u64, magic: &[u8]) -> u8 {
    let mut hash = seed as u8;

    hash += *magic.get(0).unwrap();
    hash ^= *magic.get(1).unwrap();
    hash -= *magic.get(2).unwrap();

    hash
  }

  #[inline(always)]
  fn deserialize_key(&self, key: String) -> Vec<u8> {
    hex::decode(key).unwrap()
  }

  #[inline(always)]
  fn serialize_key(&self, key: Vec<u8>) -> String {
    let mut output = String::new();
    let calc = key.len() / self.split;
    let remainder = key.len() % self.split;
    info!("Len={};Split={};Remainder={}", key.len(), self.split, remainder);
    for i in 0..self.split {
      let mut bytes: Vec<u8> = Vec::new();
      for x in 0..calc {
        bytes.push(*key.get(x + (i * calc)).unwrap())
      }

      output.push_str(hex::encode(bytes).to_ascii_uppercase().as_str());
      if i < self.split-1 {
        output.push('-');
      }
    }
    // remainder
    if remainder > 0 {
      let mut bytes: Vec<u8> = Vec::new();
      let remainder_calc = key.len() - remainder;
      for x in remainder_calc..key.len() {
        bytes.push(*key.get(x).unwrap())
      }

      output.push('-');
      output.push_str(hex::encode(bytes).to_ascii_uppercase().as_str());
    }

    output
  }
}

fn main() {
  TermLogger::init(
    LevelFilter::Trace,
    Config::default(),
    TerminalMode::Stdout,
    ColorChoice::Auto,
  ).expect("TermLogger should be initialize!");

  let user_email = "sample.name@sample.domain.com";

  let mut magic: Vec<Vec<u8>> = Vec::new();
  magic.push(Vec::from([1,2,3]));

  let license = MyLicense{ magic: magic.clone(), seed: 123, split: 3 };
  let license_key = generate_license_key(
    license.seed.clone(),
    license.magic.clone(),
    10,
    license.borrow(),
    (0xFF, 0xAA)
  );

  info!("License [raw={}; key={}]", user_email, license.serialize_key(license_key.clone().serialized_key.unwrap()));

  let mut byte_check: Vec<(usize, Vec<u8>)> = Vec::new();
  let byte_check_magic: &Vec<u8> = &*magic.get(0).unwrap();
  byte_check.push((0, byte_check_magic.clone()));

  let status = license_validate_key(license_key.clone(), Vec::new(), byte_check, (0xFF, 0xAA));
  match status {
    LicenseKeyStatus::Valid => {info!("Key is valid")}
    LicenseKeyStatus::Invalid => {info!("Key is invalid")}
    LicenseKeyStatus::Blacklisted => {info!("Key is banned")}
  }
}
