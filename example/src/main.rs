use std::borrow::Borrow;
use log::{info, LevelFilter};
use simplelog::{ColorChoice, Config, TerminalMode, TermLogger};
use offline_license_rs::{license_generate_key, license_validate_key, LicenseKeySerializer, LicenseKeyStatus};

struct MyLicense {
  magic: Vec<u8>,
  seed: u64,
  split: usize
}

impl LicenseKeySerializer for MyLicense {
  fn hash(&self, seed: u64, magic: Vec<u8>) -> u8 {
    let mut hash = seed as u8;

    hash += *magic.get(0).unwrap();
    hash ^= *magic.get(1).unwrap();
    hash -= *magic.get(2).unwrap();

    hash
  }


  fn deserialize_key(&self, key: String) -> Vec<u8> {
    hex::decode(key).unwrap()
  }

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

  let license = MyLicense{ magic: Vec::from([1,2,3]), seed: 123, split: 3 };
  let license_key = license_generate_key(
    license.seed,
    license.magic.to_vec(),
    license.magic.len(),
    10,
    license.borrow(),
  );

  // TODO generate license key properties size

  info!("License [raw={}; key={}]", user_email, license.serialize_key(license_key.clone()));

  let status = license_validate_key(license_key.clone(), 10, 3, 4);
  match status {
    LicenseKeyStatus::Valid => {info!("Key is valid")}
    LicenseKeyStatus::Invalid => {info!("Key is invalid")}
    LicenseKeyStatus::Blacklisted => {info!("Key is banned")}
  }
}
