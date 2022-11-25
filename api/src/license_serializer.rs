#![allow(arithmetic_overflow)]

use std::num::Wrapping;

pub trait LicenseKeySerializer {
    fn hash(&self, seed: &[u8], magic: &[u8]) -> u8;
    fn deserialize_key(&self, key: String) -> Vec<u8>;
    fn serialize_key(&self, key: &[u8]) -> String;
}

pub struct DefaultLicenseKeySerializer {}

impl LicenseKeySerializer for DefaultLicenseKeySerializer {
    #[inline(always)]
    fn hash(&self, seed: &[u8], magic: &[u8]) -> u8 {
        let mut hash: Wrapping<u8> = Wrapping(0);

        for &x in magic.iter() {
            if x == 3 || x == 7 {
                hash *= x;
            } else if x % 2 == 0 {
                for x in seed.iter() {
                    hash += x;
                }
            } else {
                hash ^= x;
            }
        }

        hash.0
    }

    #[inline(always)]
    fn deserialize_key(&self, key: String) -> Vec<u8> {
        key.into_bytes()
    }

    #[inline(always)]
    fn serialize_key(&self, key: &[u8]) -> String {
        let mut output = String::new();

        output.push_str(&hex::encode(key).to_ascii_uppercase());

        output
    }
}
