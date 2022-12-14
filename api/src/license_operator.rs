use std::borrow::Borrow;

use crate::license_blacklist::LicenseBlacklist;
use crate::license_byte_check::LicenseByteCheck;
use crate::magic::Result;

use sha3::{digest::ExtendableOutput, Shake256};
use simple_error::bail;

use crate::license_checksum::LicenseChecksum;
use crate::license_key::LicenseKeyStatus;
use crate::license_magic::LicenseMagic;
use crate::license_properties::LicenseProperties;
use crate::license_serializer::{DefaultLicenseKeySerializer, LicenseKeySerializer};
use crate::LicenseKey;

pub struct LicenseOperator {
    properties: LicenseProperties,
    magic: LicenseMagic,

    serializer: Box<dyn LicenseKeySerializer>,

    checksum: LicenseChecksum,

    blacklist: LicenseBlacklist,
    byte_check: LicenseByteCheck,
}

impl LicenseOperator {
    // ==================================================
    //                   Constructor
    // ==================================================

    #[inline(always)]
    pub fn new(
        properties: LicenseProperties,
        magic: LicenseMagic,
        serializer: Box<dyn LicenseKeySerializer>,
        checksum: LicenseChecksum,
        blacklist: LicenseBlacklist,
        byte_check: LicenseByteCheck,
    ) -> Self {
        LicenseOperator {
            properties,
            magic,
            serializer,
            checksum,
            blacklist,
            byte_check,
        }
    }

    /// Default license operator is not recommended for use in Production. We recommend to define
    /// your own license operator with **new** method.
    #[inline(always)]
    pub fn default(magic_size: usize, magic_count: usize, checksum_magic: [u8; 8]) -> Self {
        let mut license = LicenseOperator {
            properties: LicenseProperties {
                key_size: 16,
                magic_count,
                magic_size,
            },
            magic: LicenseMagic::default(),
            serializer: Box::new(DefaultLicenseKeySerializer {}),
            checksum: LicenseChecksum::default(checksum_magic),
            blacklist: LicenseBlacklist::default(),
            byte_check: LicenseByteCheck::default(),
        };

        license.magic.randomize_magic(magic_size, magic_count);

        license
    }

    // ==================================================
    //                    Operators
    // ==================================================

    #[inline(always)]
    pub fn add_seed_to_blacklist(&mut self, seed: &[u8]) {
        self.blacklist.push(seed.to_vec());
    }

    #[inline(always)]
    pub fn generate_license_key(&self, seed: &[u8]) -> Result<LicenseKey> {
        // Validate user parameters
        // Minimal 8 seed size, USER_PAYLOAD payload size and 4 checksum size
        let license_key_required_size: usize = 8 + self.magic.payload_size() + 4;
        if self.properties.key_size <= license_key_required_size {
            bail!(
                "Cannot generate license key with less than {} key size! [key_size={}]",
                license_key_required_size,
                self.properties.key_size
            );
        }

        let license_key_hash_size =
            self.properties.key_size - self.checksum.get_byte_size() - self.magic.payload_size();

        let mut license_key = LicenseKey::default();
        let mut serialized_license_key = Vec::<u8>::with_capacity(license_key_hash_size);

        // Hash seed
        Shake256::digest_xof(seed, &mut serialized_license_key);
        license_key.seed.extend(serialized_license_key.clone());

        // Generate payload
        for m in self.magic.get_magic().iter() {
            let payload = self.serializer.hash(license_key.seed.borrow(), m);
            serialized_license_key.push(payload);
            license_key.payload.push(payload);
        }
        license_key.properties.payload_size = license_key.payload.len();

        // Create checksum
        match self.checksum.generate(&serialized_license_key) {
            Ok(valid) => {
                serialized_license_key.extend_from_slice(&valid);
                license_key.checksum.extend_from_slice(&valid);
                license_key.properties.checksum_size = valid.len();
            }
            Err(report) => return Err(report),
        }

        license_key.serialized_key = serialized_license_key;

        Ok(license_key)
    }

    #[inline(always)]
    pub fn validate_license_key(&self, key: &LicenseKey) -> LicenseKeyStatus {
        let license_key = key.deserialize();
        match license_key {
            Ok(valid) => {
                // Validate checksum
                if !self.checksum.validate(
                    valid.seed.clone(),
                    valid.payload.clone(),
                    valid.checksum,
                ) {
                    return LicenseKeyStatus::Invalid;
                }

                // Validate seed from blacklist
                if self.blacklist.is_blacklisted(valid.seed.clone()) {
                    return LicenseKeyStatus::Blacklisted;
                }

                // Validate payload with byte check
                if !self.byte_check.validate(
                    valid.payload.borrow(),
                    self.serializer.borrow(),
                    valid.seed.borrow(),
                    self.magic.borrow(),
                ) {
                    return LicenseKeyStatus::Invalid;
                }
            }
            Err(_) => return LicenseKeyStatus::Invalid,
        }

        LicenseKeyStatus::Valid
    }

    // ==================================================
    //                Getters & Setters
    // ==================================================

    #[inline(always)]
    pub fn get_serialized_key(&self, license_key: &LicenseKey) -> String {
        self.serializer.serialize_key(&license_key.serialized_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::license_key::LicenseKeyStatus;
    use crate::license_operator::LicenseOperator;

    #[test]
    fn validate_license_key_validation() {
        let user_email = "sample.name@sample.domain.com";

        let license_op = LicenseOperator::default(1, 3, [1, 2, 3, 4, 5, 6, 7, 8]);

        let license_key = license_op.generate_license_key(user_email.as_bytes());

        assert!(license_key.is_ok());

        assert_eq!(
            license_op.validate_license_key(&license_key.unwrap()),
            LicenseKeyStatus::Valid
        )
    }
}
