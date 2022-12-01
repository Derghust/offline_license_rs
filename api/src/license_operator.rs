use color_eyre::eyre::eyre;
use color_eyre::Report;
use rand::distributions::uniform::SampleBorrow;
use std::borrow::Borrow;

use crate::license_blacklist::LicenseBlacklist;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

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
    byte_check: Vec<(usize, LicenseMagic)>,
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
        byte_check: Vec<(usize, LicenseMagic)>,
    ) -> Self {
        let mut license = LicenseOperator {
            properties: properties.clone(),
            magic,
            serializer,
            checksum,
            blacklist,
            byte_check,
        };

        license.magic.randomize_magic(
            properties.magic_size.clone(),
            properties.magic_count.clone(),
        );

        license
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
            byte_check: Vec::new(),
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
    pub fn generate_license_key(&self, seed: &[u8]) -> Result<LicenseKey, Report> {
        // Validate user parameters
        // Minimal 8 seed size, USER_PAYLOAD payload size and 4 checksum size
        let license_key_required_size: usize = 8 + self.magic.payload_size() + 4;
        if self.properties.key_size <= license_key_required_size {
            return Err(eyre!(
                "Cannot generate license key with less than {} key size! [key_size={}]",
                license_key_required_size,
                self.properties.key_size
            ));
        }

        let license_key_hash_size =
            self.properties.key_size - self.checksum.get_byte_size() - self.magic.payload_size();

        let mut license_key = LicenseKey::default();
        let mut serialized_license_key = Vec::new();

        // Hash seed to license key
        // TODO FIX ME https://github.com/Derghust/offline_license_rs/pull/1#discussion_r1033030414
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
        match self.checksum.execute(&serialized_license_key) {
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
                let mut checksum_bytes = Vec::new();
                checksum_bytes.extend(valid.key.clone());
                checksum_bytes.extend(valid.payload.clone());

                match self.checksum.execute(&checksum_bytes) {
                    Ok(x) => {
                        // Validate checksum
                        if x != valid.checksum {
                            return LicenseKeyStatus::Invalid;
                        }

                        // Validate seed from blacklist
                        if self.blacklist.isBlacklisted(&valid.key) {
                            return LicenseKeyStatus::Blacklisted;
                        }

                        // Validate key with byte check
                        for bc in &self.byte_check {
                            if valid.key.get(bc.0).is_none() {
                                return LicenseKeyStatus::Invalid;
                            }
                        }
                    }
                    Err(_) => return LicenseKeyStatus::Invalid,
                };
            }
            Err(report) => return LicenseKeyStatus::Invalid,
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

        let mut license_op = LicenseOperator::default(1, 3, [1, 2, 3, 4, 5, 6, 7, 8]);

        let license_key = license_op.generate_license_key(user_email.as_bytes());

        assert!(license_key.is_ok());

        assert_eq!(
            license_op.validate_license_key(&license_key.unwrap()),
            LicenseKeyStatus::Valid
        )
    }
}
