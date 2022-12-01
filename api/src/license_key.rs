use color_eyre::eyre::eyre;
use color_eyre::Report;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum LicenseKeyStatus {
    Valid,
    Invalid,
    Blacklisted,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LicenseKeyProperties {
    pub key_size: usize,
    pub payload_size: usize,
    pub checksum_size: usize,
}

impl LicenseKeyProperties {
    pub fn default() -> Self {
        LicenseKeyProperties {
            key_size: 0,
            payload_size: 0,
            checksum_size: 0,
        }
    }

    pub fn size(&self) -> usize {
        self.key_size + self.payload_size + self.checksum_size
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LicenseKey {
    pub properties: LicenseKeyProperties,
    pub key: Vec<u8>,
    pub payload: Vec<u8>,
    pub checksum: Vec<u8>,
    pub serialized_key: Vec<u8>,
}

impl LicenseKey {
    // ==================================================
    //                   Constructor
    // ==================================================

    #[inline(always)]
    pub fn new(
        properties: LicenseKeyProperties,
        key: Vec<u8>,
        payload: Vec<u8>,
        checksum: Vec<u8>,
        serialized_key: Vec<u8>,
    ) -> Self {
        LicenseKey {
            properties,
            key,
            payload,
            checksum,
            serialized_key,
        }
    }

    #[inline(always)]
    pub fn default() -> Self {
        LicenseKey {
            key: Vec::new(),
            payload: Vec::new(),
            checksum: Vec::new(),
            properties: LicenseKeyProperties::default(),
            serialized_key: Vec::new(),
        }
    }

    // ==================================================
    //                    Operators
    // ==================================================

    #[inline(always)]
    pub fn deserialize(&self) -> Result<Self, Report> {
        if self.serialized_key.len() < self.properties.size() {
            return Err(eyre!(
                "Cannot deserialize license key with larger properties than raw key itself!"
            ));
        }

        Ok(LicenseKey {
            properties: self.properties.clone(),
            key: self.serialized_key[0..self.properties.key_size].to_vec(),
            payload: self.serialized_key
                [self.properties.key_size..self.properties.key_size + self.properties.payload_size]
                .to_vec(),
            checksum: self.serialized_key[self.properties.key_size + self.properties.payload_size
                ..self.properties.key_size
                    + self.properties.payload_size
                    + self.properties.checksum_size]
                .to_vec(),
            serialized_key: self.serialized_key.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::license_key::{LicenseKey, LicenseKeyProperties};

    #[test]
    fn license_key_validate_deserialization() {
        let key: Vec<u8> = Vec::from([0x01, 0x02, 0x03, 0x04]);
        let payload: Vec<u8> = Vec::from([0x05, 0x06, 0x07, 0x08]);
        let checksum: Vec<u8> = Vec::from([0x09, 0x0A, 0x0B, 0x0C]);
        let properties: LicenseKeyProperties = LicenseKeyProperties {
            key_size: 4,
            payload_size: 4,
            checksum_size: 4,
        };

        let mut raw_key: Vec<u8> = Vec::new();
        raw_key.extend(key.clone());
        raw_key.extend(payload.clone());
        raw_key.extend(checksum.clone());
        let manual_license_key = LicenseKey {
            key: key.clone(),
            payload: payload.clone(),
            checksum: checksum.clone(),
            properties: properties.clone(),
            serialized_key: raw_key.clone(),
        };

        let license_key = LicenseKey::new(
            properties.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            raw_key.clone(),
        )
        .deserialize();
        match license_key {
            Ok(valid) => {
                assert_eq!(valid, manual_license_key);
            }
            Err(_) => {
                assert!(false)
            }
        }
    }
}
