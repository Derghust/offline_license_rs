use crate::adler32::adler32_checksum;
use color_eyre::Report;

pub struct LicenseChecksum {
    magic: Vec<u8>,
    byte_size: usize,
    operator: fn(&[u8], &[u8]) -> Result<Vec<u8>, Report>,
}

impl LicenseChecksum {
    // ==================================================
    //                   Constructor
    // ==================================================

    pub fn new(
        magic: Vec<u8>,
        byte_size: usize,
        operator: fn(&[u8], &[u8]) -> Result<Vec<u8>, Report>,
    ) -> Self {
        LicenseChecksum {
            magic,
            byte_size,
            operator,
        }
    }

    #[inline(always)]
    pub fn default(checksum_magic: [u8; 8]) -> Self {
        LicenseChecksum {
            magic: checksum_magic.to_vec(),
            byte_size: 4,
            operator: adler32_checksum,
        }
    }

    // ==================================================
    //                    Operators
    // ==================================================

    #[inline(always)]
    pub fn execute(&self, seed: &[u8]) -> Result<Vec<u8>, Report> {
        (self.operator)(seed, &self.magic)
    }

    // ==================================================
    //                Getters & Setters
    // ==================================================

    #[inline(always)]
    pub fn get_magic(&self) -> &Vec<u8> {
        &self.magic
    }

    #[inline(always)]
    pub fn get_byte_size(&self) -> &usize {
        &self.byte_size
    }
}
