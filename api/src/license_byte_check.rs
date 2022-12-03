use crate::license_magic::LicenseMagic;
use crate::license_serializer::LicenseKeySerializer;
use color_eyre::eyre::eyre;
use color_eyre::Report;
use log::info;

#[derive(Default)]
pub struct LicenseByteCheck {
    byte_positions: Vec<usize>,
}

impl LicenseByteCheck {
    // ==================================================
    //                   Constructor
    // ==================================================

    pub fn new(byte_positions: Vec<usize>, magic: &LicenseMagic) -> Result<Self, Report> {
        for &i in byte_positions.iter() {
            let magic_size = magic.get_magic().len();
            if i > magic_size - 1 {
                return Err(eyre!(
                    "Cannot initialize byte check with larger magic than {}!",
                    magic_size
                ));
            }
        }

        Ok(LicenseByteCheck { byte_positions })
    }

    // ==================================================
    //                    Operators
    // ==================================================

    pub fn push(mut self, byte_position: usize) -> Self {
        self.byte_positions.push(byte_position);
        self
    }

    pub fn validate(
        &self,
        payload: &[u8],
        serializer: &dyn LicenseKeySerializer,
        seed: &[u8],
        magic: &LicenseMagic,
    ) -> bool {
        for &bc in &self.byte_positions {
            match payload.get(bc) {
                None => return false,
                Some(&bs) => match magic.get_magic().get(bc) {
                    None => return false,
                    Some(m) => {
                        if bs != serializer.hash(seed, m) {
                            return false;
                        }
                    }
                },
            }
        }
        true
    }
}
