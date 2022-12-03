use color_eyre::Report;
use log::{info, LevelFilter};
use offline_license_rs::adler32::adler32_checksum;
use offline_license_rs::license_blacklist::LicenseBlacklist;
use offline_license_rs::license_byte_check::LicenseByteCheck;
use offline_license_rs::license_checksum::LicenseChecksum;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::borrow::Borrow;
use std::num::Wrapping;

use offline_license_rs::license_key::LicenseKeyStatus;
use offline_license_rs::license_magic::LicenseMagic;
use offline_license_rs::license_operator::LicenseOperator;
use offline_license_rs::license_properties::LicenseProperties;
use offline_license_rs::license_serializer::LicenseKeySerializer;

pub struct CustomizedLicenseKeySerializer {}

impl LicenseKeySerializer for CustomizedLicenseKeySerializer {
    // ==================================================
    //                    Operators
    // ==================================================

    #[inline(always)]
    fn hash(&self, seed: &[u8], magic: &[u8]) -> u8 {
        let mut hash: Wrapping<u8> = Wrapping(0);

        for &x in magic.iter() {
            if x == 1 || x == 3 {
                hash *= x;
            } else if x % 2 == 0 {
                for x in seed.iter() {
                    hash += Wrapping(x - 1).0;
                }
            } else {
                hash -= x;
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

fn main() -> Result<(), Report> {
    color_eyre::install()?;

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .expect("TermLogger should be initialize!");

    let user_email = "sample.name@sample.domain.com";

    let license_properties = LicenseProperties {
        key_size: 32,
        magic_size: 3,
        magic_count: 2,
    };

    let license_magic = LicenseMagic::new(Vec::from([
        Vec::from([0xFF, 0xAA, 0x12, 0x89]),
        Vec::from([0x45, 0x5A, 0xAD, 0x24]),
        Vec::from([0x1F, 0x11, 0xA8, 0x99]),
        Vec::from([0xF5, 0x88, 0x8A, 0x0F]),
    ]));

    let license_checksum = LicenseChecksum::new(
        Vec::from([0xFF, 0xAA, 0x24, 0xEA, 0x12, 0x44, 0x3F, 0xF8]),
        4,
        adler32_checksum,
    );

    // Create empty blacklist
    let license_blacklist = LicenseBlacklist::default();

    let license_byte_check =
        LicenseByteCheck::new(Vec::from([0, 3]), license_magic.borrow()).unwrap();

    let license_op = LicenseOperator::new(
        license_properties,
        license_magic,
        Box::new(CustomizedLicenseKeySerializer {}),
        license_checksum,
        license_blacklist,
        license_byte_check,
    );

    match license_op.generate_license_key(user_email.as_bytes()) {
        Ok(valid) => {
            info!(
                "License key [key={}]",
                license_op.get_serialized_key(&valid)
            );

            match license_op.validate_license_key(&valid) {
                LicenseKeyStatus::Valid => {
                    info!("Valid key")
                }
                LicenseKeyStatus::Invalid => {
                    info!("Invalid key")
                }
                LicenseKeyStatus::Blacklisted => {
                    info!("Blacklisted key")
                }
            }
        }
        Err(report) => return Err(report),
    }

    Ok(())
}
