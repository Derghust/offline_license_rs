use log::{info, LevelFilter};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

use offline_license_rs::license_key::LicenseKeyStatus;
use offline_license_rs::license_operator::LicenseOperator;

fn main() {
    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .expect("TermLogger should be initialize!");

    let user_email = "sample.name@sample.domain.com";

    let mut license_op = LicenseOperator::default();
    license_op.randomize_magic(1, 3);

    let license_key = license_op.generate_license_key(user_email.as_bytes());
    info!(
        "License key [key={}]",
        license_op.get_serialized_key(&license_key)
    );

    match license_op.validate_license_key(&license_key) {
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
