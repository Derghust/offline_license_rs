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

    let license_op = LicenseOperator::default(1, 3, [1, 2, 3, 4, 5, 6, 7, 8]);

    let license_key = license_op
        .generate_license_key(user_email.as_bytes())
        .unwrap();
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
