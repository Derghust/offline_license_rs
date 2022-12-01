//! # Offline license rs
//!
//! **Offline license RS** license generator used for offline software license verification.

extern crate core;

pub use crate::license_key::LicenseKey;

mod adler32;
mod license_blacklist;
mod license_checksum;
pub mod license_key;
mod license_magic;
pub mod license_operator;
mod license_properties;
pub mod license_serializer;
