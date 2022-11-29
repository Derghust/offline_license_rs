//! # Offline license rs
//!
//! **Offline license RS** license generator used for offline software license verification.

extern crate core;

pub use crate::license_key::LicenseKey;

pub mod adler32;
pub mod license_key;
pub mod license_magic;
pub mod license_operator;
pub mod license_serializer;
