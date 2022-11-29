//! # Adler 32
//!
//! Adler 32 is checksum algorithm
//!
//! [More about Adler-32](https://en.wikipedia.org/wiki/Adler-32)

use byteorder::{BigEndian, ReadBytesExt};
use color_eyre::eyre::eyre;
use color_eyre::Report;

const ADLER32_MOD: u32 = 0xFFF1;

/// Checksum hash with [Adler-32](https://en.wikipedia.org/wiki/Adler-32)
///
/// Generate checksum from hash with developer defined left and right initialized values.
#[inline(always)]
pub fn adler32_checksum(hash: &[u8], init: &[u8]) -> Result<Vec<u8>, Report> {
    if init.len() != 8 {
        return Err(eyre!(
            "Cannot generate checksum with invalid init count! [count={}]",
            init.len()
        ));
    }

    let mut split = init.split_at(4);
    let left = split.0.read_u32::<BigEndian>().unwrap();
    let right = split.1.read_u32::<BigEndian>().unwrap();

    // https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html#method.fold
    let (lo, hi) = hash.iter().fold((left, right), |(left, right), &byte| {
        (
            (left + byte as u32) % ADLER32_MOD,
            (right + left + byte as u32) % ADLER32_MOD,
        )
    });
    Ok(((hi << 16) | lo).to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use crate::adler32::adler32_checksum;
    use byteorder::{BigEndian, ReadBytesExt};

    // Example test from [Adler-32](https://en.wikipedia.org/wiki/Adler-32) Wikipedia page
    #[test]
    fn validate_adler32_checksum() {
        let checksum = adler32_checksum(
            &"Wikipedia".as_bytes().to_vec(),
            &Vec::from([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        );

        assert!(checksum.is_ok());
        assert_eq!(300286872_u32.to_be_bytes().to_vec(), checksum.unwrap())
    }
}
