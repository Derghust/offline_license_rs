//! # Adler 32
//!
//! Adler 32 is checksum algorithm
//!
//! [More about Adler-32](https://en.wikipedia.org/wiki/Adler-32)

const ADLER32_MOD: u32 = 0xFFF1;

/// Checksum hash with [Adler-32](https://en.wikipedia.org/wiki/Adler-32)
pub fn adler32_checksum(hash: Vec<u8>, init_left: u32, init_right: u32) -> u32 {
  let mut left = init_left;
  let mut right = init_right;

  for byte in hash.iter() {
    let casted_byte = *byte as u32;

    left = (left + casted_byte) % ADLER32_MOD;
    right += (right + casted_byte) % ADLER32_MOD;
  }

  (right << 16) | left
}
