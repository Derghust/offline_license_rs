use rand::{Rng, RngCore};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LicenseMagic {
    magic: Vec<Vec<u8>>,
}

impl LicenseMagic {
    pub fn new(magic: Vec<Vec<u8>>) -> LicenseMagic {
        LicenseMagic { magic }
    }

    pub fn default() -> LicenseMagic {
        LicenseMagic { magic: Vec::new() }
    }

    pub fn push(&mut self, magic: Vec<u8>) {
        self.magic.push(magic);
    }

    pub fn payload_size(&self) -> usize {
        self.magic.iter().map(|m| m.len()).sum()
    }

    pub fn get_magic(&self) -> &Vec<Vec<u8>> {
        &self.magic
    }

    #[inline(always)]
    pub fn randomize_magic(&mut self, magic_size: usize, magic_count: usize) {
        let mut rng = rand::thread_rng();

        for _ in 0..magic_size {
            self.magic
                .push((0..magic_count).map(|_| rng.gen()).collect());
        }
    }
}
