#[derive(PartialEq, Clone, Debug)]
pub struct LicenseMagic {
  magic: Vec<Vec<u8>>
}

impl LicenseMagic {
  pub fn new(magic: Vec<Vec<u8>>) -> LicenseMagic {
    LicenseMagic {
      magic
    }
  }

  pub fn default() -> LicenseMagic {
    LicenseMagic {
      magic: Vec::new()
    }
  }

  pub fn push(&mut self, magic: Vec<u8>) -> &Self {
    self.magic.push(magic);

    self
  }

  pub fn payload_size(&self) -> usize {
    let mut payload_size: usize = 0;

    for magic in self.magic.iter() {
      payload_size += magic.len();
    }

    payload_size
  }

  pub fn get_magic(&self) -> &Vec<Vec<u8>> {
    &self.magic
  }
}
