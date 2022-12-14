#[derive(Default)]
pub struct LicenseBlacklist {
    blacklist: Vec<Vec<u8>>,
}

impl LicenseBlacklist {
    // ==================================================
    //                   Constructor
    // ==================================================

    #[inline(always)]
    pub fn new(blacklist: Vec<Vec<u8>>) -> Self {
        LicenseBlacklist { blacklist }
    }

    // ==================================================
    //                    Operators
    // ==================================================

    #[inline(always)]
    pub fn push(&mut self, seed: Vec<u8>) {
        self.blacklist.push(seed)
    }

    #[inline(always)]
    pub fn is_blacklisted(&self, seed: Vec<u8>) -> bool {
        self.blacklist.contains(&seed)
    }

    // ==================================================
    //                Getters & Setters
    // ==================================================

    #[inline(always)]
    pub fn get_blacklist(&self) -> &Vec<Vec<u8>> {
        &self.blacklist
    }
}
