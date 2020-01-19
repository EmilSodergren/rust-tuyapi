use crate::mesparse::TuyaVersion;

pub(crate) struct TuyaCipher {
    key: String,
    version: TuyaVersion,
}

impl TuyaCipher {
    pub fn create(key: String, version: TuyaVersion) -> TuyaCipher {
        TuyaCipher { key, version }
    }
}
