use crate::error::ErrorKind;
use crate::mesparse::{Result, TuyaVersion};
use openssl::error::ErrorStack;
use openssl::symm::{encrypt, Cipher};

pub(crate) struct TuyaCipher {
    key: String,
    version: TuyaVersion,
}

impl TuyaCipher {
    pub fn create(key: String, version: TuyaVersion) -> TuyaCipher {
        TuyaCipher { key, version }
    }

    pub fn encrypt(&self, data: Vec<u8>, base64: bool) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        match encrypt(cipher, &self.key.as_bytes(), None, &data) {
            Ok(enc_result) => Ok(enc_result),
            Err(err) => Err(ErrorKind::EncryptionError(err)),
        }
    }
}
