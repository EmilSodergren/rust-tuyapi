use crate::error::ErrorKind;
use crate::mesparse::{Result, TuyaVersion};
use base64::encode;
use openssl::symm::{decrypt, encrypt, Cipher};

pub(crate) struct TuyaCipher {
    key: Vec<u8>,
    version: TuyaVersion,
    cipher: Cipher,
}

fn contains_header(version: &TuyaVersion, data: &[u8]) -> bool {
    data.len() > 3 && &data[..3] == version.as_bytes()
}

impl TuyaCipher {
    pub fn create(key: &[u8], version: TuyaVersion) -> TuyaCipher {
        TuyaCipher {
            key: key.to_vec(),
            version,
            cipher: Cipher::aes_128_ecb(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let res = encrypt(self.cipher, &self.key, None, data)
            .map_err(|e| ErrorKind::EncryptionError(e))?;
        match self.version {
            TuyaVersion::ThreeOne => Ok(encode(res).as_bytes().to_vec()),
            TuyaVersion::ThreeThree => Ok(res),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Different header size in version 3.1 and 3.3
        // 3.1 is base64 encoded, 3.3 is not
        let data = if contains_header(&self.version, &data) {
            // Handle the header
            match self.version {
                TuyaVersion::ThreeOne => {
                    let (_, data) = data.split_at(19);
                    base64::decode(data).map_err(|e| ErrorKind::Base64DecodeError(e))?
                }
                TuyaVersion::ThreeThree => data.split_at(15).1.to_vec(),
            }
        } else {
            // Handle No header
            match self.version {
                TuyaVersion::ThreeOne => {
                    base64::decode(data).map_err(|e| ErrorKind::Base64DecodeError(e))?
                }
                TuyaVersion::ThreeThree => data.to_vec(),
            }
        };
        let res = decrypt(self.cipher, &self.key, None, &data)
            .map_err(|e| ErrorKind::DecryptionError(e))?;

        Ok(res.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_contains_header_with_correct_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        assert_eq!(contains_header(&cipher.version, b"3.133ed3d4a2..."), true)
    }

    #[test]
    fn test_contains_header_with_wrong_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        assert_eq!(contains_header(&cipher.version, b"3.333ed3d4a2..."), false)
    }

    #[test]
    fn test_contains_header_with_no_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        assert_eq!(contains_header(&cipher.version, b"zrA8OK3r3JMi.."), false)
    }
    #[test]
    fn encrypt_message() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let data =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes();
        let result = cipher.encrypt(data).unwrap();

        let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(expected, result);
    }

    #[test]
    fn decrypt_message_with_header_and_base_64_encoding() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(message).unwrap();
        assert_eq!(&expected, &decrypted);
    }

    #[test]
    fn decrypt_message_without_header_and_without_base64_encoding() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeThree);
        let message = hex::decode("CEB03C38ADEBDC9322517A570D66AE369A58E009B673CAD9EAC6F861FD7932333C9F90720F1F9059E099B5CACFA9D7712EB866F74E9B48A6D0005B53D6E0A9FB33F903196A25FE5DD0FA763B1C97CA38").unwrap();
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(&message).unwrap();
        assert_eq!(&expected, &decrypted);
    }

    #[test]
    fn decrypt_message_without_header_and_base64_encoding() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(message).unwrap();
        assert_eq!(&expected, &decrypted);
    }

    #[test]
    fn decrypt_message_where_payload_is_not_json() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"3.133ed3d4a21effe90rt1hJFzMJPF3x9UhPTCiXw==";
        let expected = "gw id invalid".as_bytes().to_owned();

        let decrypted = cipher.decrypt(message).unwrap();
        assert_eq!(&expected, &decrypted);
    }
}
