use crate::error::ErrorKind;
use crate::mesparse::{Result, TuyaVersion};
use base64::encode;
use openssl::symm::{decrypt, encrypt, Cipher};

const UDP_KEY: &str = "yGAdlopoPVldABfn";

pub(crate) struct TuyaCipher {
    key: String,
    version: TuyaVersion,
    cipher: Cipher,
}

impl TuyaCipher {
    pub fn create(key: String, version: TuyaVersion) -> TuyaCipher {
        TuyaCipher {
            key,
            version,
            cipher: Cipher::aes_128_ecb(),
        }
    }

    pub fn encrypt(&self, data: &[u8], is_base64: bool) -> Result<Vec<u8>> {
        let res = encrypt(self.cipher, &self.key.as_bytes(), None, data)
            .map_err(|e| ErrorKind::EncryptionError(e))?;
        if is_base64 {
            Ok(res)
        } else {
            Ok(encode(res).as_bytes().to_vec())
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Different header size in version 3.1 and 3.3
        // 3.1 is base64 encoded, 3.3 is not
        let data = match self.version {
            TuyaVersion::ThreeOne => {
                let (_, data) = data.split_at(19);
                base64::decode(data).map_err(|e| ErrorKind::Base64DecodeError(e))?
            }
            TuyaVersion::ThreeThree => data.split_at(15).1.to_vec(),
        };
        // let udpkey_hash = md5::compute(UDP_KEY);
        let res = decrypt(self.cipher, &self.key.as_bytes(), None, &data)
            // .or(decrypt(self.cipher, udpkey_hash.as_bytes(), None, &data))
            .map_err(|e| ErrorKind::DecryptionError(e))?;

        Ok(res.to_vec())
    }
}

#[test]
fn encrypt_message() {
    let cipher = TuyaCipher::create("bbe88b3f4106d354".to_string(), TuyaVersion::ThreeOne);

    let data = r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
        .as_bytes()
        .to_owned();

    let base64 = false;
    let result = cipher.encrypt(&data, base64).unwrap();

    let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
    assert_eq!(expected, result);
}

#[test]
fn decrypt_message_without_header_and_base64_encoding() {
    let cipher = TuyaCipher::create("bbe88b3f4106d354".to_string(), TuyaVersion::ThreeOne);
    let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
    let expected =
        r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
            .as_bytes()
            .to_owned();
}

#[test]
fn decrypt_message_with_header_and_base_64_encoding() {
    let cipher = TuyaCipher::create("bbe88b3f4106d354".to_string(), TuyaVersion::ThreeOne);
    let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
    let expected =
        r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
            .as_bytes()
            .to_owned();

    let result = cipher.decrypt(message).unwrap();
    assert_eq!(expected, result);
}
