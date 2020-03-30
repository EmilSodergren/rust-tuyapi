use crate::error::ErrorKind;
use crate::mesparse::{Result, TuyaVersion};
use base64::encode;
use openssl::symm::{encrypt, Cipher};

pub(crate) struct TuyaCipher {
    key: String,
    version: TuyaVersion,
}

impl TuyaCipher {
    pub fn create(key: String, version: TuyaVersion) -> TuyaCipher {
        TuyaCipher { key, version }
    }

    pub fn encrypt(&self, data: &[u8], is_base64: bool) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let res = encrypt(cipher, &self.key.as_bytes(), None, data)
            .map_err(|e| ErrorKind::EncryptionError(e))?;
        if is_base64 {
            Ok(res)
        } else {
            Ok(encode(res).as_bytes().to_vec())
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (_, data) = match self.version {
            TuyaVersion::ThreeOne => data.split_at(19),
            TuyaVersion::ThreeThree => data.split_at(15),
        };
        Ok(data.to_vec())
    }
}

#[test]
fn encrypt_message_as_a_buffer() {
    let cipher = TuyaCipher::create("bbe88b3f4106d354".to_string(), TuyaVersion::ThreeOne);

    let data = json::parse(
        r#"{"devId": "002004265ccf7fb1b659",
            "dps": {"1": false, "2": 0},
            "t": 1529442366,
            "s": 8}"#,
    )
    .map(|d| json::stringify(d))
    .map(|d| d.as_bytes().to_owned())
    .unwrap();

    let base64 = false;
    let result = cipher.encrypt(&data, base64).unwrap();

    let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
    assert_eq!(expected, result);
}

#[test]
fn decrypt_message_with_header_and_base_64_encoding() {
    let cipher = TuyaCipher::create("bbe88b3f4106d354".to_string(), TuyaVersion::ThreeOne);
    let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
    let expected = json::parse(
        r#"{"devId": "002004265ccf7fb1b659",
            "dps": {"1": false, "2": 0},
            "t": 1529442366,
            "s": 8}"#,
    )
    .map(|e| json::stringify(e))
    .map(|e| e.as_bytes().to_owned())
    .unwrap();

    let result = cipher.decrypt(message).unwrap();
    assert_eq!(expected, result);
}
