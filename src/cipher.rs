use crate::mesparse::TuyaVersion;
use crate::Result;
use base64::{engine::general_purpose, Engine as _};
use openssl::symm::{decrypt, encrypt, Cipher};

/// TuyaCipher is a low level api for encrypting and decrypting Vec<u8>'s.
pub(crate) struct TuyaCipher {
    key: Vec<u8>,
    version: TuyaVersion,
    cipher: Cipher,
}

fn maybe_strip_header(version: &TuyaVersion, data: &[u8]) -> Vec<u8> {
    if data.len() > 3 && &data[..3] == version.as_bytes() {
        match version {
            TuyaVersion::ThreeOne => data.split_at(19).1.to_vec(),
            TuyaVersion::ThreeThree => data.split_at(15).1.to_vec(),
        }
    } else {
        data.to_vec()
    }
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
        let res = encrypt(self.cipher, &self.key, None, data)?;
        match self.version {
            TuyaVersion::ThreeOne => Ok(general_purpose::STANDARD.encode(res).as_bytes().to_vec()),
            TuyaVersion::ThreeThree => Ok(res),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Different header size in version 3.1 and 3.3
        let data = maybe_strip_header(&self.version, data);
        // 3.1 is base64 encoded, 3.3 is not
        let data = match self.version {
            TuyaVersion::ThreeOne => general_purpose::STANDARD.decode(&data)?,
            TuyaVersion::ThreeThree => data.to_vec(),
        };
        let res = decrypt(self.cipher, &self.key, None, &data)?;

        Ok(res.to_vec())
    }

    pub fn md5(&self, payload: &[u8]) -> Vec<u8> {
        let hash_line: Vec<u8> = [
            b"data=",
            payload,
            b"||lpv=",
            self.version.as_bytes(),
            b"||",
            self.key.as_ref(),
        ]
        .iter()
        .flat_map(|bytes| bytes.iter())
        .copied()
        .collect();
        let digest: [u8; 16] = md5::compute(hash_line).into();
        digest[4..16].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maybe_strip_header_with_correct_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"3.133ed3d4a21effe90zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=";
        let expected = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(maybe_strip_header(&cipher.version, message), expected)
    }

    #[test]
    fn maybe_strip_header_without_header() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeOne);
        let message = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        assert_eq!(maybe_strip_header(&cipher.version, &message), message)
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
    fn encrypt_message_without_base64_encoding() {
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
    fn decrypt_message_with_version_threethree() {
        let cipher = TuyaCipher::create(b"bbe88b3f4106d354", TuyaVersion::ThreeThree);
        let message = b"zrA8OK3r3JMiUXpXDWauNppY4Am2c8rZ6sb4Yf15MjM8n5ByDx+QWeCZtcrPqddxLrhm906bSKbQAFtT1uCp+zP5AxlqJf5d0Pp2OxyXyjg=".to_vec();
        let message = general_purpose::STANDARD.decode(&message).unwrap();
        let expected =
            r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0},"t":1529442366,"s":8}"#
                .as_bytes()
                .to_owned();

        let decrypted = cipher.decrypt(&message).unwrap();
        assert_eq!(&expected, &decrypted);
        // In the case of ThreeThree version,  the boolean it does not matter. It is always NOT
        // base64 encoded.
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
