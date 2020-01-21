use crate::cipher::TuyaCipher;
use failure::{Error, Fail};
use std::cmp::PartialEq;
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum TuyaVersion {
    ThreeOne,
    ThreeThree,
}

impl FromStr for TuyaVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let version: Vec<&str> = s.split(".").collect();
        if version.len() > 1 {
            if version[0] == "3" {
                if version[1] == "1" {
                    return Ok(TuyaVersion::ThreeOne);
                } else if version[1] == "3" {
                    return Ok(TuyaVersion::ThreeThree);
                }
            }
            return Err(E::VersionError(String::from(version[0]), String::from(version[1])).into());
        }
        Err(E::VersionError(String::from(""), String::from("")).into())
    }
}

struct Message {}

pub struct MessageParser {
    version: TuyaVersion,
    key: String,
    cipher: TuyaCipher,
}

impl MessageParser {
    pub fn create(ver: String, k: String) -> Result<MessageParser> {
        let version = TuyaVersion::from_str(&ver)?;
        let key = verify_key(k)?;
        let cipher = TuyaCipher::create(key.clone(), version.clone());
        Ok(MessageParser {
            version,
            key,
            cipher,
        })
    }

    // fn parse_packet(buf: Vec<u8>) -> Result()
}

fn verify_key(key: String) -> Result<String> {
    if key.len() == 16 {
        Ok(key)
    } else {
        Err(E::KeyLength(key.len()).into())
    }
}

#[derive(Debug, Fail)]
pub enum E {
    #[fail(display = "Wrong key lenght {}, should be 16", _0)]
    KeyLength(usize),
    #[fail(
        display = "Could not parse Version string. \'{}.{}\' is not a known TuyaVersion.",
        _0, _1
    )]
    VersionError(String, String),
}

#[test]
fn verify_key_length_is_16() {
    let key = String::from("0123456789ABCDEF");
    assert!(verify_key(key).is_ok());
}

#[test]
fn verify_key_lenght_not_16_gives_error() {
    let bad_key = String::from("13579BDF");
    assert!(verify_key(bad_key).is_err());
}

#[test]
fn verify_parse_mqttversion() {
    let version = TuyaVersion::from_str("3.1").unwrap();
    assert_eq!(version, TuyaVersion::ThreeOne);

    let version2 = TuyaVersion::from_str("3.3").unwrap();
    assert_eq!(version2, TuyaVersion::ThreeThree);

    assert!(TuyaVersion::from_str("3.4").is_err());
}
