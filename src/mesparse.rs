use crate::cipher::TuyaCipher;
use crate::error::{Error, ErrorKind};
use hex::FromHex;
use nom::{
    bytes::streaming::{tag, take_until},
    multi::many1,
    sequence::tuple,
    AsBytes, IResult,
};
use std::cmp::PartialEq;
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, Error>;

/// Human readable definitions of command bytes.
#[allow(dead_code)]
#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq)]
enum CommandType {
    Udp = 0,
    ApConfig = 1,
    Active = 2,
    Bind = 3,
    RenameGw = 4,
    RenameDevice = 5,
    Unbind = 6,
    Control = 7,
    Status = 8,
    HeartBeat = 9,
    DpQuery = 10,
    QueryWifi = 11,
    TokenBind = 12,
    ControlNew = 13,
    EnableWifi = 14,
    DpQueryNew = 16,
    SceneExecute = 17,
    UdpNew = 19,
    ApConfigNew = 20,
    LanGwActive = 240,
    LanSubDevRequest = 241,
    LanDeleteSubDev = 242,
    LanReportSubDev = 243,
    LanScene = 244,
    LanPublishCloudConfig = 245,
    LanPublishAppConfig = 246,
    LanExportAppConfig = 247,
    LanPublishScenePanel = 248,
    LanRemoveGw = 249,
    LanCheckGwUpdate = 250,
    LanGwUpdate = 251,
    LanSetGwChannel = 252,
}

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
            return Err(
                ErrorKind::VersionError(version[0].to_string(), version[1].to_string()).into(),
            );
        }
        Err(ErrorKind::VersionError("".to_string(), "".to_string()).into())
    }
}

#[derive(Debug, PartialEq)]
pub struct Message {
    payload: Vec<u8>,
    command: CommandType,
    seq_nr: u32,
}

pub struct MessageParser {
    version: TuyaVersion,
    key: String,
    cipher: TuyaCipher,
}

impl MessageParser {
    pub fn create(ver: String, key: String) -> Result<MessageParser> {
        let version = TuyaVersion::from_str(&ver)?;
        if !key.is_empty() {
            verify_key(&key)?;
        }
        let cipher = TuyaCipher::create(key.clone(), version.clone());
        Ok(MessageParser {
            version,
            key,
            cipher,
        })
    }
}

pub fn parse_packet(_buf: &[u8]) -> Result<Vec<Message>> {
    Ok(vec![])
}

/// Function will return a vector with the messages extracted from the bytes received from the
/// server
fn extract_messages(buf: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    let prefix_bytes = <[u8; 4]>::from_hex("000055AA").expect("");
    let suffix_bytes = <[u8; 4]>::from_hex("0000AA55").expect("");
    let (buf, data) = many1(tuple((
        tag(prefix_bytes),
        take_until(suffix_bytes.as_bytes()),
    )))(buf)?;
    let val: Vec<&[u8]> = data.into_iter().map(|(_, val)| val).collect();
    Ok((buf, val))
}

fn verify_key(key: &str) -> Result<()> {
    if key.len() == 16 {
        Ok(())
    } else {
        Err(ErrorKind::KeyLength(key.len()).into())
    }
}

#[test]
fn verify_key_length_is_16() {
    let key = "0123456789ABCDEF";
    assert!(verify_key(key).is_ok());
}

#[test]
fn verify_key_lenght_not_16_gives_error() {
    let bad_key = "13579BDF";
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

#[test]
fn test_parse_tuya() {
    let packet = hex::decode("000055aa00000000000000090000000c00000000b051ab030000aa55").unwrap();
    let expected = Message {
        command: CommandType::HeartBeat,
        payload: Vec::new(),
        seq_nr: 0,
    };
    extract_messages(&packet);
    // assert_eq!(expected, parse_tuya(&packet).unwrap())
}
