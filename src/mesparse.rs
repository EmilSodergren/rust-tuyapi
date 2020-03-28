use crate::cipher::TuyaCipher;
use crate::error::ErrorKind;
use hex::FromHex;
use nom::{
    bytes::complete::tag,
    combinator::{map, peek, recognize},
    multi::{length_data, many1},
    number::complete::be_u32,
    sequence::tuple,
    IResult,
};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::cmp::PartialEq;
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, ErrorKind>;

/// Human readable definitions of command bytes.
#[allow(dead_code)]
#[derive(Debug, FromPrimitive, PartialEq)]
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
    Error = 255,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum TuyaVersion {
    ThreeOne,
    ThreeThree,
}

impl FromStr for TuyaVersion {
    type Err = ErrorKind;

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
        Err(ErrorKind::VersionError("Unknown".to_string(), "Unknown".to_string()).into())
    }
}

#[derive(Debug, PartialEq)]
pub struct Message {
    payload: Vec<u8>,
    command: Option<CommandType>,
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

pub fn parse_messages(buf: &[u8]) -> IResult<&[u8], Vec<Message>> {
    let prefix_bytes = <[u8; 4]>::from_hex("000055AA").expect("");
    let suffix_bytes = <[u8; 4]>::from_hex("0000AA55").expect("");

    let be_u32_minus4 = map(be_u32, |n: u32| n - 4);
    let (buf, vec) = many1(tuple((
        tag(prefix_bytes),
        be_u32,
        be_u32,
        length_data(be_u32_minus4),
        tag(suffix_bytes),
    )))(buf)?;
    let mut messages = vec![];
    for (_, seq_nr, command, recv_data, _) in vec {
        // check if the recv_data contains a return code
        let (recv_data, maybe_retcode) = peek(be_u32)(recv_data)?;
        let (recv_data, _ret_code) = if maybe_retcode & 0xFFFFFF00 == 0 {
            let (a, b) = recognize(be_u32)(recv_data)?;
            (a, Some(b))
        } else {
            (recv_data, None)
        };
        // TODO: Check return code
        let (payload, _crc) = recv_data.split_at(recv_data.len() - 4);
        // TODO: Calculate CRC and compare
        let message = Message {
            payload: payload.to_vec(),
            command: FromPrimitive::from_u32(command).or(None),
            seq_nr: seq_nr,
        };
        messages.push(message);
    }
    Ok((buf, messages))
}

fn verify_key(key: &str) -> Result<()> {
    if key.len() == 16 {
        Ok(())
    } else {
        Err(ErrorKind::KeyLength(key.len()).into())
    }
}

#[test]
fn test_key_length_is_16() {
    let key = "0123456789ABCDEF";
    assert!(verify_key(key).is_ok());
}

#[test]
fn test_key_lenght_not_16_gives_error() {
    let bad_key = "13579BDF";
    assert!(verify_key(bad_key).is_err());
}

#[test]
fn test_parse_mqttversion() {
    let version = TuyaVersion::from_str("3.1").unwrap();
    assert_eq!(version, TuyaVersion::ThreeOne);

    let version2 = TuyaVersion::from_str("3.3").unwrap();
    assert_eq!(version2, TuyaVersion::ThreeThree);

    assert!(TuyaVersion::from_str("3.4").is_err());
}

#[test]
fn test_parse_messages() {
    let packet = hex::decode("000055aa00000000000000090000000c00000000b051ab030000aa55").unwrap();
    let expected = Message {
        command: Some(CommandType::HeartBeat),
        payload: Vec::new(),
        seq_nr: 0,
    };
    let (buf, messages) = parse_messages(&packet).unwrap();
    assert_eq!(messages[0], expected);
    assert_eq!(buf, &[] as &[u8]);
}

#[test]
fn test_parse_double_messages() {
    let packet = hex::decode("000055aa00000000000000090000000c00000000b051ab030000aa55000055aa000000000000000a0000000c00000000b051ab030000aa55").unwrap();
    let expected = vec![
        Message {
            command: Some(CommandType::HeartBeat),
            payload: Vec::new(),
            seq_nr: 0,
        },
        Message {
            command: Some(CommandType::DpQuery),
            payload: Vec::new(),
            seq_nr: 0,
        },
    ];
    let (buf, messages) = parse_messages(&packet).unwrap();
    assert_eq!(messages[0], expected[0]);
    assert_eq!(messages[1], expected[1]);
    assert_eq!(buf, &[] as &[u8]);
}
