use crate::cipher::TuyaCipher;
use crate::error::{Error, ErrorKind};
use failure::ResultExt;
use log::debug;
use num::{FromPrimitive, ToPrimitive};
use std::cmp::PartialEq;
use std::io::{BufReader, Read};
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, Error>;
const PREFIX_BYTES: u32 = 0x000055AA;
const SUFFIX_BYTES: u32 = 0x0000AA55;

/// Human readable definitions of command bytes.
#[allow(dead_code)]
#[derive(FromPrimitive, ToPrimitive)]
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

fn verify_magic_bytes(received: u32, magic_bytes: u32) -> Result<()> {
    if received == magic_bytes {
        return Ok(());
    }
    debug!("Received: {}, should be {}", received, magic_bytes);
    Err(ErrorKind::BadPackagePrefix.into())
}

pub fn parse_packets(buf: &[u8]) -> Result<Vec<Message>> {
    let mut packets: Vec<Message> = Vec::new();
    let mut buf = BufReader::new(buf);
    let mut prefix = [0; 4];
    buf.read_exact(&mut prefix)
        .context(ErrorKind::BadPackagePrefix)?;
    verify_magic_bytes(u32::from_be_bytes(prefix), PREFIX_BYTES)?;
    let mut seq_nr = [0; 4];
    buf.read_exact(&mut seq_nr)
        .context(ErrorKind::BadPackageSeqNr)?;
    let seq_nr = u32::from_be_bytes(seq_nr);
    let mut command = [0; 4];
    buf.read_exact(&mut command)
        .context(ErrorKind::BadCommandType)?;
    let command =
        FromPrimitive::from_u32(u32::from_be_bytes(command)).ok_or(ErrorKind::BadCommandType)?;
    let mut length = [0; 4];
    buf.read_exact(&mut length)
        .context(ErrorKind::BadPackageLength)?;
    let length = u32::from_be_bytes(length);
    let mut payload = vec![0u8; length as usize];
    buf.read_exact(&mut payload)
        .context(ErrorKind::BadPayload(length as usize))?;
    let mut suffix = [0; 4];
    buf.read_exact(&mut suffix)
        .context(ErrorKind::BadPackageSuffix)?;
    verify_magic_bytes(u32::from_be_bytes(suffix), SUFFIX_BYTES)?;
    let message = Message {
        command,
        seq_nr,
        payload,
    };
    packets.push(message);

    Ok(packets)
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
fn test_verify_magic_bytes() {
    assert!(verify_magic_bytes(PREFIX_BYTES, PREFIX_BYTES).is_ok());
    assert!(verify_magic_bytes(SUFFIX_BYTES, PREFIX_BYTES).is_err());
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
fn test_parse_packets() {
    let mut packet = Vec::new();
    packet.append(&mut PREFIX_BYTES.to_be_bytes().to_vec()); // Magic bytes
    packet.append(&mut 4u32.to_be_bytes().to_vec()); // sequence number
    packet.append(
        // Command Type
        &mut ToPrimitive::to_u32(&CommandType::HeartBeat)
            .unwrap()
            .to_be_bytes()
            .to_vec(),
    );
    let message = "ThisIsAPayload".as_bytes();
    packet.append(&mut (message.len() as u32).to_be_bytes().to_vec()); // Payload size
    packet.append(&mut 0u32.to_be_bytes().to_vec()); // Return Code
    packet.append(&mut message.to_vec()); // Payload
    packet.append(&mut 123456u32.to_be_bytes().to_vec());
    packet.append(&mut SUFFIX_BYTES.to_be_bytes().to_vec());
    println!("{:?}", packet);
}
