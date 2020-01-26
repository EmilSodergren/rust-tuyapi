use crate::cipher::TuyaCipher;
use crate::error::{Error, ErrorKind};
use failure::ResultExt;
use std::cmp::PartialEq;
use std::io::{BufReader, Read};
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, Error>;
const PrefixBytes: [u32; 4] = [0x00, 0x00, 0x55, 0xAA];
const SuffixBytes: [u32; 4] = [0x00, 0x00, 0xAA, 0x55];

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
            return Err(ErrorKind::VersionError(
                String::from(version[0]),
                String::from(version[1]),
            )
            .into());
        }
        Err(ErrorKind::VersionError(String::from(""), String::from("")).into())
    }
}

struct Message {
    data: String,
    command: CommandType,
    seqNr: u32,
}

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
}

fn parse_packets(buf: &[u8]) -> Result<Vec<Message>> {
    let packets: Vec<Message> = Vec::new();
    let mut buf = BufReader::new(buf);
    let mut prefix = [0; 4];
    buf.read_exact(&mut prefix)
        .context(ErrorKind::BadPackagePrefix)?;

    Ok(packets)
}

fn verify_key(key: String) -> Result<String> {
    if key.len() == 16 {
        Ok(key)
    } else {
        Err(ErrorKind::KeyLength(key.len()).into())
    }
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
fn verify_package_prefix() {}

#[test]
fn verify_parse_mqttversion() {
    let version = TuyaVersion::from_str("3.1").unwrap();
    assert_eq!(version, TuyaVersion::ThreeOne);

    let version2 = TuyaVersion::from_str("3.3").unwrap();
    assert_eq!(version2, TuyaVersion::ThreeThree);

    assert!(TuyaVersion::from_str("3.4").is_err());
}
