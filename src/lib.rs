mod cipher;
mod crc;
pub mod error;
pub mod mesparse;
pub mod tuyadevice;

extern crate num;
extern crate num_derive;
#[macro_use]
extern crate lazy_static;

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::mesparse::Result;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Display;

use crate::error::ErrorKind;

pub enum TuyaType {
    Socket,
}

#[derive(Debug, Clone, PartialEq)]
enum Payload {
    Struct(PayloadStruct),
    String(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[allow(non_snake_case)]
pub struct PayloadStruct {
    devId: String,
    gwId: String,
    uid: String,
    t: u32,
    dps: HashMap<String, serde_json::Value>,
}

pub trait Scramble {
    fn scramble(&self) -> Self;

    /// Take the last 5 characters
    fn scramble_str(text: &str) -> &str {
        if let Some((i, _)) = text.char_indices().rev().nth(5) {
            return &text[i..];
        }
        text
    }
}

impl TryFrom<Vec<u8>> for Payload {
    type Error = ErrorKind;

    fn try_from(vec: Vec<u8>) -> Result<Self> {
        Ok(match serde_json::from_slice(&vec)? {
            serde_json::Value::String(s) => Payload::String(s),
            value => Payload::Struct(serde_json::from_value(value)?),
        })
    }
}

impl Scramble for PayloadStruct {
    fn scramble(&self) -> PayloadStruct {
        PayloadStruct {
            devId: String::from("...") + Self::scramble_str(&self.devId),
            gwId: String::from("...") + Self::scramble_str(&self.gwId),
            t: self.t,
            uid: self.uid.clone(),
            dps: self.dps.clone(),
        }
    }
}

impl Display for PayloadStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let full_display = std::env::var("TUYA_FULL_DISPLAY").map_or_else(|_| false, |_| true);
        if full_display {
            write!(f, "{}", serde_json::to_string(self).unwrap())
        } else {
            write!(f, "{}", serde_json::to_string(&self.scramble()).unwrap())
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct GetPayload {
    devId: String,
    gwId: String,
}

// Convenience method to create a valid Tuya style payload from a device ID and a state received
// from mqtt.
// Calling:
//
// payload("abcde", TuyaType::Socket, "on");
//
// will render:
//
// {
//   devId: abcde,
//   gwId: abcde,
//   uid: "",
//   t: 132478194, <-- current time
//   dps: {
//     1: true
//   }
// }
//
pub fn payload(device_id: &str, tt: TuyaType, state: &str) -> Result<String> {
    serde_json::to_string(&PayloadStruct {
        devId: device_id.to_string(),
        gwId: device_id.to_string(),
        uid: "".to_string(),
        t: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as u32,
        dps: dps(tt, state),
    })
    .map_err(error::ErrorKind::JsonError)
}

pub fn get_payload(device_id: &str) -> Result<String> {
    serde_json::to_string(&GetPayload {
        devId: device_id.to_string(),
        gwId: device_id.to_string(),
    })
    .map_err(error::ErrorKind::JsonError)
}

fn dps(tt: TuyaType, state: &str) -> HashMap<String, serde_json::Value> {
    match tt {
        TuyaType::Socket => socket_dps(state),
    }
}

fn socket_dps(state: &str) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    if state.eq_ignore_ascii_case("on") || state.eq_ignore_ascii_case("1") {
        map.insert("1".to_string(), serde_json::to_value(true).unwrap());
    } else {
        map.insert("1".to_string(), serde_json::to_value(false).unwrap());
    }
    map
}
