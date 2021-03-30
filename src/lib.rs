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

use crate::mesparse::Result;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Display;

use crate::error::ErrorKind;
use std::convert::TryInto;

pub enum TuyaType {
    Socket,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Struct(PayloadStruct),
    String(String),
}

impl Payload {
    pub fn new(
        dev_id: String,
        gw_id: Option<String>,
        uid: Option<String>,
        t: Option<u32>,
        dps: HashMap<String, serde_json::Value>,
    ) -> Payload {
        Payload::Struct(PayloadStruct {
            dev_id,
            gw_id,
            uid,
            t,
            dps,
        })
    }
}

impl Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Payload::Struct(s) => write!(f, "{}", s),
            Payload::String(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PayloadStruct {
    #[serde(rename = "devId")]
    pub dev_id: String,
    #[serde(rename = "gwId", skip_serializing_if = "Option::is_none")]
    pub gw_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<u32>,
    pub dps: HashMap<String, serde_json::Value>,
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
        match serde_json::from_slice(&vec)? {
            serde_json::Value::String(s) => Ok(Payload::String(s)),
            value => Ok(Payload::Struct(serde_json::from_value(value)?)),
        }
    }
}
impl TryInto<Vec<u8>> for Payload {
    type Error = ErrorKind;

    fn try_into(self) -> Result<Vec<u8>> {
        match self {
            Payload::Struct(s) => Ok(serde_json::to_vec(&s)?),
            Payload::String(s) => Ok(s.as_bytes().to_vec()),
        }
    }
}

impl Scramble for PayloadStruct {
    fn scramble(&self) -> PayloadStruct {
        PayloadStruct {
            dev_id: String::from("...") + Self::scramble_str(&self.dev_id),
            gw_id: self
                .gw_id
                .as_ref()
                .map(|gwid| String::from("...") + Self::scramble_str(gwid)),
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
