mod cipher;
mod crc;
mod error;
pub mod mesparse;

extern crate num;
extern crate num_derive;
#[macro_use]
extern crate lazy_static;

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use std::collections::HashMap;

pub enum TuyaType {
    Socket,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Payload {
    devId: String,
    gwId: String,
    uid: String,
    t: u32,
    dps: HashMap<String, serde_json::Value>,
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
pub fn payload(device_id: &str, tt: TuyaType, state: &str) -> mesparse::Result<String> {
    serde_json::to_string(&Payload {
        devId: device_id.to_string(),
        gwId: device_id.to_string(),
        uid: "".to_string(),
        t: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(error::ErrorKind::SystemTimeError)?
            .as_secs() as u32,
        dps: dps(tt, state),
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
