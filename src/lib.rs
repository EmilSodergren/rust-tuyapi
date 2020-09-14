mod cipher;
mod crc;
mod error;
pub mod mesparse;

extern crate num;
extern crate num_derive;
#[macro_use]
extern crate lazy_static;

use serde::{Deserialize, Serialize};
use serde_json;
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
    t: u64,
    dps: HashMap<String, serde_json::Value>,
}

pub fn get_payload(device_id: &str, tt: TuyaType, state: &str) -> mesparse::Result<String> {
    serde_json::to_string(&Payload {
        devId: device_id.to_string(),
        gwId: device_id.to_string(),
        uid: "".to_string(),
        t: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| error::ErrorKind::SystemTimeError(e))?
            .as_secs(),
        dps: get_dps_for(tt, state),
    })
    .map_err(|e| error::ErrorKind::JsonError(e))
}

fn get_dps_for(tt: TuyaType, state: &str) -> HashMap<String, serde_json::Value> {
    match tt {
        TuyaType::Socket => get_socket_state(state),
    }
}

fn get_socket_state(state: &str) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    if state.eq_ignore_ascii_case("on") || state.eq_ignore_ascii_case("1") {
        map.insert("1".to_string(), serde_json::to_value(true).unwrap());
    } else {
        map.insert("1".to_string(), serde_json::to_value(false).unwrap());
    }
    map
}
