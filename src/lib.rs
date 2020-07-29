mod cipher;
mod crc;
mod error;
pub mod mesparse;

extern crate num;
extern crate num_derive;
#[macro_use]
extern crate lazy_static;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

pub enum TuyaType {
    Socket,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Payload {
    dev_id: String,
    dps: HashMap<String, bool>,
}

pub fn get_payload(device_id: &str, tt: TuyaType, state: &str) -> mesparse::Result<String> {
    serde_json::to_string(&Payload {
        dev_id: device_id.to_string(),
        dps: get_dps_for(tt, state),
    })
    .map_err(|e| error::ErrorKind::JsonError(e))
}

fn get_dps_for(tt: TuyaType, state: &str) -> HashMap<String, bool> {
    match tt {
        Socket => get_socket_state(state),
    }
}

fn get_socket_state(state: &str) -> HashMap<String, bool> {
    let mut map = HashMap::new();
    if state.eq_ignore_ascii_case("on") || state.eq_ignore_ascii_case("1") {
        map.insert("1".to_string(), true);
    } else {
        map.insert("1".to_string(), false);
    }
    map
}
