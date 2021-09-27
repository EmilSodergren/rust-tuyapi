//! # TuyaDevice
//! The TuyaDevice represents a communication channel with a Tuya compatible device. It
//! encapsulates the device key, version and ip address. By supplying a Payload to either set() or
//! get() functions the framework takes care of sending and receiving the reply from the device.
//!
//! The TuyaDevice is the high level device communication API. To get in to the nitty gritty
//! details, create a MessageParser.
use crate::error::ErrorKind;
use crate::mesparse::{CommandType, Message, MessageParser};
use crate::{Payload, Result};
use log::{debug, info};
use std::io::prelude::*;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

pub struct TuyaDevice {
    mp: MessageParser,
    addr: SocketAddr,
}

impl TuyaDevice {
    pub fn create(ver: &str, key: Option<&str>, addr: IpAddr) -> Result<TuyaDevice> {
        let mp = MessageParser::create(ver, key)?;
        Ok(TuyaDevice::create_with_mp(mp, addr))
    }

    pub fn create_with_mp(mp: MessageParser, addr: IpAddr) -> TuyaDevice {
        TuyaDevice {
            mp,
            addr: SocketAddr::new(addr, 6668),
        }
    }

    pub fn set(&self, tuya_payload: Payload, seq_id: u32) -> Result<()> {
        let mes = Message::new(tuya_payload, CommandType::Control, Some(seq_id));
        let replies = self.send(&mes, seq_id)?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(())
    }

    pub fn get(&self, tuya_payload: Payload, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload, CommandType::DpQuery, Some(seq_id));
        let replies = self.send(&mes, seq_id)?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(replies)
    }

    pub fn refresh(&self, tuya_payload: Payload, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload, CommandType::DpRefresh, Some(seq_id));
        let replies = self.send(&mes, seq_id)?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(replies)
    }

    fn send(&self, mes: &Message, seq_id: u32) -> Result<Vec<Message>> {
        let mut tcpstream = TcpStream::connect(&self.addr)?;
        tcpstream.set_nodelay(true)?;
        tcpstream.set_read_timeout(Some(Duration::new(2, 0)))?;
        tcpstream.set_read_timeout(Some(Duration::new(2, 0)))?;
        info!("Writing message to {} ({}):\n{}", self.addr, seq_id, &mes);
        let bts = tcpstream.write(self.mp.encode(&mes, true)?.as_ref())?;
        info!("Wrote {} bytes ({})", bts, seq_id);
        let mut buf = [0; 256];
        let bts = tcpstream.read(&mut buf)?;
        info!("Received {} bytes ({})", bts, seq_id);
        if bts == 0 {
            return Err(ErrorKind::BadTcpRead);
        } else {
            debug!(
                "Received response ({}):\n{}",
                seq_id,
                hex::encode(&buf[..bts])
            );
        }
        debug!("Shutting down connection ({})", seq_id);
        tcpstream.shutdown(Shutdown::Both)?;
        self.mp.parse(&buf[..bts])
    }
}
