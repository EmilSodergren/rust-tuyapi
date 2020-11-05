use crate::error::ErrorKind;
use crate::mesparse::{CommandType, Message, MessageParser, Result};
use log::{debug, info};
use std::io::prelude::*;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

pub struct TuyaDevice {
    mp: MessageParser,
    addr: SocketAddr,
}

impl TuyaDevice {
    pub fn create(ver: &str, key: Option<&str>, addr: SocketAddr) -> Result<TuyaDevice> {
        let mp = MessageParser::create(ver, key)?;
        Ok(TuyaDevice::create_with_mp(mp, addr))
    }

    pub fn create_with_mp(mp: MessageParser, addr: SocketAddr) -> TuyaDevice {
        TuyaDevice { mp, addr }
    }

    pub fn set(&self, tuya_payload: &str, seq_id: u32) -> Result<()> {
        let mes = Message::new(tuya_payload.as_bytes(), CommandType::Control, Some(seq_id));
        let mut tcpstream = TcpStream::connect(&self.addr).map_err(ErrorKind::TcpError)?;
        tcpstream.set_nodelay(true).map_err(ErrorKind::TcpError)?;
        tcpstream
            .set_read_timeout(Some(Duration::new(2, 0)))
            .map_err(ErrorKind::TcpError)?;
        tcpstream
            .set_read_timeout(Some(Duration::new(2, 0)))
            .map_err(ErrorKind::TcpError)?;
        info!(
            "Writing message to {} ({}):\n{}",
            self.addr, seq_id, &tuya_payload
        );
        let bts = tcpstream
            .write(self.mp.encode(&mes, true)?.as_ref())
            .map_err(ErrorKind::TcpError)?;
        info!("Wrote {} bytes.", bts);
        let mut buf = [0; 256];
        let bts = tcpstream.read(&mut buf).map_err(ErrorKind::TcpError)?;
        info!("Received {} bytes", bts);
        if bts == 0 {
            return Err(ErrorKind::BadTcpRead);
        } else {
            debug!(
                "Received message ({}):\n{}",
                seq_id,
                hex::encode(&buf[..bts])
            );
            // TODO: Can receive more than one message
            let messages = self.mp.parse(&buf[..bts])?;
            messages
                .iter()
                .for_each(|mes| info!("Decoded message ({}):\n{}", seq_id, mes));
        }

        debug!("Shutting down connection ({})", seq_id);
        tcpstream
            .shutdown(Shutdown::Both)
            .map_err(ErrorKind::TcpError)?;
        Ok(())
    }

    pub fn get(&self, tuya_payload: &str, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload.as_bytes(), CommandType::DpQuery, Some(seq_id));
        let mut tcpstream = TcpStream::connect(&self.addr).map_err(ErrorKind::TcpError)?;
        tcpstream.set_nodelay(true).map_err(ErrorKind::TcpError)?;
        tcpstream
            .set_read_timeout(Some(Duration::new(3, 0)))
            .map_err(ErrorKind::TcpError)?;
        tcpstream
            .set_read_timeout(Some(Duration::new(3, 0)))
            .map_err(ErrorKind::TcpError)?;
        info!("Connected to the device on ip {}", &self.addr);
        info!("Getting status from {} ({})", &self.addr, seq_id);
        let bts = tcpstream
            .write(self.mp.encode(&mes, true)?.as_ref())
            .map_err(ErrorKind::TcpError)?;
        info!("Wrote {} bytes.", bts);
        let mut buf = [0; 256];
        let bts = tcpstream.read(&mut buf).map_err(ErrorKind::TcpError)?;
        info!("Received {} bytes", bts);
        debug!(
            "Received message ({}):\n{}",
            seq_id,
            hex::encode(&buf[..bts])
        );
        // TODO: Can receive more than one message
        let message = self.mp.parse(&buf[..bts])?;
        info!("Decoded message ({}):\n{}", seq_id, &message[0]);

        debug!("shutting down connection");
        tcpstream
            .shutdown(Shutdown::Both)
            .map_err(ErrorKind::TcpError)?;
        Ok(message)
    }
}
