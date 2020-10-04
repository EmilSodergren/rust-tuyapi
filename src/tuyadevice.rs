use crate::mesparse::MessageParser;
use std::net::{Shutdown, SocketAddr, TcpStream};

pub struct TuyaDevice {
    mp: MessageParser,
    addr: SocketAddr,
}

impl TuyaDevice {
    pub fn create(ver: &str, key: Option<&str>, addr: SocketAddr) -> Result<MessageParser> {
        let mp = MessageParser::create(ver, key)?;
        create_with_mp(mp, addr)
    }

    pub fn create_with_mp(mp: MessageParser, addr: SocketAddr) -> TuyaDevice {
        TuyaDevice { mp, addr }
    }

    pub fn set(&self, tuya_payload: &str, seq_id: u32) -> Result<()> {
        let addr = match self.addr {
            Some(addr) => addr,
            None => return Err(ErrorKind::ParsingIncomplete),
        };
        let mut tcpstream = TcpStream::connect(addr).map_err(ErrorKind::TcpError)?;
        tcpstream.set_nodelay(true).map_err(ErrorKind::TcpError)?;
        info!("Connected to the device on ip {}", addr);
        info!(
            "Writing message to {} ({}):\n{}",
            addr, seq_id, &tuya_payload
        );
        let mes = Message::new(tuya_payload.as_bytes(), CommandType::Control, Some(seq_id));
        let bts = tcpstream
            .write(&self.encode(&mes, true)?)
            .map_err(ErrorKind::TcpError)?;
        info!("Wrote {} bytes.", bts);
        let mut buf = [0; 256];
        let bts = tcpstream.read(&mut buf).map_err(ErrorKind::TcpError)?;
        info!("Received {} bytes", bts);
        if bts > 0 {
            debug!(
                "Received message ({}):\n{}",
                seq_id,
                hex::encode(&buf[..bts])
            );
            // TODO: Can receive more than one message
            let message = self.parse(&buf[..bts])?;
            info!("Decoded message ({}):\n{}", seq_id, &message[0]);
        }

        debug!("shutting down connection");
        tcpstream
            .shutdown(Shutdown::Both)
            .map_err(ErrorKind::TcpError)?;
        Ok(())
    }
}
