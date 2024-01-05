//! # TuyaDevice
//! The TuyaDevice represents a communication channel with a Tuya compatible device. It
//! encapsulates the device key, version and ip address. By supplying a Payload to either set() or
//! get() functions the framework takes care of sending and receiving the reply from the device.
//!
//! The TuyaDevice is the high level device communication API. To get in to the nitty gritty
//! details, create a MessageParser.
use crate::mesparse::{CommandType, Message, MessageParser, TuyaVersion};
use crate::transports::{Transport, TuyaTransport};
use crate::{Payload, Result};
use log::{debug, info};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};

pub struct TuyaDevice {
    mp: MessageParser,
    addr: SocketAddr,
    transport: Transport,
    ver: TuyaVersion,
}

impl TuyaDevice {
    pub fn create(ver: &str, key: Option<&str>, addr: IpAddr) -> Result<TuyaDevice> {
        let mp = MessageParser::create(ver, key)?;
        Ok(TuyaDevice::create_with_mp(
            mp,
            addr,
            Transport::TCP(6668),
            ver.parse()?,
        ))
    }

    pub fn create_with_transport(
        ver: &str,
        key: Option<&str>,
        addr: IpAddr,
        transport: Transport,
    ) -> Result<TuyaDevice> {
        let mp = MessageParser::create(ver, key)?;
        Ok(TuyaDevice::create_with_mp(
            mp,
            addr,
            transport,
            ver.parse()?,
        ))
    }

    pub fn create_with_mp(
        mp: MessageParser,
        addr: IpAddr,
        transport: Transport,
        ver: TuyaVersion,
    ) -> TuyaDevice {
        match transport {
            Transport::TCP(port) | Transport::UDP(port) => TuyaDevice {
                mp,
                addr: SocketAddr::new(addr, port),
                transport,
                ver,
            },
        }
    }

    fn set_commandtype(&self) -> CommandType {
        match self.ver {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeTwo | TuyaVersion::ThreeThree => {
                CommandType::Control
            }
        }
    }

    fn get_commandtype(&self) -> CommandType {
        match self.ver {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeThree => CommandType::DpQuery,
            TuyaVersion::ThreeTwo => CommandType::Control,
        }
    }

    fn refresh_commandtype(&self) -> CommandType {
        match self.ver {
            TuyaVersion::ThreeOne | TuyaVersion::ThreeTwo | TuyaVersion::ThreeThree => {
                CommandType::DpRefresh
            }
        }
    }

    //TODO: There are code duplication here... do we really need three methods??
    pub fn set(&self, tuya_payload: Payload, seq_id: u32) -> Result<()> {
        let mes = Message::new(tuya_payload, self.set_commandtype(), Some(seq_id));
        let replies = self.send(&mes, seq_id)?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(())
    }

    pub fn get(&self, tuya_payload: Payload, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload, self.get_commandtype(), Some(seq_id));
        let replies = self.send(&mes, seq_id)?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(replies)
    }

    pub fn refresh(&self, tuya_payload: Payload, seq_id: u32) -> Result<Vec<Message>> {
        let mes = Message::new(tuya_payload, self.refresh_commandtype(), Some(seq_id));
        let replies = self.send(&mes, seq_id)?;
        replies
            .iter()
            .for_each(|mes| info!("Decoded response ({}):\n{}", seq_id, mes));
        Ok(replies)
    }

    fn send(&self, mes: &Message, seq_id: u32) -> Result<Vec<Message>> {
        let mut transport: Box<dyn TuyaTransport> = match self.transport {
            Transport::TCP(_) => Box::new(TcpStream::connect(self.addr)?),
            Transport::UDP(port) => Box::new(UdpSocket::bind(format!("0.0.0.0:{}", port))?),
        };
        transport.setup(self.addr)?;
        info!("Writing message to {} ({}):\n{}", self.addr, seq_id, &mes);
        let bts = transport.do_send(self.mp.encode(mes, true)?.as_ref())?;
        info!("Wrote {} bytes ({})", bts, seq_id);
        let mut buf = [0; 256];
        let bts = transport.do_read(&mut buf)?;
        info!("Received {} bytes ({})", bts, seq_id);
        if bts == 0 {
            return Err(transport.error());
        } else {
            debug!(
                "Received response ({}):\n{}",
                seq_id,
                hex::encode(&buf[..bts])
            );
        }
        debug!("Shutting down connection ({})", seq_id);
        transport.teardown()?;
        self.mp.parse(&buf[..bts])
    }
}
