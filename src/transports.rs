//! # TuyaTransports
//! The TuyaTransport trait abstracts Tcp or Udp communication.
use crate::error::ErrorKind;
use crate::Result;
use std::io::prelude::*;
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

pub enum Transport {
    TCP(u16),
    UDP(u16),
}

pub(crate) trait TuyaTransport {
    fn setup(&self, addr: SocketAddr) -> Result<()>;
    fn do_send(&mut self, buf: &[u8]) -> Result<usize>;
    fn do_read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn teardown(&self) -> Result<()>;
    fn error(&self) -> ErrorKind;
}

impl TuyaTransport for TcpStream {
    fn setup(&self, _addr: SocketAddr) -> Result<()> {
        self.set_nodelay(true)?;
        self.set_write_timeout(Some(Duration::new(2, 0)))?;
        self.set_read_timeout(Some(Duration::new(2, 0)))?;
        Ok(())
    }
    fn do_send(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(self.write(buf)?)
    }
    fn do_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.read(buf)?)
    }
    fn teardown(&self) -> Result<()> {
        Ok(self.shutdown(Shutdown::Both)?)
    }
    fn error(&self) -> ErrorKind {
        ErrorKind::BadTcpRead
    }
}

impl TuyaTransport for UdpSocket {
    fn setup(&self, addr: SocketAddr) -> Result<()> {
        self.connect(addr)?;
        self.set_write_timeout(Some(Duration::new(2, 0)))?;
        self.set_read_timeout(Some(Duration::new(2, 0)))?;
        Ok(())
    }
    fn do_send(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(self.send(buf)?)
    }
    fn do_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.recv(buf)?)
    }
    fn teardown(&self) -> Result<()> {
        Ok(())
    }
    fn error(&self) -> ErrorKind {
        ErrorKind::BadUdpRead
    }
}
