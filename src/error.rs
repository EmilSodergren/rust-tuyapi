use openssl::error::ErrorStack;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("{0}")]
pub enum ErrorKind {
    Base64DecodeError(#[from] base64::DecodeError),
    JsonError(#[from] serde_json::error::Error),
    OpenSSLError(#[from] ErrorStack),
    SystemTimeError(#[from] std::time::SystemTimeError),
    TcpError(#[from] io::Error),

    #[error("parsing failed with: {0:?}")]
    ParseError(nom::error::ErrorKind),
    #[error("Something went wrong when parsing the received buffer. It still contains data after parsing is done")]
    BufferNotCompletelyParsedError,
    #[error("Can not encode messages that are missing CommandType")]
    CanNotEncodeMessageWithoutCommand,
    #[error("No CommandType was supplied in message")]
    CommandTypeMissing,
    #[error("Error: CRC mismatch")]
    CRCError,
    #[error("The key length is {0}, should be 16")]
    KeyLength(usize),
    #[error("the tuyadevice is not created with a socket address. can not set object")]
    MissingAddressError,
    #[error("Data was incomplete. Error while parsing the received data")]
    ParsingIncomplete,
    #[error("Bad read from TcpStream")]
    BadTcpRead,
    #[error("The given version {0}.{1} is not valid")]
    VersionError(String, String),
}
