use base64::DecodeError;
use openssl::error::ErrorStack;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorKind {
    #[error("String failed to decode as base64, error was: {0}")]
    Base64DecodeError(DecodeError),
    #[error("Something went wrong when parsing the received buffer. It still contains data after parsing is done.")]
    BufferNotCompletelyParsedError,
    #[error("Can not encode messages that are missing CommandType")]
    CanNotEncodeMessageWithoutCommand,
    #[error("No CommandType was supplied in message")]
    CommandTypeMissing,
    #[error("Error: CRC mismatch")]
    CRCError,
    #[error("Decryption failed with: {0}")]
    DecryptionError(ErrorStack),
    #[error("Encryption failed with: {0}")]
    EncryptionError(ErrorStack),
    #[error("Json failed: {0}")]
    JsonError(serde_json::error::Error),
    #[error("The key length is {0}, should be 16")]
    KeyLength(usize),
    #[error("the tuyadevice is not created with a socket address. can not set object.")]
    MissingAddressError,
    #[error("parsing failed with: {0:?}")]
    ParseError(nom::error::ErrorKind),
    #[error("Data was incomplete. Error while parsing the received data")]
    ParsingIncomplete,
    #[error("{0}")]
    SystemTimeError(std::time::SystemTimeError),
    #[error("Could not write to TcpStream. Error: {0}")]
    TcpError(io::Error),
    #[error("The given version {0}.{1} is not valid")]
    VersionError(String, String),
}
