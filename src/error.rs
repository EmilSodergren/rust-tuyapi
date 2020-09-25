use base64::DecodeError;
use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ErrorKind {
    Base64DecodeError(DecodeError),
    BufferNotCompletelyParsedError,
    CanNotEncodeMessageWithoutCommand,
    CommandTypeMissing,
    CRCError,
    DecryptionError(ErrorStack),
    EncryptionError(ErrorStack),
    JsonError(serde_json::error::Error),
    KeyLength(usize),
    MissingAddressError,
    ParseError(nom::error::ErrorKind),
    ParsingIncomplete,
    SystemTimeError(std::time::SystemTimeError),
    TcpError(io::Error),
    VersionError(String, String),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind::*;
        let msg = match &self {
            Base64DecodeError(err) => format!("String failed to decode as base64, error was: {}", err),
            BufferNotCompletelyParsedError => "Something went wrong when parsing the received buffer. It still contains data after parsing is done.".to_string(),
            CanNotEncodeMessageWithoutCommand => "Can not encode messages that are missing CommandType".to_string(),
            CommandTypeMissing => "No CommandType was supplied in message".to_string(),
            CRCError => "Error: CRC mismatch".to_string(),
            DecryptionError(err) => format!("Decryption failed with: {}", err),
            EncryptionError(err) => format!("Encryption failed with: {}", err),
            JsonError(err) => format!("Json failed: {}", err),
            KeyLength(s) => format!("The key length is {}, should be 16", s),
            MissingAddressError => "The TuyaDevice is not created with a socket address. Can not set object.".to_string(),
            ParseError(err) => format!("Parsing failed with {}", err.description()),
            ParsingIncomplete => "Data was incomplete. Error while parsing the received data".to_string(),
            SystemTimeError(err) => format!("{}", err),
            TcpError(err) => format!("Could not write to TcpStream. Error: {}", err),
            VersionError(maj, min) => format!("The given version {}.{} is not valid", maj, min),
        };
        write!(f, "{}", msg)
    }
}

impl Error for ErrorKind {}
