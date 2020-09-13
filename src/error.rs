use base64::DecodeError;
use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt;

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
    ParseError(nom::error::ErrorKind),
    ParsingIncomplete,
    SystemTimeError(std::time::SystemTimeError),
    VersionError(String, String),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind::*;
        let msg = match &self {
            Base64DecodeError(err) => format!("String failed to decode as base64, error was: {}", err),
            BufferNotCompletelyParsedError => format!("Something went wrong when parsing the received buffer. It still contains data after parsing is done."),
            CanNotEncodeMessageWithoutCommand => format!("Can not encode messages that are missing CommandType"),
            CommandTypeMissing => format!("No CommandType was supplied in message"),
            CRCError => format!("Error: CRC mismatch"),
            DecryptionError(err) => format!("Decryption failed with: {}", err),
            EncryptionError(err) => format!("Encryption failed with: {}", err),
            JsonError(err) => format!("Json failed: {}", err),
            KeyLength(s) => format!("The key length is {}, should be 16", s),
            ParseError(err) => format!("Parsing failed with {}", err.description()),
            ParsingIncomplete => format!("Data was incomplete. Error while parsing the received data"),
            SystemTimeError(err) => format!("{}", err),
            VersionError(maj, min) => format!("The given version {}.{} is not valid", maj, min),
        };
        write!(f, "{}", msg)
    }
}

impl Error for ErrorKind {}
