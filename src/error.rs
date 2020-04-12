use base64::DecodeError;
use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ErrorKind {
    KeyLength(usize),
    VersionError(String, String),
    EncryptionError(ErrorStack),
    Base64DecodeError(DecodeError),
    DecryptionError(ErrorStack),
    ParseError(nom::error::ErrorKind),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind::*;
        let msg = match &self {
            KeyLength(s) => format!("The key length is {}, should be 16", s),
            VersionError(maj, min) => format!("The given version {}.{} is not valid", maj, min),
            EncryptionError(err) => format!("Encryption failed with: {}", err),
            Base64DecodeError(err) => {
                format!("String failed to decode as base64, error was: {}", err)
            }
            DecryptionError(err) => format!("Decryption failed with: {}", err),
            ParseError(err) => format!("Parsing failed with {}", err.description()),
        };
        write!(f, "{}", msg)
    }
}

impl Error for ErrorKind {}
