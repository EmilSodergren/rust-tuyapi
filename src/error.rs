use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ErrorKind {
    KeyLength(usize),
    VersionError(String, String),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind::*;
        let msg = match &self {
            KeyLength(s) => format!("The key length is {}, should be 16", s),
            VersionError(maj, min) => format!("The given version {}.{} is not valid", maj, min),
        };
        write!(f, "{}", msg)
    }
}

impl Error for ErrorKind {}
