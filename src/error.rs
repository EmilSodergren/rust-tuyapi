use failure::{Backtrace, Context, Fail};
use std::fmt;

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl From<ErrorKind> for Error {
    fn from(err: ErrorKind) -> Error {
        Error {
            inner: Context::new(err),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(ctx: Context<ErrorKind>) -> Error {
        Error { inner: ctx }
    }
}

#[derive(Fail, Debug)]
pub enum ErrorKind {
    #[fail(display = "wrong key lenght {}, should be 16", _0)]
    KeyLength(usize),
    #[fail(
        display = "could not parse Version string. \'{}.{}\' is not a known TuyaVersion.",
        _0, _1
    )]
    VersionError(String, String),
    #[fail(display = "bad prefix in package")]
    BadPackagePrefix,
    #[fail(display = "bad sequence number in package")]
    BadPackageSeqNr,
    #[fail(display = "bad command type in package")]
    BadCommandType,
    #[fail(display = "bad length in package")]
    BadPackageLength,
    #[fail(display = "could not read payload, length should be {}", _0)]
    BadPayload(usize),
    #[fail(display = "bad suffix in package")]
    BadPackageSuffix,
    #[doc(hidden)]
    #[fail(display = "")]
    __Nonexhaustive,
}
