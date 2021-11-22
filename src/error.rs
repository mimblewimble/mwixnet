use failure::{self, Context, Fail};
use std::fmt::{self, Display};
use std::io;

/// MWixnet error definition
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, Fail, PartialEq)]
/// MWixnet error types
pub enum ErrorKind {
    /// Unsupported payload version
    #[fail(display = "Unsupported Payload Version")]
    UnsupportedPayload,
    /// Error from secp256k1-zkp library
    #[fail(display = "Secp Error")]
    SecpError,
    /// Invalid key length for MAC initialization
    #[fail(display = "InvalidKeyLength")]
    InvalidKeyLength,
    /// Wraps an io error produced when reading or writing
    #[fail(display = "IOError")]
    IOErr(
        String,
        io::ErrorKind,
    ),
    /// Expected a given value that wasn't found
    #[fail(display = "UnexpectedData")]
    UnexpectedData {
        /// What we wanted
        expected: Vec<u8>,
        /// What we got
        received: Vec<u8>,
    },
    /// Data wasn't in a consumable format
    #[fail(display = "CorruptedData")]
    CorruptedData,
    /// Incorrect number of elements (when deserializing a vec via read_multi say).
    #[fail(display = "CountError")]
    CountError,
    /// When asked to read too much data
    #[fail(display = "TooLargeReadErr")]
    TooLargeReadErr,
}

impl std::error::Error for Error {
    
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        ErrorKind::IOErr(format!("{}", e), e.kind()).into()
    }
}

impl From<io::ErrorKind> for Error {
    fn from(e: io::ErrorKind) -> Error {
        ErrorKind::IOErr(format!("{}", io::Error::from(e)), e).into()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.inner.get_context().clone()
    }

    pub fn message(&self) -> String {
        format!("{}", self).into()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl From<secp256k1zkp::Error> for Error {
    fn from(_error: secp256k1zkp::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::SecpError),
        }
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for Error {
    fn from(_error: hmac::crypto_mac::InvalidKeyLength) -> Error {
        Error {
            inner: Context::new(ErrorKind::InvalidKeyLength),
        }
    }
}