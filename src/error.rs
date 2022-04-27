use failure::{self, Context, Fail};
use std::fmt::{self, Display};
use std::io;
use grin_wallet_libwallet as libwallet;

/// MWixnet error definition
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

pub type Result<T> = std::result::Result<T, Error>;
pub type StdResult<T, E> = std::result::Result<T, E>;

#[derive(Clone, Debug, Eq, Fail, PartialEq)]
/// MWixnet error types
pub enum ErrorKind {
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
    /// Data wasn't in a consumable format
    #[fail(display = "CorruptedData")]
    CorruptedData,
    /// Error from grin's api crate
    #[fail(display = "GRIN API Error")]
    GrinApiError,
    /// Error from grin core
    #[fail(display = "grincore Error")]
    GrinCoreError,
    /// Error from grin-wallet's libwallet
    #[fail(display = "libwallet Error")]
    LibWalletError,
    /// Error from serde-json
    #[fail(display = "serde json Error")]
    SerdeJsonError,
    /// Error from invalid signature
    #[fail(display = "invalid signature Error")]
    InvalidSigError,
    /// Error while saving config
    #[fail(display = "save config Error")]
    SaveConfigError,
    /// Error while loading config
    #[fail(display = "load config Error")]
    LoadConfigError,
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

impl From<grin_core::ser::Error> for Error {
    fn from(_e: grin_core::ser::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::GrinCoreError),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn new(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
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

impl From<hmac::digest::InvalidLength> for Error {
    fn from(_error: hmac::digest::InvalidLength) -> Error {
        Error {
            inner: Context::new(ErrorKind::InvalidKeyLength),
        }
    }
}

impl From<grin_api::Error> for Error {
    fn from(_error: grin_api::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::GrinApiError),
        }
    }
}

impl From<grin_api::json_rpc::Error> for Error {
    fn from(_error: grin_api::json_rpc::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::GrinApiError),
        }
    }
}

impl From<grin_core::core::transaction::Error> for Error {
    fn from(_error: grin_core::core::transaction::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::GrinCoreError),
        }
    }
}

impl From<libwallet::Error> for Error {
    fn from(_error: libwallet::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::LibWalletError),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(_error: serde_json::Error) -> Error {
        Error {
            inner: Context::new(ErrorKind::SerdeJsonError),
        }
    }
}