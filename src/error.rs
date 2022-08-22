use failure::{self, Context, Fail};
use grin_wallet_libwallet as libwallet;
use std::fmt::{self, Display};
use std::io;

/// MWixnet error definition
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

pub type Result<T> = std::result::Result<T, Error>;

/// MWixnet error types
#[derive(Debug, Fail)]
pub enum ErrorKind {
	/// Error from secp256k1-zkp library
	#[fail(display = "Secp Error")]
	SecpError,
	/// Wraps an io error produced when reading or writing
	#[fail(display = "IO Error: {}", _0)]
	IOErr(String, io::ErrorKind),
	/// Error from grin's api crate
	#[fail(display = "GRIN API Error: {}", _0)]
	GrinApiError(String),
	/// Error from grin core
	#[fail(display = "GRIN Core Error: {}", _0)]
	GrinCoreError(String),
	/// Error from grin-wallet's libwallet
	#[fail(display = "libwallet error: {}", _0)]
	LibWalletError(String),
	/// Error from serde-json
	#[fail(display = "serde json error: {}", _0)]
	SerdeJsonError(String),
	/// Error from invalid signature
	#[fail(display = "invalid signature")]
	InvalidSigError,
	/// Wallet error
	#[fail(display = "wallet error: {}", _0)]
	WalletError(crate::wallet::WalletError),
}

impl std::error::Error for Error {}

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
	fn from(e: grin_core::ser::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::GrinCoreError(e.to_string())),
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

impl From<grin_api::Error> for Error {
	fn from(e: grin_api::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::GrinApiError(e.to_string())),
		}
	}
}

impl From<grin_api::json_rpc::Error> for Error {
	fn from(e: grin_api::json_rpc::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::GrinApiError(e.to_string())),
		}
	}
}

impl From<grin_core::core::transaction::Error> for Error {
	fn from(e: grin_core::core::transaction::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::GrinCoreError(e.to_string())),
		}
	}
}

impl From<libwallet::Error> for Error {
	fn from(e: libwallet::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibWalletError(e.to_string())),
		}
	}
}

impl From<serde_json::Error> for Error {
	fn from(e: serde_json::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::SerdeJsonError(e.to_string())),
		}
	}
}

impl From<crate::wallet::WalletError> for Error {
	fn from(e: crate::wallet::WalletError) -> Error {
		Error {
			inner: Context::new(ErrorKind::WalletError(e)),
		}
	}
}
