use failure::{self, Context, Fail};
use std::fmt::{self, Display};

/// MWixnet error definition
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

pub type Result<T> = std::result::Result<T, Error>;

/// MWixnet error types
#[derive(Debug, Fail)]
pub enum ErrorKind {
	/// Wallet error
	#[fail(display = "wallet error: {}", _0)]
	WalletError(crate::wallet::WalletError),
	/// Wallet error
	#[fail(display = "node error: {}", _0)]
	NodeError(crate::node::NodeError),
}

impl std::error::Error for Error {}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl From<crate::wallet::WalletError> for Error {
	fn from(e: crate::wallet::WalletError) -> Error {
		Error {
			inner: Context::new(ErrorKind::WalletError(e)),
		}
	}
}

impl From<crate::node::NodeError> for Error {
	fn from(e: crate::node::NodeError) -> Error {
		Error {
			inner: Context::new(ErrorKind::NodeError(e)),
		}
	}
}
