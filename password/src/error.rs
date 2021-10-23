#![allow(clippy::module_name_repetitions)]

//! See [`Error`](enum@Error). Also re-exports [`InternalError`] and
//! [`ProtocolError`].

pub use opaque_ke::errors::{InternalError, ProtocolError};
use thiserror::Error;

/// [`Result`](std::result::Result) for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error`](std::error::Error) type for this crate.
#[derive(Clone, Debug, Error, Eq, Hash, PartialEq)]
pub enum Error {
	/// Internal OPAQUE error.
	#[error("Internal Opaque error: {0}")]
	Opaque(#[from] ProtocolError),
	/// Servers public key didn't match expected one.
	#[error("Servers identity unexpected")]
	InvalidServer,
	/// Failed to construct [`Mhf`](crate::Mhf) because out-of-range integers.
	#[error("Integers used are out-of-range")]
	MhfConfig,
	/// [`Config`](crate::Config) doesn't match.
	#[error("Configuration doesn't match")]
	Config,
	/// [`PublicKey`](crate::PublicKey) in [`ClientConfig`](crate::ClientConfig)
	/// and [`ClientFile`](crate::ClientFile) don't match.
	#[error("Public keys don't match")]
	ConfigPublicKey,
	/// Credentials don't match.
	#[error("Credentials don't match")]
	Credentials,
	/// [`ServerFile`](crate::ServerFile) was not created with the same
	/// [`ServerConfig`](crate::ServerConfig).
	#[error("Server file was not created with the same server configuration")]
	ServerFile,
}
