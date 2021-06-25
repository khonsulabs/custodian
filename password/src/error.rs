#![allow(clippy::module_name_repetitions)]

//! See [`Error`](enum@Error). Also re-exports [`InternalPakeError`],
//! [`PakeError`] and [`ProtocolError`].

pub use opaque_ke::errors::{InternalPakeError, PakeError, ProtocolError};
use thiserror::Error;

/// [`Result`](std::result::Result) for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error`](std::error::Error) type for this crate.
#[derive(Clone, Debug, Error, Eq, Hash, PartialEq)]
pub enum Error {
	/// Internal OPAQUE error.
	#[error("Iternal Opaque error: {0}")]
	Opaque(#[from] ProtocolError),
	/// Servers public key didn't match expected one.
	#[error("Servers identity unexpected")]
	InvalidServer,
	/// [`Config`](crate::Config) doesn't match.
	#[error("Configuration doesn't match")]
	Config,
	/// [`PublicKey`](crate::PublicKey) in [`ClientConfig`](crate::ClientConfig)
	/// and [`ClientFile`](crate::ClientFile) don't match.
	#[error("Public keys don't match")]
	PublicKey,
	/// Credentials don't match.
	#[error("Credentials don't match")]
	Credentials,
}
