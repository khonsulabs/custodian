//! Password configuration.

use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;

/// Common password configuration between server and client.
#[derive(
	Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Config {
	/// Inner type implementing
	/// [`CipherSuite`](opaque_ke::ciphersuite::CipherSuite) to prevent exposing
	/// it publicly.
	cipher_suite: CipherSuite,
}

impl Config {
	/// Builds new default [`Config`].
	#[must_use]
	pub const fn new() -> Self {
		Self {
			cipher_suite: CipherSuite,
		}
	}
}
