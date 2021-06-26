//! Password configuration.

use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;

/// Common password configuration between server and client.
#[derive(
	Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Config(pub(crate) CipherSuite);

impl PartialEq<CipherSuite> for Config {
	fn eq(&self, other: &CipherSuite) -> bool {
		&self.0 == other
	}
}

impl Config {
	/// Builds new default [`Config`].
	#[must_use]
	pub fn new() -> Self {
		Self(CipherSuite::default())
	}
}
