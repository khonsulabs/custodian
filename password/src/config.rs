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
	/// Builds new [`Config`].
	#[must_use]
	pub const fn new(slow_hash: SlowHash) -> Self {
		Self(match slow_hash {
			SlowHash::Argon2id => CipherSuite::Curve25519Sha512Argon2id,
			SlowHash::Argon2d => CipherSuite::Curve25519Sha512Argon2d,
		})
	}

	/// Returns [`SlowHash`] of this [`Config`].
	#[must_use]
	pub const fn slow_hash(self) -> SlowHash {
		match self.0 {
			CipherSuite::Curve25519Sha512Argon2id => SlowHash::Argon2id,
			CipherSuite::Curve25519Sha512Argon2d => SlowHash::Argon2d,
		}
	}
}

/// Slow hash algorithm for OPAQUE.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SlowHash {
	/// Argon2id.
	Argon2id,
	/// Argon2d.
	Argon2d,
}

impl Default for SlowHash {
	fn default() -> Self {
		Self::Argon2id
	}
}
