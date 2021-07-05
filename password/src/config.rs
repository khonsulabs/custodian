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
	pub const fn new(hash: Hash, slow_hash: SlowHash) -> Self {
		Self(match (hash, slow_hash) {
			(Hash::Sha512, SlowHash::Argon2id) => CipherSuite::Curve25519Sha512Argon2id,
			(Hash::Sha512, SlowHash::Argon2d) => CipherSuite::Curve25519Sha512Argon2d,
			#[cfg(feature = "sha3")]
			(Hash::Sha3_512, SlowHash::Argon2id) => CipherSuite::Curve25519Sha3_512Argon2id,
			#[cfg(feature = "sha3")]
			(Hash::Sha3_512, SlowHash::Argon2d) => CipherSuite::Curve25519Sha3_512Argon2d,
		})
	}

	/// Returns [`Hash`] of this [`Config`].
	#[must_use]
	pub const fn hash(self) -> Hash {
		#[allow(clippy::match_same_arms)]
		match self.0 {
			CipherSuite::Curve25519Sha512Argon2id => Hash::Sha512,
			CipherSuite::Curve25519Sha512Argon2d => Hash::Sha512,
			#[cfg(feature = "sha3")]
			CipherSuite::Curve25519Sha3_512Argon2id => Hash::Sha3_512,
			#[cfg(feature = "sha3")]
			CipherSuite::Curve25519Sha3_512Argon2d => Hash::Sha3_512,
		}
	}

	/// Returns [`SlowHash`] of this [`Config`].
	#[must_use]
	pub const fn slow_hash(self) -> SlowHash {
		#[allow(clippy::match_same_arms)]
		match self.0 {
			CipherSuite::Curve25519Sha512Argon2id => SlowHash::Argon2id,
			CipherSuite::Curve25519Sha512Argon2d => SlowHash::Argon2d,
			#[cfg(feature = "sha3")]
			CipherSuite::Curve25519Sha3_512Argon2id => SlowHash::Argon2id,
			#[cfg(feature = "sha3")]
			CipherSuite::Curve25519Sha3_512Argon2d => SlowHash::Argon2d,
		}
	}
}

/// Hash algorithm for OPAQUE.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Hash {
	/// SHA-512.
	Sha512,
	/// SHA3-512
	#[cfg(feature = "sha3")]
	Sha3_512,
}

impl Default for Hash {
	fn default() -> Self {
		#[cfg(feature = "sha3")]
		return Self::Sha3_512;
		#[cfg(not(feature = "sha3"))]
		Self::Sha512
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
