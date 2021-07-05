//! Password configuration.

use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;

/// Common password configuration between server and client.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Config(pub(crate) CipherSuite);

impl Default for Config {
	fn default() -> Self {
		Self::new(Hash::default(), SlowHash::default())
	}
}

impl Config {
	/// Builds new [`Config`].
	#[must_use]
	pub const fn new(hash: Hash, slow_hash: SlowHash) -> Self {
		#[allow(clippy::enum_glob_use)]
		use self::{CipherSuite::*, Hash::*, SlowHash::*};

		Self(match (hash, slow_hash) {
			(Sha512, Argon2id) => Curve25519Sha512Argon2id,
			(Sha512, Argon2d) => Curve25519Sha512Argon2d,
			#[cfg(feature = "sha3")]
			(Sha3_512, Argon2id) => Curve25519Sha3_512Argon2id,
			#[cfg(feature = "sha3")]
			(Sha3_512, Argon2d) => Curve25519Sha3_512Argon2d,
			#[cfg(feature = "blake3")]
			(Blake3, Argon2id) => Curve25519Blake3Argon2id,
			#[cfg(feature = "blake3")]
			(Blake3, Argon2d) => Curve25519Blake3Argon2d,
		})
	}

	/// Returns [`Hash`](self::Hash) of this [`Config`].
	#[must_use]
	pub const fn hash(self) -> Hash {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		match self.0 {
			Curve25519Sha512Argon2id | Curve25519Sha512Argon2d => Hash::Sha512,
			#[cfg(feature = "sha3")]
			Curve25519Sha3_512Argon2id | Curve25519Sha3_512Argon2d => Hash::Sha3_512,
			#[cfg(feature = "blake3")]
			Curve25519Blake3Argon2id | Curve25519Blake3Argon2d => Hash::Blake3,
		}
	}

	/// Returns [`SlowHash`] of this [`Config`].
	#[must_use]
	pub const fn slow_hash(self) -> SlowHash {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		#[allow(clippy::match_same_arms)]
		match self.0 {
			Curve25519Sha512Argon2id => SlowHash::Argon2id,
			Curve25519Sha512Argon2d => SlowHash::Argon2d,
			#[cfg(feature = "sha3")]
			Curve25519Sha3_512Argon2id => SlowHash::Argon2id,
			#[cfg(feature = "sha3")]
			Curve25519Sha3_512Argon2d => SlowHash::Argon2d,
			#[cfg(feature = "blake3")]
			Curve25519Blake3Argon2id => SlowHash::Argon2id,
			#[cfg(feature = "blake3")]
			Curve25519Blake3Argon2d => SlowHash::Argon2d,
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
	/// BLAKE3
	#[cfg(feature = "blake3")]
	Blake3,
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
