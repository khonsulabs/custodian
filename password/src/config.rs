//! Password configuration.

use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;

/// Common password configuration between server and client.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Config(pub(crate) CipherSuite);

impl Default for Config {
	fn default() -> Self {
		Self::new(Group::default(), Hash::default(), SlowHash::default())
	}
}

impl Config {
	/// Builds new [`Config`].
	#[must_use]
	pub const fn new(group: Group, hash: Hash, slow_hash: SlowHash) -> Self {
		#[allow(clippy::enum_glob_use)]
		use self::{CipherSuite::*, Group::*, Hash::*, SlowHash::*};

		Self(match (group, hash, slow_hash) {
			(Ristretto255, Sha2, Argon2id) => Ristretto255Sha512Argon2id,
			(Ristretto255, Sha2, Argon2d) => Ristretto255Sha512Argon2d,
			#[cfg(feature = "pbkdf2")]
			(Ristretto255, Sha2, Pbkdf2) => Ristretto255Sha512Pbkdf2,
			#[cfg(feature = "sha3")]
			(Ristretto255, Sha3, Argon2id) => Ristretto255Sha3_512Argon2id,
			#[cfg(feature = "sha3")]
			(Ristretto255, Sha3, Argon2d) => Ristretto255Sha3_512Argon2d,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			(Ristretto255, Sha3, Pbkdf2) => Ristretto255Sha3_512Pbkdf2,
			#[cfg(feature = "blake3")]
			(Ristretto255, Blake3, Argon2id) => Ristretto255Blake3Argon2id,
			#[cfg(feature = "blake3")]
			(Ristretto255, Blake3, Argon2d) => Ristretto255Blake3Argon2d,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			(Ristretto255, Blake3, Pbkdf2) => Ristretto255Blake3Pbkdf2,
			#[cfg(feature = "p256")]
			(P256, Sha2, Argon2id) => P256Sha256Argon2id,
			#[cfg(feature = "p256")]
			(P256, Sha2, Argon2d) => P256Sha256Argon2d,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			(P256, Sha2, Pbkdf2) => P256Sha256Pbkdf2,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			(P256, Sha3, Argon2id) => P256Sha3_256Argon2id,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			(P256, Sha3, Argon2d) => P256Sha3_256Argon2d,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			(P256, Sha3, Pbkdf2) => P256Sha3_256Pbkdf2,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			(P256, Blake3, Argon2id) => P256Blake3Argon2id,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			(P256, Blake3, Argon2d) => P256Blake3Argon2d,
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			(P256, Blake3, Pbkdf2) => P256Blake3Pbkdf2,
		})
	}

	/// Returns [`Group`] of this [`Config`].
	#[must_use]
	pub const fn group(self) -> Group {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		#[allow(clippy::match_same_arms)]
		match self.0 {
			Ristretto255Sha512Argon2id | Ristretto255Sha512Argon2d => Group::Ristretto255,
			#[cfg(feature = "pbkdf2")]
			Ristretto255Sha512Pbkdf2 => Group::Ristretto255,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2id | Ristretto255Sha3_512Argon2d => Group::Ristretto255,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			Ristretto255Sha3_512Pbkdf2 => Group::Ristretto255,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2id | Ristretto255Blake3Argon2d => Group::Ristretto255,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			Ristretto255Blake3Pbkdf2 => Group::Ristretto255,
			#[cfg(feature = "p256")]
			P256Sha256Argon2id | P256Sha256Argon2d => Group::P256,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			P256Sha256Pbkdf2 => Group::P256,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2id | P256Sha3_256Argon2d => Group::P256,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			P256Sha3_256Pbkdf2 => Group::P256,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2id | P256Blake3Argon2d => Group::P256,
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			P256Blake3Pbkdf2 => Group::P256,
		}
	}

	/// Returns [`Hash`](self::Hash) of this [`Config`].
	#[must_use]
	pub const fn hash(self) -> Hash {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		#[allow(clippy::match_same_arms)]
		match self.0 {
			Ristretto255Sha512Argon2id | Ristretto255Sha512Argon2d => Hash::Sha2,
			#[cfg(feature = "pbkdf2")]
			Ristretto255Sha512Pbkdf2 => Hash::Sha2,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2id | Ristretto255Sha3_512Argon2d => Hash::Sha3,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			Ristretto255Sha3_512Pbkdf2 => Hash::Sha3,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2id | Ristretto255Blake3Argon2d => Hash::Blake3,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			Ristretto255Blake3Pbkdf2 => Hash::Blake3,
			#[cfg(feature = "p256")]
			P256Sha256Argon2id | P256Sha256Argon2d => Hash::Sha2,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			P256Sha256Pbkdf2 => Hash::Sha2,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2id | P256Sha3_256Argon2d => Hash::Sha3,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			P256Sha3_256Pbkdf2 => Hash::Sha3,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2id | P256Blake3Argon2d => Hash::Blake3,
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			P256Blake3Pbkdf2 => Hash::Blake3,
		}
	}

	/// Returns [`SlowHash`] of this [`Config`].
	#[must_use]
	pub const fn slow_hash(self) -> SlowHash {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		#[allow(clippy::match_same_arms)]
		match self.0 {
			Ristretto255Sha512Argon2id => SlowHash::Argon2id,
			Ristretto255Sha512Argon2d => SlowHash::Argon2d,
			#[cfg(feature = "pbkdf2")]
			Ristretto255Sha512Pbkdf2 => SlowHash::Pbkdf2,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2id => SlowHash::Argon2id,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2d => SlowHash::Argon2d,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			Ristretto255Sha3_512Pbkdf2 => SlowHash::Pbkdf2,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2id => SlowHash::Argon2id,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2d => SlowHash::Argon2d,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			Ristretto255Blake3Pbkdf2 => SlowHash::Pbkdf2,
			#[cfg(feature = "p256")]
			P256Sha256Argon2id => SlowHash::Argon2id,
			#[cfg(feature = "p256")]
			P256Sha256Argon2d => SlowHash::Argon2d,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			P256Sha256Pbkdf2 => SlowHash::Pbkdf2,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2id => SlowHash::Argon2id,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2d => SlowHash::Argon2d,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			P256Sha3_256Pbkdf2 => SlowHash::Pbkdf2,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2id => SlowHash::Argon2id,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2d => SlowHash::Argon2d,
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			P256Blake3Pbkdf2 => SlowHash::Pbkdf2,
		}
	}
}

/// Prime-order group algorithm for OPAQUE.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Group {
	/// Ristretto255, uses SHA-512 or SHA3-512 respectively.
	Ristretto255,
	/// P256, uses SHA-256 or SHA3-256 respectively.
	#[cfg(feature = "p256")]
	P256,
}

impl Default for Group {
	fn default() -> Self {
		Self::Ristretto255
	}
}

/// Hash algorithm for OPAQUE.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Hash {
	/// SHA-2, size depends on selected [`Group`].
	Sha2,
	/// SHA-3, size depends on selected [`Group`].
	#[cfg(feature = "sha3")]
	Sha3,
	/// BLAKE3.
	#[cfg(feature = "blake3")]
	Blake3,
}

impl Default for Hash {
	fn default() -> Self {
		#[cfg(feature = "sha3")]
		return Self::Sha3;
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
	/// PBKDF2-SHA256.
	#[cfg(feature = "pbkdf2")]
	Pbkdf2,
}

impl Default for SlowHash {
	fn default() -> Self {
		Self::Argon2id
	}
}
