//! Password configuration.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cipher_suite::CipherSuite;

/// Common password configuration between server and client.
#[derive(
	Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Zeroize,
)]
pub struct Config(pub(crate) CipherSuite);

impl Default for Config {
	fn default() -> Self {
		Self::new(Group::default(), Hash::default(), Mhf::default())
	}
}

impl Config {
	/// Builds new [`Config`].
	#[must_use]
	pub const fn new(group: Group, hash: Hash, mhf: Mhf) -> Self {
		#[allow(clippy::enum_glob_use)]
		use self::{CipherSuite::*, Group::*, Hash::*, Mhf::*};

		Self(match (group, hash, mhf) {
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
	pub const fn crypto_hash(self) -> Hash {
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

	/// Returns [`Mhf`] of this [`Config`].
	#[must_use]
	pub const fn mhf(self) -> Mhf {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		#[allow(clippy::match_same_arms)]
		match self.0 {
			Ristretto255Sha512Argon2id => Mhf::Argon2id,
			Ristretto255Sha512Argon2d => Mhf::Argon2d,
			#[cfg(feature = "pbkdf2")]
			Ristretto255Sha512Pbkdf2 => Mhf::Pbkdf2,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2id => Mhf::Argon2id,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2d => Mhf::Argon2d,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			Ristretto255Sha3_512Pbkdf2 => Mhf::Pbkdf2,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2id => Mhf::Argon2id,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2d => Mhf::Argon2d,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			Ristretto255Blake3Pbkdf2 => Mhf::Pbkdf2,
			#[cfg(feature = "p256")]
			P256Sha256Argon2id => Mhf::Argon2id,
			#[cfg(feature = "p256")]
			P256Sha256Argon2d => Mhf::Argon2d,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			P256Sha256Pbkdf2 => Mhf::Pbkdf2,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2id => Mhf::Argon2id,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2d => Mhf::Argon2d,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			P256Sha3_256Pbkdf2 => Mhf::Pbkdf2,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2id => Mhf::Argon2id,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2d => Mhf::Argon2d,
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			P256Blake3Pbkdf2 => Mhf::Pbkdf2,
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
		#[cfg(feature = "blake3")]
		return Self::Blake3;
		#[cfg(all(not(feature = "blake3"), feature = "sha3"))]
		return Self::Sha3;
		#[cfg(all(not(feature = "blake3"), not(feature = "sha3")))]
		return Self::Sha2;
	}
}

/// Memory-hardening function for OPAQUE.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Mhf {
	/// Argon2id.
	Argon2id,
	/// Argon2d.
	Argon2d,
	/// PBKDF2-SHA256.
	#[cfg(feature = "pbkdf2")]
	Pbkdf2,
}

impl Default for Mhf {
	fn default() -> Self {
		Self::Argon2id
	}
}
