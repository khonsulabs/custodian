//! Password configuration.

use std::num::NonZeroU32;

use argon2::{Algorithm, Argon2, Params, Version};
use deranged::U32;
use serde::{Deserialize, Serialize};

#[cfg(feature = "pbkdf2")]
use crate::cipher_suite::pbkdf2::Pbkdf2;
use crate::{
	cipher_suite::{CipherSuite, SlowHashParams},
	Error, Result,
};

/// Common password configuration between server and client.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Config {
	/// [`CipherSuite`] for this [`Config`].
	pub(crate) cipher_suite: CipherSuite,
	/// [`Mhf`] configuration.
	mhf: Mhf,
}

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

		match (group, hash, mhf) {
			(Ristretto255, Sha2, mhf @ Argon2(_)) => Self {
				cipher_suite: Ristretto255Sha512Argon2,
				mhf,
			},
			#[cfg(feature = "pbkdf2")]
			(Ristretto255, Sha2, mhf @ Pbkdf2(_)) => Self {
				cipher_suite: Ristretto255Sha512Pbkdf2,
				mhf,
			},
			#[cfg(feature = "sha3")]
			(Ristretto255, Sha3, mhf @ Argon2(_)) => Self {
				cipher_suite: Ristretto255Sha3_512Argon2,
				mhf,
			},
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			(Ristretto255, Sha3, mhf @ Pbkdf2(_)) => Self {
				cipher_suite: Ristretto255Sha3_512Pbkdf2,
				mhf,
			},
			#[cfg(feature = "blake3")]
			(Ristretto255, Blake3, mhf @ Argon2(_)) => Self {
				cipher_suite: Ristretto255Blake3Argon2,
				mhf,
			},
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			(Ristretto255, Blake3, mhf @ Pbkdf2(_)) => Self {
				cipher_suite: Ristretto255Blake3Pbkdf2,
				mhf,
			},
			#[cfg(feature = "p256")]
			(P256, Sha2, mhf @ Argon2(_)) => Self {
				cipher_suite: P256Sha256Argon2,
				mhf,
			},
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			(P256, Sha2, mhf @ Pbkdf2(_)) => Self {
				cipher_suite: P256Sha256Pbkdf2,
				mhf,
			},
			#[cfg(all(feature = "p256", feature = "sha3"))]
			(P256, Sha3, mhf @ Argon2(_)) => Self {
				cipher_suite: P256Sha3_256Argon2,
				mhf,
			},
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			(P256, Sha3, mhf @ Pbkdf2(_)) => Self {
				cipher_suite: P256Sha3_256Pbkdf2,
				mhf,
			},
			#[cfg(all(feature = "p256", feature = "blake3"))]
			(P256, Blake3, mhf @ Argon2(_)) => Self {
				cipher_suite: P256Blake3Argon2,
				mhf,
			},
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			(P256, Blake3, mhf @ Pbkdf2(_)) => Self {
				cipher_suite: P256Blake3Pbkdf2,
				mhf,
			},
		}
	}

	/// Returns [`Group`] of this [`Config`].
	#[must_use]
	pub const fn group(self) -> Group {
		#[allow(clippy::enum_glob_use)]
		use CipherSuite::*;

		#[allow(clippy::match_same_arms)]
		match self.cipher_suite {
			Ristretto255Sha512Argon2 => Group::Ristretto255,
			#[cfg(feature = "pbkdf2")]
			Ristretto255Sha512Pbkdf2 => Group::Ristretto255,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2 => Group::Ristretto255,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			Ristretto255Sha3_512Pbkdf2 => Group::Ristretto255,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2 => Group::Ristretto255,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			Ristretto255Blake3Pbkdf2 => Group::Ristretto255,
			#[cfg(feature = "p256")]
			P256Sha256Argon2 => Group::P256,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			P256Sha256Pbkdf2 => Group::P256,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2 => Group::P256,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			P256Sha3_256Pbkdf2 => Group::P256,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2 => Group::P256,
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
		match self.cipher_suite {
			Ristretto255Sha512Argon2 => Hash::Sha2,
			#[cfg(feature = "pbkdf2")]
			Ristretto255Sha512Pbkdf2 => Hash::Sha2,
			#[cfg(feature = "sha3")]
			Ristretto255Sha3_512Argon2 => Hash::Sha3,
			#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
			Ristretto255Sha3_512Pbkdf2 => Hash::Sha3,
			#[cfg(feature = "blake3")]
			Ristretto255Blake3Argon2 => Hash::Blake3,
			#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
			Ristretto255Blake3Pbkdf2 => Hash::Blake3,
			#[cfg(feature = "p256")]
			P256Sha256Argon2 => Hash::Sha2,
			#[cfg(all(feature = "p256", feature = "pbkdf2"))]
			P256Sha256Pbkdf2 => Hash::Sha2,
			#[cfg(all(feature = "p256", feature = "sha3"))]
			P256Sha3_256Argon2 => Hash::Sha3,
			#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
			P256Sha3_256Pbkdf2 => Hash::Sha3,
			#[cfg(all(feature = "p256", feature = "blake3"))]
			P256Blake3Argon2 => Hash::Blake3,
			#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
			P256Blake3Pbkdf2 => Hash::Blake3,
		}
	}

	/// Returns [`Mhf`] of this [`Config`].
	#[must_use]
	pub const fn mhf(self) -> Mhf {
		self.mhf
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
	/// Argon2.
	Argon2(Argon2Params),
	/// PBKDF2.
	#[cfg(feature = "pbkdf2")]
	Pbkdf2(Pbkdf2Params),
}

impl Default for Mhf {
	fn default() -> Self {
		Self::Argon2(Argon2Params::default())
	}
}

impl Mhf {
	/// Converts [`Mhf`] to [`SlowHashParams`].
	pub(crate) fn to_slow_hash(self) -> SlowHashParams {
		match self {
			Self::Argon2(config) => {
				let algorithm = match config.algorithm {
					Argon2Algorithm::Argon2id => Algorithm::Argon2id,
					Argon2Algorithm::Argon2d => Algorithm::Argon2d,
				};

				SlowHashParams::Argon2(Argon2::new(
					algorithm,
					Version::default(),
					Params::new(
						config.m_cost.get(),
						config.t_cost.get(),
						config.p_cost.get(),
						None,
					)
					.expect("unexpected parameter"),
				))
			}
			#[cfg(feature = "pbkdf2")]
			Self::Pbkdf2(config) => SlowHashParams::Pbkdf2(Pbkdf2(config)),
		}
	}
}

/// Configuration for [`Mhf::Argon2`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Argon2Params {
	/// Specific algorithm to use.
	pub algorithm: Argon2Algorithm,
	/// Number of memory blocks.
	pub m_cost: U32<{ Params::MIN_M_COST }, { Params::MAX_M_COST }>,
	/// Number of passes.
	pub t_cost: NonZeroU32,
	/// Number of threads.
	pub p_cost: U32<{ Params::MIN_P_COST }, { Params::MAX_P_COST }>,
}

#[test]
fn argon2_ranges() {
	assert_eq!(8, Params::MIN_M_COST);
	assert_eq!(0x0fff_ffff, Params::MAX_M_COST);
	assert_eq!(1, Params::MIN_T_COST);
	assert_eq!(0xffff_ffff, Params::MAX_T_COST);
	assert_eq!(1, Params::MIN_P_COST);
	assert_eq!(0x00ff_ffff, Params::MAX_P_COST);
}

impl Argon2Params {
	/// Construct a new [`Argon2Params`], checking for correct integer ranges.
	///
	/// # Errors
	/// [`Error::MhfConfig`] if `m_cost`, `t_cost` or `p_cost` are out of range:
	/// - `m_cost`: 8 - 0x0fffffff
	/// - `t_cost`: 1 - 0xffffffff
	/// - `p_cost`: 1 - 0x00ffffff
	pub fn new<
		A: Into<Option<Argon2Algorithm>>,
		M: Into<Option<u32>>,
		T: Into<Option<u32>>,
		P: Into<Option<u32>>,
	>(
		algorithm: A,
		m_cost: M,
		t_cost: T,
		p_cost: P,
	) -> Result<Self> {
		Ok(Self {
			algorithm: algorithm.into().unwrap_or_default(),
			m_cost: U32::new(m_cost.into().unwrap_or(Params::DEFAULT_M_COST))
				.ok_or(Error::MhfConfig)?,
			t_cost: NonZeroU32::new(t_cost.into().unwrap_or(Params::DEFAULT_T_COST))
				.ok_or(Error::MhfConfig)?,
			p_cost: U32::new(p_cost.into().unwrap_or(Params::DEFAULT_P_COST))
				.ok_or(Error::MhfConfig)?,
		})
	}
}

/// Specific algorithm to use for [`Argon2Params`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Argon2Algorithm {
	/// Argon2id algorithm. Slower then Argon2d, but resists side-channel
	/// attacks.
	Argon2id,
	/// Argon2d algorithm. Faster then Argon2id, but has no resistance against
	/// side-channel attacks.
	///
	/// # Caution
	/// Only use this when you trust your host, e.g. not a shared cloud
	/// instance.
	Argon2d,
}

impl Default for Argon2Params {
	fn default() -> Self {
		Self {
			algorithm: Argon2Algorithm::default(),
			m_cost: U32::new(Params::DEFAULT_M_COST).expect("unexpected cost"),
			t_cost: NonZeroU32::new(Params::DEFAULT_T_COST).expect("unexpected cost"),
			p_cost: U32::new(Params::DEFAULT_P_COST).expect("unexpected cost"),
		}
	}
}

impl Default for Argon2Algorithm {
	fn default() -> Self {
		Self::Argon2id
	}
}

/// Configuration for [`Mhf::Pbkdf2`].
#[cfg(feature = "pbkdf2")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Pbkdf2Params {
	/// Specific [hash](Pbkdf2Hash) to use with PBKDF2.
	pub hash: Pbkdf2Hash,
	/// Number of passes.
	pub rounds: NonZeroU32,
}

#[cfg(feature = "pbkdf2")]
impl Pbkdf2Params {
	/// Construct a new [`Pbkdf2Params`], checking for correct integer ranges.
	///
	/// # Errors
	/// [`Error::MhfConfig`] if `rounds` is `0`.
	pub fn new<H: Into<Option<Pbkdf2Hash>>, R: Into<Option<u32>>>(
		hash: H,
		rounds: R,
	) -> Result<Self> {
		Ok(Self {
			hash: hash.into().unwrap_or_default(),
			rounds: NonZeroU32::new(rounds.into().unwrap_or(10000)).ok_or(Error::MhfConfig)?,
		})
	}
}

/// Specific hash to use with PBKDF2.
#[cfg(feature = "pbkdf2")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Pbkdf2Hash {
	/// SHA-256.
	Sha256,
	/// SHA-512.
	Sha512,
}

#[cfg(feature = "pbkdf2")]
impl Default for Pbkdf2Params {
	fn default() -> Self {
		Self {
			hash: Pbkdf2Hash::default(),
			rounds: NonZeroU32::new(10000).expect("unexpected value"),
		}
	}
}

#[cfg(feature = "pbkdf2")]
impl Default for Pbkdf2Hash {
	fn default() -> Self {
		Self::Sha256
	}
}
