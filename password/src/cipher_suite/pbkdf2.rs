//! See [`Pbkdf2`].

use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use hmac::Hmac;
use opaque_ke::{errors::InternalError, slow_hash::SlowHash};
use sha2::{Sha256, Sha512};

/// Hash algorithm to use with [`Pbkdf2`].
pub enum Hash {
	/// SHA-256.
	Sha256,
	/// SHA-512.
	Sha512,
}

impl Default for Hash {
	fn default() -> Self {
		Self::Sha256
	}
}

/// Object implementing [`SlowHash`] for PBKDF2.
pub(crate) struct Pbkdf2 {
	/// [`Hash`] to use with [`Pbkdf2`].
	hash: Hash,
	/// "rounds" parameter for [`Pbkdf2`].
	rounds: u32,
}

impl Default for Pbkdf2 {
	fn default() -> Self {
		Self {
			hash: Hash::default(),
			rounds: 10000,
		}
	}
}

impl<D: opaque_ke::hash::Hash> SlowHash<D> for Pbkdf2 {
	fn hash(
		&self,
		input: GenericArray<u8, <D as Digest>::OutputSize>,
	) -> Result<Vec<u8>, InternalError> {
		let mut output = vec![0; <D as Digest>::OutputSize::to_usize()];

		let pbkdf2 = match self.hash {
			Hash::Sha256 => pbkdf2_::pbkdf2::<Hmac<Sha256>>,
			Hash::Sha512 => pbkdf2_::pbkdf2::<Hmac<Sha512>>,
		};

		pbkdf2(&input, &[], self.rounds, &mut output);
		Ok(output)
	}
}
