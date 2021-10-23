//! See [`Pbkdf2`].

use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use hmac::Hmac;
use opaque_ke::{errors::InternalError, slow_hash::SlowHash};
use sha2::{Sha256, Sha512};

use crate::config::{Pbkdf2Hash, Pbkdf2Params};

/// Object implementing [`SlowHash`] for [PBKDF2](pbkdf2_).
#[derive(Default)]
pub(crate) struct Pbkdf2(pub(crate) Pbkdf2Params);

impl<D: opaque_ke::hash::Hash> SlowHash<D> for Pbkdf2 {
	fn hash(
		&self,
		input: GenericArray<u8, <D as Digest>::OutputSize>,
	) -> Result<Vec<u8>, InternalError> {
		let mut output = vec![0; <D as Digest>::OutputSize::to_usize()];

		let pbkdf2 = match self.0.hash {
			Pbkdf2Hash::Sha256 => pbkdf2_::pbkdf2::<Hmac<Sha256>>,
			Pbkdf2Hash::Sha512 => pbkdf2_::pbkdf2::<Hmac<Sha512>>,
		};

		pbkdf2(&input, &[], self.0.rounds.get(), &mut output);
		Ok(output)
	}
}
