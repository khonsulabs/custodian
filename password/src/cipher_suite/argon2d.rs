//! See [`Argon2d`].

use argon2::{Algorithm, Argon2, Params, Version};
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use opaque_ke::{errors::InternalError, hash::Hash, slow_hash::SlowHash};

/// Object implementing [`SlowHash`] for
/// [`Argon2d`](Algorithm::Argon2d).
pub(crate) struct Argon2d(Argon2<'static>);

impl Default for Argon2d {
	fn default() -> Self {
		Self(Argon2::new(
			Algorithm::Argon2d,
			Version::default(),
			Params::default(),
		))
	}
}

impl<D: Hash> SlowHash<D> for Argon2d {
	fn hash(
		&self,
		input: GenericArray<u8, <D as Digest>::OutputSize>,
	) -> Result<Vec<u8>, InternalError> {
		let mut output = vec![0; <D as Digest>::OutputSize::to_usize()];
		self.0.hash_password_into(&input, &[0; argon2::MIN_SALT_LEN], &mut output)
			.map_err(|_| InternalError::SlowHashError)?;
		Ok(output)
	}
}
