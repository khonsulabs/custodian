//! See [`Argon2d`].

use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use opaque_ke::{errors::InternalPakeError, hash::Hash, slow_hash::SlowHash};

/// Object implementing [`SlowHash`] for
/// [`Argon2d`](argon2::Algorithm::Argon2d).
pub(crate) struct Argon2d;

impl<D: Hash> SlowHash<D> for Argon2d {
	fn hash(
		input: GenericArray<u8, <D as Digest>::OutputSize>,
	) -> Result<Vec<u8>, InternalPakeError> {
		let params = argon2::Argon2::default();
		let mut output = vec![0; <D as Digest>::OutputSize::to_usize()];
		params
			.hash_password_into(
				argon2::Algorithm::Argon2d,
				&input,
				&[0; argon2::MIN_SALT_LENGTH],
				&[],
				&mut output,
			)
			.map_err(|_| InternalPakeError::SlowHashError)?;
		Ok(output)
	}
}
