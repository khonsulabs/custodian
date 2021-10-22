//! See [`Pbkdf2`].

use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use hmac::Hmac;
use opaque_ke::{errors::InternalError, hash::Hash, slow_hash::SlowHash};
use sha2::Sha256;

/// Object implementing [`SlowHash`] for PBKDF2.
#[derive(Default)]
pub(crate) struct Pbkdf2;

impl<D: Hash> SlowHash<D> for Pbkdf2 {
	fn hash(
		&self,
		input: GenericArray<u8, <D as Digest>::OutputSize>,
	) -> Result<Vec<u8>, InternalError> {
		let mut output = vec![0; <D as Digest>::OutputSize::to_usize()];
		pbkdf2_::pbkdf2::<Hmac<Sha256>>(&input, &[], 10_000, &mut output);
		Ok(output)
	}
}
