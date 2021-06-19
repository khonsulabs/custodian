//! OPAQUE cipher suite.

use argon2::Algorithm;
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::{typenum::Unsigned, GenericArray};
use opaque_ke::{
	ciphersuite, errors::InternalPakeError, hash::Hash, key_exchange::tripledh::TripleDH,
	slow_hash::SlowHash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Type implementing [`CipherSuite`](ciphersuite::CipherSuite) to prevent
/// exposing it publicly.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct CipherSuite;

impl ciphersuite::CipherSuite for CipherSuite {
	type Group = RistrettoPoint;
	type Hash = Sha512;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2;
}

/// Type implementing [`CipherSuite`](ciphersuite::CipherSuite) because
/// [`opaque_ke`] doesn't.
pub(crate) struct Argon2;

impl<D: Hash> SlowHash<D> for Argon2 {
	fn hash(
		input: GenericArray<u8, <D as Digest>::OutputSize>,
	) -> Result<Vec<u8>, InternalPakeError> {
		let params = argon2::Argon2::default();
		let mut output = vec![0; <D as Digest>::OutputSize::to_usize()];
		params
			.hash_password_into(
				Algorithm::Argon2i,
				&input,
				&[0; argon2::MIN_SALT_LENGTH],
				&[],
				&mut output,
			)
			.map_err(|_| InternalPakeError::SlowHashError)?;
		Ok(output)
	}
}
