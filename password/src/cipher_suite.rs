//! OPAQUE cipher suite.

use argon2::Argon2;
use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::{ciphersuite, key_exchange::tripledh::TripleDH};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

/// Type implementing [`CipherSuite`](ciphersuite::CipherSuite) to prevent
/// exposing it publicly.
#[derive(
	Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub(crate) struct CipherSuite;

impl ciphersuite::CipherSuite for CipherSuite {
	type Group = RistrettoPoint;
	type Hash = Sha512;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2<'static>;
}
