//! See [`PublicKey`].

use std::ops::Deref;

use opaque_ke::keypair;
use serde::{Deserialize, Serialize};

/// Public key, used to verify the server by the client. See
/// [`ClientRegistration::register()`](crate::ClientRegistration::register).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PublicKey([u8; 32]);

impl Deref for PublicKey {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl PublicKey {
	/// Create a [`PublicKey`] from a [`opaque_ke::keypair::PublicKey`].
	pub(crate) fn from_opaque(opaque: &keypair::PublicKey) -> Self {
		let mut public_key = [0; 32];
		public_key.copy_from_slice(opaque);

		Self(public_key)
	}

	/// Returns [`true`] if [`self`] and [`opaque`](keypair::PublicKey) match.
	pub(crate) fn is_opaque(self, opaque: &keypair::PublicKey) -> bool {
		*self == ***opaque
	}
}
