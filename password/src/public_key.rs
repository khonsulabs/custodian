//! See [`PublicKey`].

use opaque_ke::keypair;
use serde::{Deserialize, Serialize};

use crate::Config;

/// Public key, used to verify the server by the client. See
/// [`ClientRegistration::register()`](crate::ClientRegistration::register).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PublicKey {
	/// Common config.
	pub(crate) config: Config,
	/// Public key bytes.
	pub(crate) key: [u8; 32],
}

impl PublicKey {
	/// Returns the [`Config`] associated with this [`PublicKey`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Create a [`PublicKey`] from a [`opaque_ke::keypair::PublicKey`].
	pub(crate) fn new(config: Config, public_key: &keypair::PublicKey) -> Self {
		Self {
			config,
			key: Self::from_opaque(public_key),
		}
	}

	/// Create a `[u8; 32]` from a [`opaque_ke::keypair::PublicKey`].
	pub(crate) fn from_opaque(public_key: &keypair::PublicKey) -> [u8; 32] {
		let mut key = [0; 32];
		key.copy_from_slice(public_key);

		key
	}

	/// Returns [`true`] if `key` and [`opaque`](keypair::PublicKey) match.
	pub(crate) fn is_opaque(key: [u8; 32], opaque: &keypair::PublicKey) -> bool {
		key[..] == ***opaque
	}
}
