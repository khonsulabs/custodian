//! See [`PublicKey`].

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::Config;

/// Public key, used to verify the server by the client. See
/// [`ClientRegistration::register()`](crate::ClientRegistration::register).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PublicKey {
	/// [`Config`] this [`PublicKey`] was created with.
	pub(crate) config: Config,
	/// Public key bytes.
	#[serde(with = "BigArray")]
	pub(crate) key: [u8; 33],
}

impl PublicKey {
	/// Create a [`PublicKey`] from a `[u8; 33]`.
	pub(crate) const fn new(config: Config, key: [u8; 33]) -> Self {
		Self { config, key }
	}

	/// Returns the [`Config`] associated with this [`PublicKey`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}
