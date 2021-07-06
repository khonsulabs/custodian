//! See [`ExportKey`].

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::Config;

/// Secret key derived from the users password on the client. The server has no
/// access to it! Can be used to encrypt data and store it safely at the server.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExportKey {
	/// [`Config`] this [`ExportKey`] was created with.
	config: Config,
	/// Key bytes.
	#[serde(with = "BigArray")]
	pub(crate) key: [u8; 64],
}

impl ExportKey {
	/// Create a [`ExportKey`] from a `[u8; 33]`.
	pub(crate) const fn new(config: Config, key: [u8; 64]) -> Self {
		Self { config, key }
	}
}
