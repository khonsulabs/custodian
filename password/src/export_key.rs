//! See [`ExportKey`].

use std::ops::Deref;

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Secret key derived from the users password on the client. The server has no
/// access to it! Can be used to encrypt data and store it safely at the server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct ExportKey(ArrayVec<u8, 64>);

impl ExportKey {
	/// Create a [`ExportKey`] from a `[u8; 64]`.
	pub(crate) const fn new(key: ArrayVec<u8, 64>) -> Self {
		Self(key)
	}

	/// Returns an [`ArrayVec`] of this key.
	#[must_use]
	pub const fn as_bytes(&self) -> &ArrayVec<u8, 64> {
		&self.0
	}
}

impl AsRef<ArrayVec<u8, 64>> for ExportKey {
	fn as_ref(&self) -> &ArrayVec<u8, 64> {
		self.as_bytes()
	}
}

impl Deref for ExportKey {
	type Target = ArrayVec<u8, 64>;

	fn deref(&self) -> &Self::Target {
		self.as_bytes()
	}
}
