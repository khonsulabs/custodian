//! See [`PublicKeyExt`].

use opaque_ke::keypair::PublicKey;

/// Utility traits to help convert and compare [`opaque_ke::keypair::PublicKey`]
/// to `[u8; 33]`.
pub(crate) trait PublicKeyExt {
	/// Convert [`opaque_ke::keypair::PublicKey`] to `[u8; 33]`.
	fn to_array(&self) -> [u8; 33];

	/// Compare [`opaque_ke::keypair::PublicKey`] to `[u8; 33]`.
	fn is_array(&self, key: [u8; 33]) -> bool;
}

impl<G> PublicKeyExt for PublicKey<G> {
	fn to_array(&self) -> [u8; 33] {
		let mut key = [0; 33];
		key.get_mut(..self.len())
			.expect("unexpected public key length")
			.copy_from_slice(self);

		key
	}

	fn is_array(&self, key: [u8; 33]) -> bool {
		key.get(..self.len()).map_or(false, |key| key == ***self)
	}
}
