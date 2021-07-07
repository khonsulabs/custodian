//! See [`PublicKeyExt`].

use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::keypair::PublicKey;

use super::p256::P256;

/// Utility trait to help convert and compare [`opaque_ke::keypair::PublicKey`]
/// to `[u8; 33]`.
pub(crate) trait PublicKeyExt {
	/// Convert [`opaque_ke::keypair::PublicKey`] to `[u8; 33]`.
	fn into_array(self) -> [u8; 33];

	/// Convert [`opaque_ke::keypair::PublicKey`] reference to `[u8; 33]`.
	fn to_array(&self) -> [u8; 33];

	/// Compare [`opaque_ke::keypair::PublicKey`] to `[u8; 33]`.
	fn is_array(&self, key: [u8; 33]) -> bool;
}

impl PublicKeyExt for PublicKey<RistrettoPoint> {
	fn into_array(self) -> [u8; 33] {
		Self::to_array(&self)
	}

	fn to_array(&self) -> [u8; 33] {
		let mut key = [0; 33];
		key[..32].copy_from_slice(self);

		key
	}

	fn is_array(&self, key: [u8; 33]) -> bool {
		&key[..32] == self.as_slice()
	}
}

#[cfg(feature = "p256")]
impl PublicKeyExt for PublicKey<P256> {
	fn into_array(self) -> [u8; 33] {
		(**self).into()
	}

	fn to_array(&self) -> [u8; 33] {
		AsRef::<[u8; 33]>::as_ref(&***self).to_owned()
	}

	fn is_array(&self, key: [u8; 33]) -> bool {
		key == self.as_slice()
	}
}
