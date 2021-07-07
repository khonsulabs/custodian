//! See [`ExportKeyExt`].

use generic_array::{
	typenum::{U32, U64},
	GenericArray,
};

/// Utility trait to help convert export key to `[u8; 64]`.
pub(crate) trait ExportKeyExt {
	/// Convert export key to `[u8; 64]`.
	fn into_array(self) -> [u8; 64];
}

impl ExportKeyExt for GenericArray<u8, U32> {
	fn into_array(self) -> [u8; 64] {
		let mut key = [0; 64];
		key[..32].copy_from_slice(&self);

		key
	}
}

impl ExportKeyExt for GenericArray<u8, U64> {
	fn into_array(self) -> [u8; 64] {
		self.into()
	}
}
