//! See [`Blake3`].

use blake3::Hasher;
use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::{GenericArray, typenum::U64};

/// Object implementing [`Hash`](opaque_ke::hash::Hash) for BLAKE3. This
/// encapsulates [`blake3::Hasher`] over a 64-bit output size.
#[derive(Clone, Default)]
pub(crate) struct Blake3(Hasher);

impl Update for Blake3 {
	fn update(&mut self, data: impl AsRef<[u8]>) {
		Update::update(&mut self.0, data);
	}
}

impl BlockInput for Blake3 {
	type BlockSize = <Hasher as BlockInput>::BlockSize;
}

impl FixedOutput for Blake3 {
	type OutputSize = U64;

	fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
		self.0.finalize_xof().fill(out);
	}

	fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
		self.0.finalize_xof().fill(out);
		self.0.reset();
	}
}

impl Reset for Blake3 {
	fn reset(&mut self) {
		Reset::reset(&mut self.0);
	}
}
