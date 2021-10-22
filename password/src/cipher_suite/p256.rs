//! See [`P256`].

use std::ops::Mul;

use generic_array::GenericArray;
use opaque_ke::{
	errors::InternalError,
	group::Group,
	rand::{CryptoRng, RngCore},
};
use p256_::ProjectivePoint;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// Object implementing [`Group`] for P256. This encapsulates
/// [`ProjectivePoint`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct P256(ProjectivePoint);

impl<'de> Deserialize<'de> for P256 {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Self::from_element_slice(&GenericArray::deserialize(deserializer)?)
			.map_err(de::Error::custom)
	}
}

impl Serialize for P256 {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		Group::to_arr(self).serialize(serializer)
	}
}

impl Mul<&Scalar> for P256 {
	type Output = Self;

	fn mul(self, other: &Scalar) -> Self {
		Self(Mul::mul(self.0, other.0))
	}
}

impl Group for P256 {
	type ElemLen = <ProjectivePoint as Group>::ElemLen;
	type Scalar = Scalar;
	type ScalarLen = <ProjectivePoint as Group>::ScalarLen;

	const SUITE_ID: usize = <ProjectivePoint as Group>::SUITE_ID;

	fn map_to_curve<H: opaque_ke::hash::Hash>(
		msg: &[u8],
		dst: &[u8],
	) -> Result<Self, opaque_ke::errors::ProtocolError> {
		ProjectivePoint::map_to_curve::<H>(msg, dst).map(Self)
	}

	fn hash_to_scalar<H: opaque_ke::hash::Hash>(
		input: &[u8],
		dst: &[u8],
	) -> Result<Self::Scalar, opaque_ke::errors::ProtocolError> {
		ProjectivePoint::hash_to_scalar::<H>(input, dst).map(Scalar)
	}

	fn from_scalar_slice(
		scalar_bits: &GenericArray<u8, Self::ScalarLen>,
	) -> Result<Self::Scalar, InternalError> {
		ProjectivePoint::from_scalar_slice(scalar_bits).map(Scalar)
	}

	fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
		Scalar(ProjectivePoint::random_nonzero_scalar(rng))
	}

	fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
		ProjectivePoint::scalar_as_bytes(scalar.0)
	}

	fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
		Scalar(ProjectivePoint::scalar_invert(&scalar.0))
	}

	fn from_element_slice(
		element_bits: &GenericArray<u8, Self::ElemLen>,
	) -> Result<Self, InternalError> {
		ProjectivePoint::from_element_slice(element_bits).map(Self)
	}

	fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
		self.0.to_arr()
	}

	fn is_identity(&self) -> bool {
		self.0.is_identity()
	}

	fn ct_equal(&self, other: &Self) -> bool {
		self.0.ct_equal(&other.0)
	}

	fn base_point() -> Self {
		Self(ProjectivePoint::base_point())
	}

	fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
		Self(self.0.mult_by_slice(scalar))
	}
}

/// Wrapper over [`p256::Scalar`](p256_::Scalar) to implement common traits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub(crate) struct Scalar(p256_::Scalar);

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for Scalar {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.0.to_bytes().hash(state);
	}
}

impl<'de> Deserialize<'de> for Scalar {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Ok(Self(p256_::Scalar::from_bytes_reduced(
			&GenericArray::deserialize(deserializer)?,
		)))
	}
}

impl Serialize for Scalar {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.0.to_bytes().serialize(serializer)
	}
}
