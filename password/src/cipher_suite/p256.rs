//! See [`P256`].

use std::ops::Mul;

use digest::Digest;
use generic_array::{
	typenum::{Unsigned, U32, U33},
	GenericArray,
};
use opaque_ke::{
	errors::InternalPakeError,
	group::Group,
	hash::Hash,
	map_to_curve::{expand_message_xmd, GroupWithMapToCurve},
	rand::{CryptoRng, RngCore},
};
use p256_::{
	elliptic_curve::{group::GroupEncoding, sec1::FromEncodedPoint, Field},
	EncodedPoint, ProjectivePoint, ScalarBytes, SecretKey,
};
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
		Option::from(ProjectivePoint::from_bytes(&GenericArray::deserialize(
			deserializer,
		)?))
		.map(P256)
		.ok_or_else(|| de::Error::custom("Invalid point"))
	}
}

impl Serialize for P256 {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.0.to_bytes().serialize(serializer)
	}
}

impl Mul<&Scalar> for P256 {
	type Output = Self;

	fn mul(self, other: &Scalar) -> Self {
		Self(Mul::mul(self.0, other.0))
	}
}

impl GroupWithMapToCurve for P256 {
	const SUITE_ID: usize = 0x0003;

	fn map_to_curve<H: Hash>(msg: &[u8], dst: &[u8]) -> Result<Self, InternalPakeError> {
		let uniform_bytes =
			expand_message_xmd::<H>(msg, dst, <H as Digest>::OutputSize::to_usize())?;
		Ok(<Self as Group>::hash_to_curve(
			&GenericArray::clone_from_slice(&uniform_bytes[..]),
		))
	}

	fn hash_to_scalar<H: Hash>(
		input: &[u8],
		dst: &[u8],
	) -> Result<Self::Scalar, InternalPakeError> {
		let uniform_bytes = expand_message_xmd::<H>(input, dst, 32)?;
		let mut bits = [0; 32];
		bits.copy_from_slice(&uniform_bytes[..]);

		Ok(Scalar(p256_::Scalar::from_bytes_reduced(&bits.into())))
	}
}

impl Group for P256 {
	type ElemLen = U33;
	type Scalar = Scalar;
	type ScalarLen = U32;
	type UniformBytesLen = U32;

	fn from_scalar_slice(
		scalar_bits: &GenericArray<u8, Self::ScalarLen>,
	) -> Result<Self::Scalar, InternalPakeError> {
		Ok(Scalar(p256_::Scalar::from_bytes_reduced(scalar_bits)))
	}

	fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
		Scalar(p256_::Scalar::random(rng))
	}

	fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
		scalar.0.into()
	}

	fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
		Scalar(scalar.0.invert().unwrap_or(p256_::Scalar::zero()))
	}

	fn from_element_slice(
		element_bits: &GenericArray<u8, Self::ElemLen>,
	) -> Result<Self, InternalPakeError> {
		Option::from(ProjectivePoint::from_bytes(element_bits))
			.map(P256)
			.ok_or(InternalPakeError::PointError)
	}

	fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
		self.0.to_bytes()
	}

	fn hash_to_curve(uniform_bytes: &GenericArray<u8, Self::UniformBytesLen>) -> Self {
		Self(
			ProjectivePoint::from_encoded_point(&EncodedPoint::from_secret_key(
				&SecretKey::new(ScalarBytes::from_scalar(
					&p256_::Scalar::from_bytes_reduced(uniform_bytes),
				)),
				true,
			))
			.expect("failed to generate group from bytes"),
		)
	}

	fn base_point() -> Self {
		Self(ProjectivePoint::generator())
	}

	fn mult_by_slice(&self, scalar: &GenericArray<u8, Self::ScalarLen>) -> Self {
		Self(self.0 * p256_::Scalar::from_bytes_reduced(scalar))
	}

	fn is_identity(&self) -> bool {
		self.0 == ProjectivePoint::identity()
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
