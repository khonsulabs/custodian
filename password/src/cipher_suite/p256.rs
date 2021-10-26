//! See [`P256`].

use std::ops::{Add, Mul, Sub};

use digest::{BlockInput, Digest};
use generic_array::{typenum::U1, ArrayLength, GenericArray};
use opaque_ke::{
	errors::InternalError,
	key_exchange::group::KeGroup,
	rand::{CryptoRng, RngCore},
};
use p256_::ProjectivePoint;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use voprf::{errors::InternalError as VoprfInternalError, group::Group};
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
		Self::from_element_slice(&GenericArray::deserialize(deserializer)?).map_err(Error::custom)
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

impl Add<&Self> for P256 {
	type Output = Self;

	fn add(self, other: &Self) -> Self {
		Self(Add::add(self.0, other.0))
	}
}

impl Mul<&Scalar> for P256 {
	type Output = Self;

	fn mul(self, other: &Scalar) -> Self {
		Self(Mul::mul(self.0, other.0))
	}
}

impl ConstantTimeEq for P256 {
	fn ct_eq(&self, other: &Self) -> subtle::Choice {
		self.0.ct_eq(&other.0)
	}
}

impl KeGroup for P256 {
	type PkLen = <ProjectivePoint as KeGroup>::PkLen;
	type SkLen = <ProjectivePoint as KeGroup>::SkLen;

	fn from_pk_slice(element_bits: &GenericArray<u8, Self::PkLen>) -> Result<Self, InternalError> {
		ProjectivePoint::from_pk_slice(element_bits).map(Self)
	}

	fn random_sk<R: RngCore + CryptoRng>(rng: &mut R) -> GenericArray<u8, Self::SkLen> {
		ProjectivePoint::random_sk(rng)
	}

	fn public_key(sk: &GenericArray<u8, Self::SkLen>) -> Self {
		Self(ProjectivePoint::public_key(sk))
	}

	fn to_arr(&self) -> GenericArray<u8, Self::PkLen> {
		<ProjectivePoint as KeGroup>::to_arr(&self.0)
	}

	fn diffie_hellman(&self, sk: &GenericArray<u8, Self::SkLen>) -> GenericArray<u8, Self::PkLen> {
		self.0.diffie_hellman(sk)
	}
}

impl Group for P256 {
	type ElemLen = <ProjectivePoint as Group>::ElemLen;
	type Scalar = Scalar;
	type ScalarLen = <ProjectivePoint as Group>::ScalarLen;

	const SUITE_ID: usize = <ProjectivePoint as Group>::SUITE_ID;

	fn hash_to_curve<H: BlockInput + Digest, D: ArrayLength<u8> + Add<U1>>(
		msg: &[u8],
		dst: GenericArray<u8, D>,
	) -> Result<Self, VoprfInternalError>
	where
		<D as Add<U1>>::Output: ArrayLength<u8>,
	{
		ProjectivePoint::hash_to_curve::<H, _>(msg, dst).map(Self)
	}

	#[allow(single_use_lifetimes)]
	fn hash_to_scalar<
		'a,
		H: BlockInput + Digest,
		D: ArrayLength<u8> + Add<U1>,
		I: IntoIterator<Item = &'a [u8]>,
	>(
		input: I,
		dst: GenericArray<u8, D>,
	) -> Result<Self::Scalar, VoprfInternalError>
	where
		<D as Add<U1>>::Output: ArrayLength<u8>,
	{
		ProjectivePoint::hash_to_scalar::<H, _, _>(input, dst).map(Scalar)
	}

	fn from_scalar_slice_unchecked(
		scalar_bits: &GenericArray<u8, Self::ScalarLen>,
	) -> Result<Self::Scalar, VoprfInternalError> {
		ProjectivePoint::from_scalar_slice_unchecked(scalar_bits).map(Scalar)
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

	fn from_element_slice_unchecked(
		element_bits: &GenericArray<u8, Self::ElemLen>,
	) -> Result<Self, VoprfInternalError> {
		ProjectivePoint::from_element_slice_unchecked(element_bits).map(Self)
	}

	fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
		<ProjectivePoint as Group>::to_arr(&self.0)
	}

	fn base_point() -> Self {
		Self(ProjectivePoint::base_point())
	}

	fn is_identity(&self) -> bool {
		self.0.is_identity()
	}

	fn identity() -> Self {
		Self(ProjectivePoint::identity())
	}

	fn scalar_zero() -> Self::Scalar {
		Scalar(ProjectivePoint::scalar_zero())
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

impl Add<&Self> for Scalar {
	type Output = Self;

	fn add(self, rhs: &Self) -> Self::Output {
		Self(self.0.add(&rhs.0))
	}
}

impl Sub<&Self> for Scalar {
	type Output = Self;

	fn sub(self, rhs: &Self) -> Self::Output {
		Self(self.0.sub(&rhs.0))
	}
}

impl Mul<&Self> for Scalar {
	type Output = Self;

	fn mul(self, rhs: &Self) -> Self::Output {
		Self(self.0.mul(&rhs.0))
	}
}

impl ConstantTimeEq for Scalar {
	fn ct_eq(&self, other: &Self) -> subtle::Choice {
		self.0.ct_eq(&other.0)
	}
}
