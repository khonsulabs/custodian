//! [`CipherSuite`](ciphersuite::CipherSuite) implementations and all
//! corresponding types.
//!
//! This consists mainly of wrappers around all types requiring generic bounds
//! of [`CipherSuite`](ciphersuite::CipherSuite). The goal is to avoid any
//! user-facing types with generics. This allows users to dynamically
//! instantiate [`Config`](crate::Config) with arbitrary settings and store all
//! states and files in the same container.

mod argon2d;
#[cfg(feature = "blake3")]
mod blake3;
#[cfg(feature = "p256")]
mod p256;
#[cfg(feature = "blake3")]
mod pbkdf2;
mod public_key;

use argon2::Argon2;
use curve25519_dalek::ristretto::RistrettoPoint;
use digest::Digest;
use generic_array::{
	sequence::Concat,
	typenum::{operator_aliases::Diff, U64},
	GenericArray,
};
use opaque_ke::{
	ciphersuite, key_exchange::tripledh::TripleDH, rand::rngs::OsRng, ClientLoginFinishResult,
	ClientLoginStartResult, ClientRegistrationFinishResult, ClientRegistrationStartResult,
	ServerLoginFinishResult, ServerLoginStartParameters, ServerLoginStartResult,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "p256")]
use sha2::Sha256;
use sha2::Sha512;
#[cfg(all(feature = "p256", feature = "sha3"))]
use sha3::Sha3_256;
#[cfg(feature = "sha3")]
use sha3::Sha3_512;

#[cfg(feature = "blake3")]
use self::blake3::Blake3;
#[cfg(feature = "p256")]
use self::p256::P256;
#[cfg(feature = "pbkdf2")]
use self::pbkdf2::Pbkdf2;
use self::{argon2d::Argon2d, public_key::PublicKeyExt};
use crate::{Error, Result};

/// Wrapper around multiple [`CipherSuite`](ciphersuite::CipherSuite)s to avoid
/// user-facing generics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum CipherSuite {
	/// Ristretto255 + SHA512 + Argon2id
	Ristretto255Sha512Argon2id,
	/// Ristretto255 + SHA512 + Argon2d
	Ristretto255Sha512Argon2d,
	/// Ristretto255 + SHA512 + PBKDF2
	#[cfg(feature = "pbkdf2")]
	Ristretto255Sha512Pbkdf2,
	/// Ristretto255 + SHA3-512 + Argon2id
	#[cfg(feature = "sha3")]
	Ristretto255Sha3_512Argon2id,
	/// Ristretto255 + SHA3-512 + Argon2d
	#[cfg(feature = "sha3")]
	Ristretto255Sha3_512Argon2d,
	/// Ristretto255 + SHA3-512 + PBKDF2
	#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
	Ristretto255Sha3_512Pbkdf2,
	/// Ristretto255 + BLAKE3 + Argon2id
	#[cfg(feature = "blake3")]
	Ristretto255Blake3Argon2id,
	/// Ristretto255 + BLAKE3 + Argon2d
	#[cfg(feature = "blake3")]
	Ristretto255Blake3Argon2d,
	/// Ristretto255 + BLAKE3 + PBKDF2
	#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
	Ristretto255Blake3Pbkdf2,
	/// P256 + SHA256 + Argon2id
	#[cfg(feature = "p256")]
	P256Sha256Argon2id,
	/// P256 + SHA256 + Argon2d
	#[cfg(feature = "p256")]
	P256Sha256Argon2d,
	/// P256 + SHA256 + PBKDF2
	#[cfg(all(feature = "p256", feature = "pbkdf2"))]
	P256Sha256Pbkdf2,
	/// P256 + SHA3-256 + Argon2id
	#[cfg(all(feature = "p256", feature = "sha3"))]
	P256Sha3_256Argon2id,
	/// P256 + SHA3-256 + Argon2d
	#[cfg(all(feature = "p256", feature = "sha3"))]
	P256Sha3_256Argon2d,
	/// P256 + SHA3-256 + PBKDF2
	#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
	P256Sha3_256Pbkdf2,
	/// P256 + BLAKE3 + Argon2id
	#[cfg(all(feature = "p256", feature = "blake3"))]
	P256Blake3Argon2id,
	/// P256 + BLAKE3 + Argon2d
	#[cfg(all(feature = "p256", feature = "blake3"))]
	P256Blake3Argon2d,
	/// P256 + BLAKE3 + PBKDF2
	#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
	P256Blake3Pbkdf2,
}

macro_rules! cipher_suite {
	(
		$($(#[$attr:meta])? [
			$cipher_suite:ident,
			$group:ty,
			$hash:ty,
			$slow_hash:ty$(,)?
		]),+$(,)?) => {
		$(
		$(#[$attr])?
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
		pub(crate) struct $cipher_suite;

		$(#[$attr])?
		impl ciphersuite::CipherSuite for $cipher_suite {
			type Group = $group;
			type Hash = $hash;
			type KeyExchange = TripleDH;
			type SlowHash = $slow_hash;
		}
		)+

		/// [`opaque_ke::ClientRegistration`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum ClientRegistration {
			$($(#[$attr])? $cipher_suite(opaque_ke::ClientRegistration<$cipher_suite>),)+
		}

		impl ClientRegistration {
			/// Return corresponding [`CipherSuite`].
			pub(crate) const fn cipher_suite(&self) -> CipherSuite {
				match self {
					$($(#[$attr])? ClientRegistration::$cipher_suite(_) =>
						CipherSuite::$cipher_suite,)+
				}
			}

			/// [`opaque_ke::ClientRegistration::start()`] wrapper.
			pub(crate) fn register(
				cipher_suite: CipherSuite,
				password: &[u8],
			) -> Result<(Self, RegistrationRequest)> {
				match cipher_suite {
					$($(#[$attr])? CipherSuite::$cipher_suite => {
						let result = opaque_ke::ClientRegistration::start(&mut OsRng, password)?;
						let ClientRegistrationStartResult { state, message } = result;
						Ok((
							Self::$cipher_suite(state),
							RegistrationRequest::$cipher_suite(message),
						))
					})+
				}
			}

			/// [`opaque_ke::ClientRegistration::finish()`] wrapper.
			pub(crate) fn finish(
				self,
				response: RegistrationResponse,
			) -> Result<(RegistrationFinalization, [u8; 33], [u8; 64])> {
				match (self, response) {
					$($(#[$attr])? (
						Self::$cipher_suite(state),
						RegistrationResponse::$cipher_suite(response),
					) => {
						let result = state.finish(
							&mut OsRng,
							response,
							opaque_ke::ClientRegistrationFinishParameters::Default,
						)?;
						let ClientRegistrationFinishResult {
							message,
							export_key,
							server_s_pk,
						} = result;

						Ok((
							RegistrationFinalization::$cipher_suite(message),
							server_s_pk.to_array(),
							export_key.concat(
								GenericArray::<
									u8,
									Diff<
										U64,
										<<$cipher_suite as ciphersuite::CipherSuite>::Hash
											 as Digest>::OutputSize>
									>::default()
							).into(),
						))
					})+
					_ => Err(Error::Config),
				}
			}
		}

		/// [`opaque_ke::ClientLogin`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum ClientLogin {
			$($(#[$attr])? $cipher_suite(opaque_ke::ClientLogin<$cipher_suite>),)+
		}

		impl ClientLogin {
			/// Return corresponding [`CipherSuite`].
			pub(crate) const fn cipher_suite(&self) -> CipherSuite {
				match self {
					$($(#[$attr])? ClientLogin::$cipher_suite(_) => CipherSuite::$cipher_suite,)+
				}
			}

			/// [`opaque_ke::ClientLogin::start()`] wrapper.
			pub(crate) fn login(
				cipher_suite: CipherSuite,
				password: &[u8],
			) -> Result<(Self, LoginRequest)> {
				match cipher_suite {
					$($(#[$attr])? CipherSuite::$cipher_suite => {
						let result = opaque_ke::ClientLogin::start(&mut OsRng, password)?;
						let ClientLoginStartResult { state, message } = result;
						Ok((
							Self::$cipher_suite(state),
							LoginRequest::$cipher_suite(message),
						))
					})+
				}
			}

			/// [`opaque_ke::ClientLogin::finish()`] wrapper.
			pub(crate) fn finish(
				self,
				response: LoginResponse,
			) -> Result<(LoginFinalization, [u8; 33], [u8; 64])> {
				match (self, response) {
					$($(#[$attr])? (
						Self::$cipher_suite(state),
						LoginResponse::$cipher_suite(response),
					) => {
						let result =
							state.finish(
								response,
								opaque_ke::ClientLoginFinishParameters::Default,
							)?;
						let ClientLoginFinishResult {
							message,
							export_key,
							server_s_pk,
							..
						} = result;
						Ok((
							LoginFinalization::$cipher_suite(message),
							server_s_pk.to_array(),
							export_key.concat(
								GenericArray::<
									u8,
									Diff<
										U64,
										<<$cipher_suite as ciphersuite::CipherSuite>::Hash
											 as Digest>::OutputSize>
									>::default()
							).into(),
						))
					})+
					_ => Err(Error::Config),
				}
			}
		}

		/// [`opaque_ke::ServerSetup`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum ServerSetup {
			$($(#[$attr])? $cipher_suite(opaque_ke::ServerSetup<$cipher_suite>),)+
		}

		impl ServerSetup {
			/// Return corresponding [`CipherSuite`].
			pub(crate) const fn cipher_suite(&self) -> CipherSuite {
				match self {
					$($(#[$attr])? ServerSetup::$cipher_suite(_) => CipherSuite::$cipher_suite,)+
				}
			}

			/// [`opaque_ke::ServerSetup::new()`] wrapper.
			pub(crate) fn new(cipher_suite: CipherSuite) -> Self {
				match cipher_suite {
					$($(#[$attr])? CipherSuite::$cipher_suite =>
						Self::$cipher_suite(opaque_ke::ServerSetup::new(&mut OsRng)),)+
				}
			}

			/// [`opaque_ke::ServerSetup::keypair()`] wrapper.
			pub(crate) fn public_key(&self) -> [u8; 33] {
				match self {
					$($(#[$attr])? ServerSetup::$cipher_suite(server_setup) =>
						server_setup.keypair().public().to_array(),)+
				}
			}
		}

		/// [`opaque_ke::ServerRegistration`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum ServerFile {
			$($(#[$attr])? $cipher_suite(opaque_ke::ServerRegistration<$cipher_suite>),)+
		}

		impl ServerFile {
			/// Return corresponding [`CipherSuite`].
			pub(crate) const fn cipher_suite(&self) -> CipherSuite {
				match self {
					$($(#[$attr])? ServerFile::$cipher_suite(_) => CipherSuite::$cipher_suite,)+
				}
			}
		}

		/// [`opaque_ke::ServerRegistration`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
		pub(crate) enum ServerRegistration {
			$($(#[$attr])? $cipher_suite,)+
		}

		impl ServerRegistration {
			/// Return corresponding [`CipherSuite`].
			pub(crate) const fn cipher_suite(&self) -> CipherSuite {
				match self {
					$($(#[$attr])?
					ServerRegistration::$cipher_suite => CipherSuite::$cipher_suite,)+
				}
			}

			/// [`opaque_ke::ServerRegistration::start()`] wrapper.
			pub(crate) fn register(
				server_setup: &ServerSetup,
				request: RegistrationRequest,
			) -> Result<(Self, RegistrationResponse)> {
				match (server_setup, request) {
					$($(#[$attr])? (
						ServerSetup::$cipher_suite(server_setup),
						RegistrationRequest::$cipher_suite(request),
					) => {
						let response =
							opaque_ke::ServerRegistration::start(
								server_setup,
								request,
								&[]
							)?.message;
						Ok((
							Self::$cipher_suite,
							RegistrationResponse::$cipher_suite(response),
						))
					})+
					_ => Err(Error::Config),
				}
			}

			/// [`opaque_ke::ServerRegistration::finish()`] wrapper.
			pub(crate) fn finish(self, finalization: RegistrationFinalization
			) -> Result<ServerFile> {
				match (self, finalization) {
					$($(#[$attr])? (
						Self::$cipher_suite,
						RegistrationFinalization::$cipher_suite(finalization),
					) => {
						let file = opaque_ke::ServerRegistration::finish(finalization);
						Ok(ServerFile::$cipher_suite(file))
					})+
					_ => Err(Error::Config),
				}
			}
		}

		/// [`opaque_ke::ServerLogin`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum ServerLogin {
			$($(#[$attr])? $cipher_suite(opaque_ke::ServerLogin<$cipher_suite>),)+
		}

		impl ServerLogin {
			/// Return corresponding [`CipherSuite`].
			pub(crate) const fn cipher_suite(&self) -> CipherSuite {
				match self {
					$($(#[$attr])? ServerLogin::$cipher_suite(_) => CipherSuite::$cipher_suite,)+
				}
			}

			/// [`opaque_ke::ServerLogin::start()`] wrapper.
			pub(crate) fn login(
				setup: &ServerSetup,
				file: Option<(ServerFile, [u8; 33])>,
				request: LoginRequest,
			) -> Result<(Self, LoginResponse)> {
				match (setup, request) {
					$($(#[$attr])? (
						ServerSetup::$cipher_suite(server_setup),
						LoginRequest::$cipher_suite(request),
					) => {
						let file = match file {
							Some((ServerFile::$cipher_suite(file), public_key)) => {
								if !server_setup.keypair().public().is_array(public_key) {
									return Err(Error::ServerConfig);
								}

								Some(file)
							},
							Some(_) => return Err(Error::Config),
							None => None,
						};

						let result = opaque_ke::ServerLogin::start(
							&mut OsRng,
							server_setup,
							file,
							request,
							&[],
							ServerLoginStartParameters::default(),
						)?;
						let ServerLoginStartResult { state, message } = result;
						Ok((
							Self::$cipher_suite(state),
							LoginResponse::$cipher_suite(message),
						))
					})+
					_ => Err(Error::Config),
				}
			}

			/// [`opaque_ke::ClientLogin::finish()`] wrapper.
			pub(crate) fn finish(self, finalization: LoginFinalization) -> Result<()> {
				match (self, finalization) {
					$($(#[$attr])? (
						Self::$cipher_suite(state),
						LoginFinalization::$cipher_suite(finalization),
					) => {
						let result = state.finish(finalization)?;
						let ServerLoginFinishResult { .. } = result;

						Ok(())
					})+
					_ => Err(Error::Config),
				}
			}
		}

		/// [`opaque_ke::RegistrationRequest`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
		pub(crate) enum RegistrationRequest {
			$($(#[$attr])? $cipher_suite(opaque_ke::RegistrationRequest<$cipher_suite>),)+
		}

		/// [`opaque_ke::RegistrationResponse`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
		pub(crate) enum RegistrationResponse {
			$($(#[$attr])? $cipher_suite(opaque_ke::RegistrationResponse<$cipher_suite>),)+
		}

		/// [`opaque_ke::RegistrationUpload`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum RegistrationFinalization {
			$($(#[$attr])? $cipher_suite(opaque_ke::RegistrationUpload<$cipher_suite>),)+
		}

		/// [`opaque_ke::CredentialRequest`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
		pub(crate) enum LoginRequest {
			$($(#[$attr])? $cipher_suite(opaque_ke::CredentialRequest<$cipher_suite>),)+
		}

		/// [`opaque_ke::CredentialResponse`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
		pub(crate) enum LoginResponse {
			$($(#[$attr])? $cipher_suite(opaque_ke::CredentialResponse<$cipher_suite>),)+
		}

		/// [`opaque_ke::CredentialFinalization`] wrapper.
		#[allow(clippy::missing_docs_in_private_items)]
		#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
		pub(crate) enum LoginFinalization {
			$($(#[$attr])? $cipher_suite(opaque_ke::CredentialFinalization<$cipher_suite>),)+
		}
	};
}

cipher_suite!(
	[Ristretto255Sha512Argon2id, RistrettoPoint, Sha512, Argon2<'static>],
	[Ristretto255Sha512Argon2d, RistrettoPoint, Sha512, Argon2d],
	#[cfg(feature = "pbkdf2")]
	[Ristretto255Sha512Pbkdf2, RistrettoPoint, Sha512, Pbkdf2],
	#[cfg(feature = "sha3")]
	[Ristretto255Sha3_512Argon2id, RistrettoPoint, Sha3_512, Argon2<'static>],
	#[cfg(feature = "sha3")]
	[Ristretto255Sha3_512Argon2d, RistrettoPoint, Sha3_512, Argon2d],
	#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
	[Ristretto255Sha3_512Pbkdf2, RistrettoPoint, Sha3_512, Pbkdf2],
	#[cfg(feature = "blake3")]
	[Ristretto255Blake3Argon2id, RistrettoPoint, Blake3, Argon2<'static>],
	#[cfg(feature = "blake3")]
	[Ristretto255Blake3Argon2d, RistrettoPoint, Blake3, Argon2d],
	#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
	[Ristretto255Blake3Pbkdf2, RistrettoPoint, Blake3, Pbkdf2],
	#[cfg(feature = "p256")]
	[P256Sha256Argon2id, P256, Sha256, Argon2<'static>],
	#[cfg(feature = "p256")]
	[P256Sha256Argon2d, P256, Sha256, Argon2d],
	#[cfg(all(feature = "p256", feature = "pbkdf2"))]
	[P256Sha256Pbkdf2, P256, Sha256, Pbkdf2],
	#[cfg(all(feature = "p256", feature = "sha3"))]
	[P256Sha3_256Argon2id, P256, Sha3_256, Argon2<'static>],
	#[cfg(all(feature = "p256", feature = "sha3"))]
	[P256Sha3_256Argon2d, P256, Sha3_256, Argon2d],
	#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
	[P256Sha3_256Pbkdf2, P256, Sha3_256, Pbkdf2],
	#[cfg(all(feature = "p256", feature = "blake3"))]
	[P256Blake3Argon2id, P256, ::blake3::Hasher, Argon2<'static>],
	#[cfg(all(feature = "p256", feature = "blake3"))]
	[P256Blake3Argon2d, P256, ::blake3::Hasher, Argon2d],
	#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
	[P256Blake3Pbkdf2, P256, ::blake3::Hasher, Pbkdf2],
);
