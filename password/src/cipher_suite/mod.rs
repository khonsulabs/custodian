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

use argon2::Argon2;
use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::{
	ciphersuite, key_exchange::tripledh::TripleDH, keypair::PublicKey, rand::rngs::OsRng,
	ClientLoginFinishResult, ClientLoginStartResult, ClientRegistrationFinishResult,
	ClientRegistrationStartResult, ServerLoginFinishResult, ServerLoginStartParameters,
	ServerLoginStartResult,
};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
#[cfg(feature = "sha3")]
use sha3::Sha3_512;

use self::argon2d::Argon2d;
#[cfg(feature = "blake3")]
use self::blake3::Blake3;
use crate::{Error, Result};

/// Wrapper around multiple [`CipherSuite`](ciphersuite::CipherSuite)s to avoid
/// user-facing generics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum CipherSuite {
	/// Curve25519 + Sha512 + Argon2id
	Curve25519Sha512Argon2id,
	/// Curve25519 + Sha512 + Argon2d
	Curve25519Sha512Argon2d,
	#[cfg(feature = "sha3")]
	/// Curve25519 + Sha3-512 + Argon2id
	Curve25519Sha3_512Argon2id,
	#[cfg(feature = "sha3")]
	/// Curve25519 + Sha3-512 + Argon2d
	Curve25519Sha3_512Argon2d,
	#[cfg(feature = "blake3")]
	/// Curve25519 + BLAKE3 + Argon2id
	Curve25519Blake3Argon2id,
	#[cfg(feature = "blake3")]
	/// Curve25519 + BLAKE3 + Argon2d
	Curve25519Blake3Argon2d,
}

#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Curve25519Sha512Argon2id;

impl ciphersuite::CipherSuite for Curve25519Sha512Argon2id {
	type Group = RistrettoPoint;
	type Hash = Sha512;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2<'static>;
}

#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Curve25519Sha512Argon2d;

impl ciphersuite::CipherSuite for Curve25519Sha512Argon2d {
	type Group = RistrettoPoint;
	type Hash = Sha512;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2d;
}

#[cfg(feature = "sha3")]
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Curve25519Sha3_512Argon2id;

#[cfg(feature = "sha3")]
impl ciphersuite::CipherSuite for Curve25519Sha3_512Argon2id {
	type Group = RistrettoPoint;
	type Hash = Sha3_512;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2<'static>;
}

#[cfg(feature = "sha3")]
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Curve25519Sha3_512Argon2d;

#[cfg(feature = "sha3")]
impl ciphersuite::CipherSuite for Curve25519Sha3_512Argon2d {
	type Group = RistrettoPoint;
	type Hash = Sha3_512;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2d;
}

#[cfg(feature = "blake3")]
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Curve25519Blake3Argon2id;

#[cfg(feature = "blake3")]
impl ciphersuite::CipherSuite for Curve25519Blake3Argon2id {
	type Group = RistrettoPoint;
	type Hash = Blake3;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2<'static>;
}

#[cfg(feature = "blake3")]
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Curve25519Blake3Argon2d;

#[cfg(feature = "blake3")]
impl ciphersuite::CipherSuite for Curve25519Blake3Argon2d {
	type Group = RistrettoPoint;
	type Hash = Blake3;
	type KeyExchange = TripleDH;
	type SlowHash = Argon2d;
}

macro_rules! cipher_suite {
	($($(#[$attr:meta])? $cipher_suite:ident),+$(,)?) => {
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
			) -> Result<(RegistrationFinalization, PublicKey, [u8; 64])> {
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
							server_s_pk,
							export_key.into(),
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
			) -> Result<(LoginFinalization, PublicKey, [u8; 64])> {
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
							server_s_pk,
							export_key.into(),
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
			pub(crate) fn public_key(&self) -> &PublicKey {
				match self {
					$($(#[$attr])? ServerSetup::$cipher_suite(server_setup) =>
						server_setup.keypair().public(),)+
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
				file: Option<(ServerFile, [u8; 32])>,
				request: LoginRequest,
			) -> Result<(Self, LoginResponse)> {
				match (setup, request) {
					$($(#[$attr])? (
						ServerSetup::$cipher_suite(server_setup),
						LoginRequest::$cipher_suite(request),
					) => {
						let file = match file {
							Some((ServerFile::$cipher_suite(file), public_key)) => {
								if ***setup.public_key() != public_key {
									return Err(Error::ServerConfig);
								}

								Some(file)
							},
							#[allow(unreachable_patterns)]
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
	Curve25519Sha512Argon2id,
	Curve25519Sha512Argon2d,
	#[cfg(feature = "sha3")]
	Curve25519Sha3_512Argon2id,
	#[cfg(feature = "sha3")]
	Curve25519Sha3_512Argon2d,
	#[cfg(feature = "blake3")]
	Curve25519Blake3Argon2id,
	#[cfg(feature = "blake3")]
	Curve25519Blake3Argon2d,
);
