//! [`CipherSuite`](ciphersuite::CipherSuite) implementations and all
//! corresponding types.
//!
//! This consists mainly of wrappers around all types requiring generic bounds
//! of [`CipherSuite`](ciphersuite::CipherSuite). The goal is to avoid any
//! user-facing types with generics. This allows users to dynamically
//! instantiate [`Config`](crate::Config) with arbitrary settings and store all
//! states and files in the same container.

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

use crate::{Error, Result};

/// Wrapper around multiple [`CipherSuite`](ciphersuite::CipherSuite)s to avoid
/// user-facing generics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum CipherSuite {
	/// Curve25519 + Sha512 + Argon2id
	Curve25519Sha512Argon2id,
}

impl Default for CipherSuite {
	fn default() -> Self {
		Self::Curve25519Sha512Argon2id
	}
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

/// [`opaque_ke::ClientRegistration`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum ClientRegistration {
	Curve25519Sha512Argon2id(opaque_ke::ClientRegistration<Curve25519Sha512Argon2id>),
}

impl ClientRegistration {
	/// Return corresponding [`CipherSuite`].
	pub(crate) const fn cipher_suite(&self) -> CipherSuite {
		match self {
			ClientRegistration::Curve25519Sha512Argon2id(_) =>
				CipherSuite::Curve25519Sha512Argon2id,
		}
	}

	/// [`opaque_ke::ClientRegistration::start()`] wrapper.
	pub(crate) fn register(
		cipher_suite: CipherSuite,
		password: &[u8],
	) -> Result<(Self, RegistrationRequest)> {
		match cipher_suite {
			CipherSuite::Curve25519Sha512Argon2id => {
				let result = opaque_ke::ClientRegistration::start(&mut OsRng, password)?;
				let ClientRegistrationStartResult { state, message } = result;
				Ok((
					Self::Curve25519Sha512Argon2id(state),
					RegistrationRequest::Curve25519Sha512Argon2id(message),
				))
			}
		}
	}

	/// [`opaque_ke::ClientRegistration::finish()`] wrapper.
	pub(crate) fn finish(
		self,
		response: RegistrationResponse,
	) -> Result<(RegistrationFinalization, PublicKey, [u8; 64])> {
		match (self, response) {
			(
				Self::Curve25519Sha512Argon2id(state),
				RegistrationResponse::Curve25519Sha512Argon2id(response),
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
					RegistrationFinalization::Curve25519Sha512Argon2id(message),
					server_s_pk,
					export_key.into(),
				))
			}
			#[allow(unreachable_patterns)]
			_ => Err(Error::Config),
		}
	}
}

/// [`opaque_ke::ClientLogin`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum ClientLogin {
	Curve25519Sha512Argon2id(opaque_ke::ClientLogin<Curve25519Sha512Argon2id>),
}

impl ClientLogin {
	/// Return corresponding [`CipherSuite`].
	pub(crate) const fn cipher_suite(&self) -> CipherSuite {
		match self {
			ClientLogin::Curve25519Sha512Argon2id(_) => CipherSuite::Curve25519Sha512Argon2id,
		}
	}

	/// [`opaque_ke::ClientLogin::start()`] wrapper.
	pub(crate) fn login(
		cipher_suite: CipherSuite,
		password: &[u8],
	) -> Result<(Self, LoginRequest)> {
		match cipher_suite {
			CipherSuite::Curve25519Sha512Argon2id => {
				let result = opaque_ke::ClientLogin::start(&mut OsRng, password)?;
				let ClientLoginStartResult { state, message } = result;
				Ok((
					Self::Curve25519Sha512Argon2id(state),
					LoginRequest::Curve25519Sha512Argon2id(message),
				))
			}
		}
	}

	/// [`opaque_ke::ClientLogin::finish()`] wrapper.
	pub(crate) fn finish(
		self,
		response: LoginResponse,
	) -> Result<(LoginFinalization, PublicKey, [u8; 64])> {
		match (self, response) {
			(
				Self::Curve25519Sha512Argon2id(state),
				LoginResponse::Curve25519Sha512Argon2id(response),
			) => {
				let result =
					state.finish(response, opaque_ke::ClientLoginFinishParameters::Default)?;
				let ClientLoginFinishResult {
					message,
					export_key,
					server_s_pk,
					..
				} = result;
				Ok((
					LoginFinalization::Curve25519Sha512Argon2id(message),
					server_s_pk,
					export_key.into(),
				))
			}
			#[allow(unreachable_patterns)]
			_ => Err(Error::Config),
		}
	}
}

/// [`opaque_ke::ServerSetup`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum ServerSetup {
	Curve25519Sha512Argon2id(opaque_ke::ServerSetup<Curve25519Sha512Argon2id>),
}

impl ServerSetup {
	/// Return corresponding [`CipherSuite`].
	pub(crate) const fn cipher_suite(&self) -> CipherSuite {
		match self {
			ServerSetup::Curve25519Sha512Argon2id(_) => CipherSuite::Curve25519Sha512Argon2id,
		}
	}

	/// [`opaque_ke::ServerSetup::new()`] wrapper.
	pub(crate) fn new(cipher_suite: CipherSuite) -> Self {
		match cipher_suite {
			CipherSuite::Curve25519Sha512Argon2id =>
				Self::Curve25519Sha512Argon2id(opaque_ke::ServerSetup::new(&mut OsRng)),
		}
	}

	/// [`opaque_ke::ServerSetup::keypair()`] wrapper.
	pub(crate) fn public_key(&self) -> &PublicKey {
		match self {
			ServerSetup::Curve25519Sha512Argon2id(server_setup) => server_setup.keypair().public(),
		}
	}
}

/// [`opaque_ke::ServerRegistration`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum ServerFile {
	Curve25519Sha512Argon2id(opaque_ke::ServerRegistration<Curve25519Sha512Argon2id>),
}

impl ServerFile {
	/// Return corresponding [`CipherSuite`].
	pub(crate) const fn cipher_suite(&self) -> CipherSuite {
		match self {
			ServerFile::Curve25519Sha512Argon2id(_) => CipherSuite::Curve25519Sha512Argon2id,
		}
	}
}

/// [`opaque_ke::ServerRegistration`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum ServerRegistration {
	Curve25519Sha512Argon2id,
}

impl ServerRegistration {
	/// Return corresponding [`CipherSuite`].
	pub(crate) const fn cipher_suite(&self) -> CipherSuite {
		match self {
			ServerRegistration::Curve25519Sha512Argon2id => CipherSuite::Curve25519Sha512Argon2id,
		}
	}

	/// [`opaque_ke::ServerRegistration::start()`] wrapper.
	pub(crate) fn register(
		server_setup: &ServerSetup,
		request: RegistrationRequest,
	) -> Result<(Self, RegistrationResponse)> {
		match (server_setup, request) {
			(
				ServerSetup::Curve25519Sha512Argon2id(server_setup),
				RegistrationRequest::Curve25519Sha512Argon2id(request),
			) => {
				let response =
					opaque_ke::ServerRegistration::start(server_setup, request, &[])?.message;
				Ok((
					Self::Curve25519Sha512Argon2id,
					RegistrationResponse::Curve25519Sha512Argon2id(response),
				))
			}
			#[allow(unreachable_patterns)]
			_ => Err(Error::Config),
		}
	}

	/// [`opaque_ke::ServerRegistration::finish()`] wrapper.
	pub(crate) fn finish(self, finalization: RegistrationFinalization) -> Result<ServerFile> {
		match (self, finalization) {
			(
				Self::Curve25519Sha512Argon2id,
				RegistrationFinalization::Curve25519Sha512Argon2id(finalization),
			) => {
				let file = opaque_ke::ServerRegistration::finish(finalization);
				Ok(ServerFile::Curve25519Sha512Argon2id(file))
			}
			#[allow(unreachable_patterns)]
			_ => Err(Error::Config),
		}
	}
}

/// [`opaque_ke::ServerLogin`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum ServerLogin {
	Curve25519Sha512Argon2id(opaque_ke::ServerLogin<Curve25519Sha512Argon2id>),
}

impl ServerLogin {
	/// Return corresponding [`CipherSuite`].
	pub(crate) const fn cipher_suite(&self) -> CipherSuite {
		match self {
			ServerLogin::Curve25519Sha512Argon2id(_) => CipherSuite::Curve25519Sha512Argon2id,
		}
	}

	/// [`opaque_ke::ServerLogin::start()`] wrapper.
	pub(crate) fn login(
		setup: &ServerSetup,
		file: Option<ServerFile>,
		request: LoginRequest,
	) -> Result<(Self, LoginResponse)> {
		match (setup, request) {
			(
				ServerSetup::Curve25519Sha512Argon2id(server_setup),
				LoginRequest::Curve25519Sha512Argon2id(request),
			) => {
				let file = match file {
					Some(ServerFile::Curve25519Sha512Argon2id(file)) => Some(file),
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
					Self::Curve25519Sha512Argon2id(state),
					LoginResponse::Curve25519Sha512Argon2id(message),
				))
			}
			#[allow(unreachable_patterns)]
			_ => Err(Error::Config),
		}
	}

	/// [`opaque_ke::ClientLogin::finish()`] wrapper.
	pub(crate) fn finish(self, finalization: LoginFinalization) -> Result<()> {
		match (self, finalization) {
			(
				Self::Curve25519Sha512Argon2id(state),
				LoginFinalization::Curve25519Sha512Argon2id(finalization),
			) => {
				let result = state.finish(finalization)?;
				let ServerLoginFinishResult { .. } = result;

				Ok(())
			}
			#[allow(unreachable_patterns)]
			_ => Err(Error::Config),
		}
	}
}

/// [`opaque_ke::RegistrationRequest`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum RegistrationRequest {
	Curve25519Sha512Argon2id(opaque_ke::RegistrationRequest<Curve25519Sha512Argon2id>),
}

/// [`opaque_ke::RegistrationResponse`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum RegistrationResponse {
	Curve25519Sha512Argon2id(opaque_ke::RegistrationResponse<Curve25519Sha512Argon2id>),
}

/// [`opaque_ke::RegistrationUpload`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum RegistrationFinalization {
	Curve25519Sha512Argon2id(opaque_ke::RegistrationUpload<Curve25519Sha512Argon2id>),
}

/// [`opaque_ke::CredentialRequest`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum LoginRequest {
	Curve25519Sha512Argon2id(opaque_ke::CredentialRequest<Curve25519Sha512Argon2id>),
}

/// [`opaque_ke::CredentialResponse`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum LoginResponse {
	Curve25519Sha512Argon2id(opaque_ke::CredentialResponse<Curve25519Sha512Argon2id>),
}

/// [`opaque_ke::CredentialFinalization`] wrapper.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum LoginFinalization {
	Curve25519Sha512Argon2id(opaque_ke::CredentialFinalization<Curve25519Sha512Argon2id>),
}
