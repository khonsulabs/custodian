#![allow(clippy::module_name_repetitions)]

//! OPAQUE server side handling.

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::Error;
use crate::{
	cipher_suite, Config, LoginFinalization, LoginRequest, LoginResponse, PublicKey,
	RegistrationFinalization, RegistrationRequest, RegistrationResponse, Result,
};

/// Server configuration. This contains the secret key needed to create and use
/// [`ServerFile`]s, if it is lost, all corresponding [`ServerFile`]s become
/// unusable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerConfig(cipher_suite::ServerSetup);

impl Default for ServerConfig {
	fn default() -> Self {
		Self(cipher_suite::ServerSetup::new(Config::default().0))
	}
}

impl ServerConfig {
	/// Create a new [`ServerConfig`]. This contains the secret key needed to
	/// create and use [`ServerFile`]s, if it is lost, all corresponding
	/// [`ServerFile`]s become unusable.
	#[must_use]
	pub fn new(config: Config) -> Self {
		Self(cipher_suite::ServerSetup::new(config.0))
	}

	/// Returns the [`Config`] associated with this [`ServerConfig`].
	#[must_use]
	pub const fn config(&self) -> Config {
		Config(self.0.cipher_suite())
	}

	/// Returns the [`PublicKey`] associated with this [`ServerConfig`].
	#[must_use]
	pub fn public_key(&self) -> PublicKey {
		PublicKey::new(self.config(), self.0.public_key())
	}
}

/// Holds the state of a registration process. See [`register`](Self::register).
#[allow(missing_copy_implementations)]
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerRegistration {
	/// Registration process sate.
	state: cipher_suite::ServerRegistration,
	/// Public key of the corresponding [`ServerConfig`].
	public_key: PublicKey,
}

impl ServerRegistration {
	/// Returns the [`Config`] associated with this [`ServerRegistration`].
	#[must_use]
	pub const fn config(&self) -> Config {
		Config(self.state.cipher_suite())
	}

	/// Returns the [`PublicKey`] associated with this [`ServerRegistration`].
	#[must_use]
	pub const fn public_key(&self) -> PublicKey {
		self.public_key
	}

	/// Starts the registration process. The returned [`RegistrationResponse`]
	/// has to be send back to the client to drive the registration process. See
	/// [`ClientRegistration::finish()`](crate::ClientRegistration::finish).
	///
	/// # Errors
	/// - [`Error::Config`](crate::Error::Config) if [`ServerConfig`] and
	///   [`RegistrationRequest`] were not created with the same [`Config`]
	/// - [`Error::Opaque`](crate::Error::Opaque) on internal OPAQUE error
	pub fn register(
		config: &ServerConfig,
		request: RegistrationRequest,
	) -> Result<(Self, RegistrationResponse)> {
		let (state, response) = cipher_suite::ServerRegistration::register(&config.0, request.0)?;

		Ok((
			Self {
				state,
				public_key: config.public_key(),
			},
			RegistrationResponse(response),
		))
	}

	/// Finishes the registration process. The returned [`ServerFile`] is
	/// needed for the client to login. See [`ServerLogin::login()`].
	///
	/// # Errors
	/// [`Error::Config`](crate::Error::Config) if [`ServerConfig`] and
	/// [`RegistrationRequest`] were not created with the same [`Config`].
	pub fn finish(self, finalization: RegistrationFinalization) -> Result<ServerFile> {
		let file = self.state.finish(finalization.0)?;

		Ok(ServerFile {
			file,
			public_key: self.public_key,
		})
	}
}

/// Represents a registered client, this is needed for the client to login. See
/// [`ServerLogin::login()`].
#[must_use = "Without this the client can't login"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerFile {
	/// Password envelope.
	file: cipher_suite::ServerFile,
	/// Public key of the corresponding [`ServerConfig`].
	public_key: PublicKey,
}

impl ServerFile {
	/// Returns the [`Config`] associated with this [`ServerFile`].
	#[must_use]
	pub const fn config(&self) -> Config {
		Config(self.file.cipher_suite())
	}

	/// Returns the [`PublicKey`] associated with this [`ServerFile`].
	#[must_use]
	pub const fn public_key(&self) -> PublicKey {
		self.public_key
	}
}

/// Starts the login process on the server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[must_use = "Does nothing if not `finish`ed"]
pub struct ServerLogin(cipher_suite::ServerLogin);

impl ServerLogin {
	/// Returns the [`Config`] associated with this [`ServerRegistration`].
	#[must_use]
	pub const fn config(&self) -> Config {
		Config(self.0.cipher_suite())
	}

	/// Starts the login process. The returned [`LoginResponse`] has to
	/// be send back to the client to drive the login process. See
	/// [`ClientLogin::finish()`](crate::ClientLogin::finish).
	///
	/// If a client is registered, pass the appropriate [`ServerFile`], pass
	/// [`None`] otherwise. Passing [`None`] simulates a login attempt in a way
	/// that doesn't let an attacker determine if a corresponding client is
	/// registered or not.
	///
	/// # Errors
	/// - [`Error::Config`] if [`ServerConfig`], [`ServerFile`] or
	///   [`LoginRequest`] were not created with the same [`Config`]
	/// - [`Error::ServerConfig`] if [`ServerFile`] was not created with the
	///   same [`ServerConfig`]
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn login(
		config: &ServerConfig,
		file: Option<ServerFile>,
		request: LoginRequest,
	) -> Result<(Self, LoginResponse)> {
		let (state, response) = cipher_suite::ServerLogin::login(
			&config.0,
			file.map(|file| (file.file, file.public_key.key)),
			request.0,
		)?;

		Ok((Self(state), LoginResponse(response)))
	}

	/// Finishes the login process.
	///
	/// # Errors
	/// [`Error::Opaque`](crate::Error::Opaque) on internal OPAQUE error.
	pub fn finish(self, finalization: LoginFinalization) -> Result<()> {
		self.0.finish(finalization.0)
	}
}
