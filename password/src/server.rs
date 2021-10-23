#![allow(clippy::module_name_repetitions)]

//! OPAQUE server side handling.

use serde::{Deserialize, Serialize};

use crate::{
	cipher_suite::{self, ServerSetup},
	Config, Error, LoginFinalization, LoginRequest, LoginResponse, PublicKey,
	RegistrationFinalization, RegistrationRequest, RegistrationResponse, Result,
};

/// Server configuration. This contains the secret key needed to create and use
/// [`ServerFile`]s, if it is lost, all corresponding [`ServerFile`]s become
/// unusable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerConfig {
	/// [`Config`] of this [`ServerConfig`].
	config: Config,
	/// Holds the private key and OPRF seed.
	setup: ServerSetup,
}

impl Default for ServerConfig {
	fn default() -> Self {
		let config = Config::default();

		Self {
			config,
			setup: ServerSetup::new(config.cipher_suite),
		}
	}
}

impl ServerConfig {
	/// Create a new [`ServerConfig`]. This contains the secret key needed to
	/// create and use [`ServerFile`]s, if it is lost, all corresponding
	/// [`ServerFile`]s become unusable.
	#[must_use]
	pub fn new(config: Config) -> Self {
		Self {
			config,
			setup: ServerSetup::new(config.cipher_suite),
		}
	}

	/// Returns the [`Config`] associated with this [`ServerConfig`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the [`PublicKey`] associated with this [`ServerConfig`].
	#[must_use]
	pub fn public_key(&self) -> PublicKey {
		PublicKey::new(self.config(), self.setup.public_key())
	}
}

/// Holds the state of a registration process. See [`register`](Self::register).
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerRegistration {
	/// [`Config`] of the corresponding [`ServerConfig`].
	config: Config,
	/// Public key of the corresponding [`ServerConfig`].
	public_key: PublicKey,
	/// Registration process sate.
	state: cipher_suite::ServerRegistration,
}

impl ServerRegistration {
	/// Returns the [`Config`] associated with this [`ServerRegistration`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
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
	/// - [`Error::Config`] if [`ServerConfig`] and [`RegistrationRequest`] were
	///   not created with the same [`Config`]
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn register(
		config: &ServerConfig,
		request: RegistrationRequest,
	) -> Result<(Self, RegistrationResponse)> {
		if config.config != request.config {
			return Err(Error::Config);
		}

		let (state, message) =
			cipher_suite::ServerRegistration::register(&config.setup, request.message)?;

		Ok((
			Self {
				config: config.config,
				public_key: config.public_key(),
				state,
			},
			RegistrationResponse {
				config: config.config,
				message,
			},
		))
	}

	/// Finishes the registration process. The returned [`ServerFile`] is
	/// needed for the client to login. See [`ServerLogin::login()`].
	///
	/// # Errors
	/// [`Error::Config`] if [`ServerConfig`] and [`RegistrationRequest`] were
	/// not created with the same [`Config`].
	pub fn finish(self, finalization: RegistrationFinalization) -> Result<ServerFile> {
		if self.config != finalization.config {
			return Err(Error::Config);
		}

		let file = self.state.finish(finalization.message)?;

		Ok(ServerFile {
			config: self.config,
			public_key: self.public_key,
			file,
		})
	}
}

/// Represents a registered client, this is needed for the client to login. See
/// [`ServerLogin::login()`].
#[must_use = "Without this the client can't login"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerFile {
	/// [`Config`] of the corresponding [`ServerConfig`].
	config: Config,
	/// Public key of the corresponding [`ServerConfig`].
	public_key: PublicKey,
	/// Password envelope.
	file: cipher_suite::ServerFile,
}

impl ServerFile {
	/// Returns the [`Config`] associated with this [`ServerFile`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
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
pub struct ServerLogin {
	/// [`Config`] of the corresponding [`ServerConfig`].
	config: Config,
	/// Public key of the corresponding [`ServerConfig`].
	public_key: PublicKey,
	/// Login process state.
	state: cipher_suite::ServerLogin,
}

impl ServerLogin {
	/// Returns the [`Config`] associated with this [`ServerLogin`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the [`PublicKey`] associated with this [`ServerLogin`].
	#[must_use]
	pub const fn public_key(&self) -> PublicKey {
		self.public_key
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
	/// - [`Error::ServerFile`] if [`ServerFile`] was not created with the same
	///   [`ServerConfig`]
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn login(
		config: &ServerConfig,
		file: Option<ServerFile>,
		request: LoginRequest,
	) -> Result<(Self, LoginResponse)> {
		if config.config != request.config {
			return Err(Error::Config);
		}

		let (state, message) = cipher_suite::ServerLogin::login(
			&config.setup,
			file.map(|file| (file.file, file.public_key.key)),
			request.message,
		)?;

		Ok((
			Self {
				config: config.config,
				public_key: config.public_key(),
				state,
			},
			LoginResponse {
				config: config.config,
				message,
			},
		))
	}

	/// Finishes the login process.
	///
	/// # Errors
	/// [`Error::Opaque`] on internal OPAQUE error.
	pub fn finish(self, finalization: LoginFinalization) -> Result<()> {
		if self.config != finalization.config {
			return Err(Error::Config);
		}

		self.state.finish(finalization.message)
	}
}
