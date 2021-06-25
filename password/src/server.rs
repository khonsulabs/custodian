#![allow(clippy::module_name_repetitions)]

//! OPAQUE server side handling.

use opaque_ke::{
	rand::rngs::OsRng, ServerLoginStartParameters, ServerLoginStartResult, ServerSetup,
};
use serde::{Deserialize, Serialize};

use crate::{
	CipherSuite, Config, Error, LoginFinalization, LoginRequest, LoginResponse, PublicKey,
	RegistrationFinalization, RegistrationRequest, RegistrationResponse, Result,
};

/// Server configuration. This contains the secret key needed to create and use
/// [`ServerFile`]s, if it is lost, all [`ServerFile`]s become unusable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerConfig {
	/// Common config.
	config: Config,
	/// Server key pair.
	key_pair: ServerSetup<CipherSuite>,
}

impl ServerConfig {
	/// Create a new [`ServerConfig`]. This contains the secret key needed to
	/// create and use [`ServerFile`]s, if it is lost, all corresponding
	/// [`ServerFile`]s become unusable.
	#[must_use]
	pub fn new(config: Config) -> Self {
		let key_pair = ServerSetup::new(&mut OsRng);

		Self { config, key_pair }
	}

	/// Returns the [`Config`] associated with this [`ServerConfig`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the [`PublicKey`] associated with this [`ServerConfig`].
	#[must_use]
	pub fn public_key(&self) -> PublicKey {
		PublicKey::from_opaque(self.key_pair.keypair().public())
	}
}

/// Starts a registration process on the server. See
/// [`register`](Self::register).
#[allow(missing_copy_implementations)]
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerRegistration {
	/// Common config.
	config: Config,
}

impl ServerRegistration {
	/// Starts the registration process. The returned [`RegistrationResponse`]
	/// has to be send back to the client to drive the registration process. See
	/// [`ClientRegistration::finish()`](crate::ClientRegistration::finish).
	///
	/// # Errors
	/// [`Error::Opaque`] on internal OPAQUE error.
	pub fn register(
		config: &ServerConfig,
		request: RegistrationRequest,
	) -> Result<(Self, RegistrationResponse)> {
		let message =
			opaque_ke::ServerRegistration::start(&config.key_pair, request.0, &[])?.message;

		Ok((
			Self {
				config: config.config,
			},
			RegistrationResponse(message),
		))
	}

	/// Finishes the registration process. The returned [`ServerFile`] is
	/// needed for [`login`](ServerLogin::login), typically this is saved in a
	/// database.
	pub fn finish(self, finalization: RegistrationFinalization) -> ServerFile {
		let file = opaque_ke::ServerRegistration::finish(finalization.0);

		ServerFile {
			config: self.config,
			file,
		}
	}
}

/// Represents a registered client, store this to to allow login. See
/// [`ServerLogin::login`].
#[must_use = "This data has to stored for login to function"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServerFile {
	/// Common config.
	config: Config,
	/// Password file.
	file: opaque_ke::ServerRegistration<CipherSuite>,
}

/// Starts the login process on the server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[must_use = "Does nothing if not `finish`ed"]
pub struct ServerLogin {
	/// Common config.
	config: Config,
	/// Client login state.
	state: opaque_ke::ServerLogin<CipherSuite>,
}

impl ServerLogin {
	/// Starts the login process. The returned [`LoginResponse`] has to
	/// be send back to the client to drive the login process. See
	/// [`ClientLogin::finish()`](crate::ClientLogin::finish).
	///
	/// If no corresponding client was registered, pass [`None`] to `file`,
	/// otherwise pass the appropriate [`ServerFile`]. Passing [`None`]
	/// simulates a login attempt in a way that doesn't let an attacker
	/// determine if a corresponding client is registered or not.
	///
	/// # Errors
	/// - [`Error::Config`] if [`ServerConfig`] and [`ServerFile`] were not
	///   created with the same [`Config`]
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn login(
		config: &ServerConfig,
		file: Option<ServerFile>,
		request: LoginRequest,
	) -> Result<(Self, LoginResponse)> {
		if let Some(file) = &file {
			if file.config != config.config {
				return Err(Error::Config);
			}
		}

		let result = opaque_ke::ServerLogin::start(
			&mut OsRng,
			&config.key_pair,
			file.map(|file| file.file),
			request.0,
			&[],
			ServerLoginStartParameters::default(),
		)?;
		let ServerLoginStartResult { state, message } = result;

		Ok((
			Self {
				config: config.config,
				state,
			},
			LoginResponse(message),
		))
	}

	/// Finishes the login process.
	///
	/// # Errors
	/// [`Error::Opaque`] on internal OPAQUE error.
	pub fn finish(self, finalization: LoginFinalization) -> Result<()> {
		let _result = self.state.finish(finalization.0)?;

		Ok(())
	}
}
