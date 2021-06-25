#![allow(clippy::module_name_repetitions)]

//! OPAQUE client side handling.

use opaque_ke::{
	errors::{PakeError, ProtocolError},
	rand::rngs::OsRng,
	ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
	ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
};
use serde::{Deserialize, Serialize};

use crate::{
	CipherSuite, Config, Error, ExportKey, LoginFinalization, LoginRequest, LoginResponse,
	PublicKey, RegistrationFinalization, RegistrationRequest, RegistrationResponse, Result,
};

/// Client configuration.
#[allow(missing_copy_implementations)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientConfig {
	/// Common config.
	config: Config,
	/// Server key pair.
	public_key: Option<PublicKey>,
}

impl ClientConfig {
	/// Create a new [`ClientConfig`].
	///
	/// A [public key](PublicKey) can be used to ensure the servers identity
	/// during registration or login. If no [`PublicKey`] could be obtained
	/// before registration or login, it can be retrieved after successful
	/// registration or login.
	#[must_use]
	pub const fn new(config: Config, public_key: Option<PublicKey>) -> Self {
		Self { config, public_key }
	}

	/// Returns the [`Config`] associated with this [`ClientConfig`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the [`PublicKey`] associated with this [`ClientConfig`].
	#[must_use]
	pub const fn public_key(self) -> Option<PublicKey> {
		self.public_key
	}

	/// Sets the [`PublicKey`] to validate the server during registration or
	/// login.
	pub fn set_public_key(&mut self, public_key: Option<PublicKey>) -> &mut Self {
		self.public_key = public_key;
		self
	}
}

/// Starts a registration process. See [`register`](Self::register).
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientRegistration {
	/// Common password config.
	config: Config,
	/// Server public key.
	public_key: Option<PublicKey>,
	/// Client registration state.
	state: opaque_ke::ClientRegistration<CipherSuite>,
}

impl ClientRegistration {
	/// Returns [`Config`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the configured server public key for validation.
	#[must_use]
	pub const fn public_key(&self) -> Option<PublicKey> {
		self.public_key
	}

	/// Starts the registration process. The returned [`RegistrationRequest`]
	/// has to be send to the server to drive the registration process. See
	/// [`ServerRegistration::register()`](crate::ServerRegistration::register).
	///
	/// # Errors
	/// [`Error::Opaque`] on internal OPAQUE error.
	pub fn register<P: AsRef<[u8]>>(
		config: &ClientConfig,
		password: P,
	) -> Result<(Self, RegistrationRequest)> {
		use opaque_ke::ClientRegistrationStartResult;

		let result = opaque_ke::ClientRegistration::start(&mut OsRng, password.as_ref())?;
		let ClientRegistrationStartResult { state, message } = result;

		Ok((
			Self {
				config: config.config,
				public_key: config.public_key,
				state,
			},
			RegistrationRequest(message),
		))
	}

	/// Finishes the registration process. The returned
	/// [`RegistrationFinalization`] has to be send back to the server to finish
	/// the registration process. See
	/// [`ServerRegistration::finish()`](crate::ServerRegistration::finish).
	///
	/// [`ClientFile`] can be used to validate the server during login. See
	/// [`ClientLogin::login()`].
	///
	/// [`ExportKey`] can be used to encrypt data and store it on safely on
	/// the server. See [`ExportKey`] for more details.
	///
	/// # Errors
	/// - [`Error::InvalidServer`] if the public key given in
	///   [`register()`](Self::register) does not match the servers public key
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn finish(
		self,
		response: RegistrationResponse,
	) -> Result<(ClientFile, RegistrationFinalization, ExportKey)> {
		let public_key = if let Some(public_key) = self.public_key {
			if !public_key.is_opaque(response.0.public_key()) {
				return Err(Error::InvalidServer);
			}

			public_key
		} else {
			PublicKey::from_opaque(response.0.public_key())
		};

		let result = self.state.finish(
			&mut OsRng,
			response.0,
			ClientRegistrationFinishParameters::default(),
		)?;
		let ClientRegistrationFinishResult {
			message,
			export_key,
		} = result;

		Ok((
			ClientFile {
				config: self.config,
				public_key,
			},
			RegistrationFinalization(message),
			ExportKey(export_key.into()),
		))
	}
}

/// Store this to enable server validation during login.
#[allow(missing_copy_implementations)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientFile {
	/// Persistant [`Config`] between login and registration.
	config: Config,
	/// Server public key.
	public_key: PublicKey,
}

impl ClientFile {
	/// Returns the [`Config`] associated with this [`ClientFile`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the [`PublicKey`] associated with this [`ClientFile`].
	#[must_use]
	pub const fn public_key(self) -> PublicKey {
		self.public_key
	}
}

/// Starts the login process on the client.
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientLogin {
	/// Common config.
	config: Config,
	/// Server public key.
	public_key: Option<PublicKey>,
	/// Client login state.
	state: opaque_ke::ClientLogin<CipherSuite>,
}

impl ClientLogin {
	/// Starts the login process. The returned [`LoginRequest`] has to be send
	/// to the server to drive the login process. See
	/// [`ServerLogin::login()`](crate::ServerLogin::login).
	///
	/// If a [`ClientFile`] was stored during registration, it can help validate
	/// the server when passed.
	///
	/// # Errors
	/// - [`Error::Config`] if [`ClientConfig`] and [`ClientFile`] were not
	///   created with the same [`Config`]
	/// - [`Error::PublicKey`] if [`PublicKey`] in [`ClientConfig`] and
	///   [`ClientFile`] don't match
	/// - [`Error::Opaque`] on internal OPAQUE error
	#[allow(clippy::needless_pass_by_value)]
	pub fn login<P: AsRef<[u8]>>(
		config: &ClientConfig,
		file: Option<ClientFile>,
		password: P,
	) -> Result<(Self, LoginRequest)> {
		let public_key = if let Some(file) = &file {
			if file.config != config.config {
				return Err(Error::Config);
			}

			if let Some(public_key) = config.public_key {
				if public_key != file.public_key {
					return Err(Error::PublicKey);
				}
			}

			Some(file.public_key)
		} else {
			config.public_key
		};

		let result = opaque_ke::ClientLogin::start(&mut OsRng, password.as_ref())?;
		let ClientLoginStartResult { state, message } = result;

		Ok((
			Self {
				config: config.config,
				public_key,
				state,
			},
			LoginRequest(message),
		))
	}

	/// Finishes the login process. The returned [`LoginFinalization`] has to be
	/// send back to the server to finish the login process.
	///
	/// [`ClientFile`] can be used to validate the server during the next login.
	/// See [`login()`](Self::login).
	///
	/// [`ExportKey`] can be used to encrypt data and store it on safely on
	/// the server. See [`ExportKey`] for more details.
	///
	/// # Errors
	/// - [`Error::Credentials`] if credentials don't match
	/// - [`Error::InvalidServer`] if the public key given in
	///   [`login()`](Self::login) does not match the servers public key
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn finish(
		self,
		response: LoginResponse,
	) -> Result<(ClientFile, LoginFinalization, ExportKey)> {
		let result = match self
			.state
			.finish(response.0, ClientLoginFinishParameters::default())
		{
			Ok(result) => result,
			Err(ProtocolError::VerificationError(PakeError::InvalidLoginError)) =>
				return Err(Error::Credentials),
			Err(error) => return Err(error.into()),
		};
		let ClientLoginFinishResult {
			message,
			export_key,
			server_s_pk,
			..
		} = result;

		let public_key = if let Some(public_key) = self.public_key {
			if !public_key.is_opaque(&server_s_pk) {
				return Err(Error::InvalidServer);
			}

			public_key
		} else {
			PublicKey::from_opaque(&server_s_pk)
		};

		Ok((
			ClientFile {
				config: self.config,
				public_key,
			},
			LoginFinalization(message),
			ExportKey(export_key.into()),
		))
	}
}
