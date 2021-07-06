#![allow(clippy::module_name_repetitions)]

//! OPAQUE client side handling.

use opaque_ke::errors::{PakeError, ProtocolError};
use serde::{Deserialize, Serialize};

use crate::{
	cipher_suite, Config, Error, ExportKey, LoginFinalization, LoginRequest, LoginResponse,
	PublicKey, RegistrationFinalization, RegistrationRequest, RegistrationResponse, Result,
};

/// Client configuration.
#[allow(missing_copy_implementations)]
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientConfig {
	/// Common config.
	config: Config,
	/// Server key pair.
	public_key: Option<PublicKey>,
}

impl ClientConfig {
	/// Create a new [`ClientConfig`].
	///
	/// A [`PublicKey`] can be used to ensure the servers identity
	/// during registration or login. If no [`PublicKey`] could be obtained
	/// beforehand, it can be retrieved after successful registration or login.
	///
	/// # Errors
	/// [`Error::Config`] if [`PublicKey`] was not created with the same
	/// [`Config`].
	pub fn new(config: Config, public_key: Option<PublicKey>) -> Result<Self> {
		if let Some(public_key) = public_key {
			if public_key.config != config {
				return Err(Error::Config);
			}
		}

		Ok(Self { config, public_key })
	}

	/// Returns the [`Config`] associated with this [`ClientConfig`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}

	/// Returns the [`PublicKey`] associated with this [`ClientConfig`].
	#[must_use]
	pub const fn public_key(&self) -> Option<PublicKey> {
		self.public_key
	}
}

/// Holds the state of a registration process. See [`register`](Self::register).
#[must_use = "Use `finish()` to complete the registration process"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientRegistration {
	/// Client registration state.
	state: cipher_suite::ClientRegistration,
	/// Server public key.
	public_key: Option<PublicKey>,
}

impl ClientRegistration {
	/// Returns the [`Config`] associated with this [`ClientRegistration`].
	#[must_use]
	pub const fn config(&self) -> Config {
		Config(self.state.cipher_suite())
	}

	/// Returns the servers [`PublicKey`] associated with this [`ClientFile`].
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
		let (state, message) =
			cipher_suite::ClientRegistration::register(config.config.0, password.as_ref())?;

		Ok((
			Self {
				state,
				public_key: config.public_key,
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
	/// [`ExportKey`] can be used to encrypt data and store it safely on
	/// the server. See [`ExportKey`] for more details.
	///
	/// # Errors
	/// - [`Error::Config`] if [`ClientRegistration`] and
	///   [`RegistrationResponse`] were not created with the same [`Config`]
	/// - [`Error::InvalidServer`] if the public key given in
	///   [`register()`](Self::register) does not match the servers public key
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn finish(
		self,
		response: RegistrationResponse,
	) -> Result<(ClientFile, RegistrationFinalization, ExportKey)> {
		let config = self.config();
		let (finalization, new_public_key, export_key) = self.state.finish(response.0)?;

		let public_key = if let Some(public_key) = self.public_key {
			if public_key.key != new_public_key {
				return Err(Error::InvalidServer);
			}

			public_key
		} else {
			PublicKey::new(config, new_public_key)
		};

		Ok((
			ClientFile(public_key),
			RegistrationFinalization(finalization),
			ExportKey::new(config, export_key),
		))
	}
}

/// Use this to enable server validation during login.
#[allow(missing_copy_implementations)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientFile(PublicKey);

impl ClientFile {
	/// Returns the [`Config`] associated with this [`ClientFile`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.0.config
	}

	/// Returns the servers [`PublicKey`] associated with this [`ClientFile`].
	#[must_use]
	pub const fn public_key(&self) -> PublicKey {
		self.0
	}
}

/// Holds the state of a login process. See [`login`](Self::login).
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ClientLogin {
	/// Client login state.
	state: cipher_suite::ClientLogin,
	/// Server public key.
	public_key: Option<PublicKey>,
}

impl ClientLogin {
	/// Returns the [`Config`] associated with this [`ClientLogin`].
	#[must_use]
	pub const fn config(&self) -> Config {
		Config(self.state.cipher_suite())
	}

	/// Returns the servers [`ClientLogin`] associated with this [`ClientFile`].
	#[must_use]
	pub const fn public_key(&self) -> Option<PublicKey> {
		self.public_key
	}

	/// Starts the login process. The returned [`LoginRequest`] has to be send
	/// to the server to drive the login process. See
	/// [`ServerLogin::login()`](crate::ServerLogin::login).
	///
	/// If a [`ClientFile`] was stored during registration, it can validate the
	/// server when passed.
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
			if file.0.config != config.config {
				return Err(Error::Config);
			}

			if let Some(public_key) = config.public_key {
				if public_key != file.0 {
					return Err(Error::PublicKey);
				}
			}

			Some(file.0)
		} else {
			config.public_key
		};

		let (state, request) =
			cipher_suite::ClientLogin::login(config.config.0, password.as_ref())?;

		Ok((Self { state, public_key }, LoginRequest(request)))
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
	/// - [`Error::Config`] if [`ClientLogin`] and [`LoginResponse`] were not
	///   created with the same [`Config`]
	/// - [`Error::Credentials`] if credentials don't match
	/// - [`Error::InvalidServer`] if the public key given in
	///   [`login()`](Self::login) does not match the servers public key
	/// - [`Error::Opaque`] on internal OPAQUE error
	pub fn finish(
		self,
		response: LoginResponse,
	) -> Result<(ClientFile, LoginFinalization, ExportKey)> {
		let config = Config(self.state.cipher_suite());
		let (finalization, new_public_key, export_key) = match self.state.finish(response.0) {
			Ok(result) => result,
			Err(Error::Opaque(ProtocolError::VerificationError(PakeError::InvalidLoginError))) =>
				return Err(Error::Credentials),
			Err(error) => return Err(error),
		};

		let public_key = if let Some(public_key) = self.public_key {
			if public_key.key != new_public_key {
				return Err(Error::InvalidServer);
			}

			public_key
		} else {
			PublicKey::new(config, new_public_key)
		};

		Ok((
			ClientFile(public_key),
			LoginFinalization(finalization),
			ExportKey::new(config, export_key),
		))
	}
}
