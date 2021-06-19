//! OPAQUE client side handling.

mod impls;

use opaque_ke::{
	rand::rngs::OsRng, ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters,
	ClientRegistration, ClientRegistrationFinishParameters,
};
use serde::{Deserialize, Serialize};

use crate::{server, CipherSuite, Config, Error, Result};

/// Starts a login process on the client.
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Login {
	/// Common config.
	config: Config,
	/// Client login state.
	state: LoginState,
}

impl Login {
	/// Starts the login process. The returned [`LoginRequest`] has to be send
	/// to the server to drive the login process.
	///
	/// # Errors
	/// [`Error::Login`] on login failure.
	pub fn login(config: Config, password: &[u8]) -> Result<(Self, LoginRequest)> {
		let result = ClientLogin::<CipherSuite>::start(
			&mut OsRng,
			password,
			ClientLoginStartParameters::default(),
		)
		.map_err(|_| Error::Login)?;

		let state = LoginState(result.state);
		let message = LoginRequest(result.message.serialize());

		Ok((Self { config, state }, message))
	}

	/// Finishes the login. The returned [`LoginResponse`] has to be send back
	/// to the server to finish the login process. Authentication is successful
	/// if this returns [`Ok`].
	///
	/// # Errors
	/// [`Error::Login`] on login failure.
	pub fn finish(self, response: &server::LoginResponse) -> Result<LoginResponse> {
		let response = opaque_ke::CredentialResponse::deserialize(response.message())
			.map_err(|_| Error::Login)?;

		let result = self
			.state
			.0
			.finish(response, ClientLoginFinishParameters::default())
			.map_err(|_| Error::Login)?;

		Ok(LoginResponse(result.message.serialize()))
	}
}

/// Starts a registration process on the client.
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Register {
	/// Common password config.
	config: Config,
	/// Client registration state.
	state: RegisterState,
}

impl Register {
	/// Starts the registration process. The returned [`RegistrationRequest`]
	/// has to be send to the server to drive the registration process.
	///
	/// # Errors
	/// [`Error::Registration`] on registration failure.
	pub fn register(config: Config, password: &[u8]) -> Result<(Self, RegistrationRequest)> {
		let result = opaque_ke::ClientRegistration::<CipherSuite>::start(&mut OsRng, password)
			.map_err(|_| Error::Registration)?;

		let state = RegisterState(result.state);
		let message = RegistrationRequest(result.message.serialize());

		Ok((Self { config, state }, message))
	}

	/// Finishes the registration. The returned [`RegistrationResponse`]
	/// has to be send back to the server to finish the registration process.
	///
	/// # Errors
	/// [`Error::Registration`] on registration failure.
	pub fn finish(self, response: &server::RegistrationResponse) -> Result<RegistrationResponse> {
		let response = opaque_ke::RegistrationResponse::deserialize(response.message())
			.map_err(|_| Error::Registration)?;

		let result = self
			.state
			.0
			.finish(
				&mut OsRng,
				response,
				ClientRegistrationFinishParameters::default(),
			)
			.map_err(|_| Error::Registration)?;

		Ok(RegistrationResponse(result.message.serialize()))
	}
}

/// Wraps around [`ClientLogin`] because common traits aren't implemented in the
/// dependency.
struct LoginState(ClientLogin<CipherSuite>);

/// Wraps around [`ClientRegistration`] because common traits aren't implemented
/// in the dependency.
struct RegisterState(ClientRegistration<CipherSuite>);

/// Send this back to the server to finish the registration process.
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LoginResponse(Vec<u8>);

impl LoginResponse {
	/// Getter for message.
	pub(crate) fn message(&self) -> &[u8] {
		&self.0
	}
}

/// Send this to the server to drive the login process.
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LoginRequest(Vec<u8>);

impl LoginRequest {
	/// Getter for message.
	pub(crate) fn message(&self) -> &[u8] {
		&self.0
	}
}

/// Send this to the server to drive the registration process.
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RegistrationRequest(Vec<u8>);

impl RegistrationRequest {
	/// Getter for message.
	pub(crate) fn message(&self) -> &[u8] {
		&self.0
	}
}

/// Send this to the server to finish the registration.
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RegistrationResponse(Vec<u8>);

impl RegistrationResponse {
	/// Getter for message.
	pub(crate) fn message(&self) -> &[u8] {
		&self.0
	}
}
