//! OPAQUE server side handling.

mod impls;

use generic_bytes::SizedBytes;
use opaque_ke::{
	ciphersuite::CipherSuite, keypair::Key, rand::rngs::OsRng, CredentialRequest,
	RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters,
};
use serde::{Deserialize, Serialize};

use crate::{
	client::{self, LoginRequest},
	Config, Error, Result,
};

/// Login process on the server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[must_use = "Does nothing if not `finish`ed"]
pub struct Login {
	/// Common config.
	config: Config,
	/// Client login state.
	state: LoginState,
}

impl Login {
	/// Finishes the login. Authentication is successful if this returns [`Ok`].
	///
	/// # Errors
	/// [`Error::Login`] on login failure.
	pub fn finish(self, response: &client::LoginResponse) -> Result<()> {
		let response = opaque_ke::CredentialFinalization::deserialize(response.message())
			.map_err(|_| Error::Login)?;

		let _result = self.state.0.finish(response).map_err(|_| Error::Login)?;

		Ok(())
	}
}

/// Registration object needed to [`login`](Self::login). Typically this is
/// saved in a database.
#[must_use = "Does nothing if not used to `login`"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Registration {
	/// Common config.
	config: Config,
	/// Password file.
	file: ServerRegistration,
	/// Private key.
	private_key: [u8; 32],
}

impl Registration {
	/// Starts the login process. The returned [`RegistrationResponse`] has to
	/// be send back to the client to drive the login process.
	///
	/// # Errors
	/// [`Error::Login`] on login failure.
	pub fn login(self, request: &LoginRequest) -> Result<(Login, LoginResponse)> {
		let key = Key::from_arr(&self.private_key.into()).map_err(|_| Error::Login)?;
		let request =
			CredentialRequest::deserialize(request.message()).map_err(|_| Error::Login)?;

		let result = ServerLogin::start(
			&mut OsRng,
			self.file.0,
			&key,
			request,
			ServerLoginStartParameters::default(),
		)
		.map_err(|_| Error::Login)?;

		let state = LoginState(result.state);
		let message = LoginResponse(result.message.serialize());

		Ok((
			Login {
				config: self.config,
				state,
			},
			message,
		))
	}
}

/// Starts a registration process on the server.
#[must_use = "Does nothing if not `finish`ed"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RegistrationBuilder {
	/// Common config.
	config: Config,
	/// Private key.
	private_key: [u8; 32],
	/// Server registration state.
	state: ServerRegistration,
}

impl RegistrationBuilder {
	/// Starts the registration process. The returned [`RegistrationResponse`]
	/// has to be send back to the client to drive the registration process.
	///
	/// # Errors
	/// [`Error::Registration`] on registration failure.
	pub fn register(
		config: Config,
		request: &client::RegistrationRequest,
	) -> Result<(Self, RegistrationResponse)> {
		let request =
			RegistrationRequest::deserialize(request.message()).map_err(|_| Error::Registration)?;
		let keypair = Config::generate_random_keypair(&mut OsRng);

		let result =
			opaque_ke::ServerRegistration::<Config>::start(&mut OsRng, request, keypair.public())
				.map_err(|_| Error::Registration)?;

		let private_key = keypair.private().to_arr().into();
		let state = ServerRegistration(result.state);
		let message = RegistrationResponse(result.message.serialize());

		Ok((
			Self {
				config,
				private_key,
				state,
			},
			message,
		))
	}

	/// Finishes the registration process. The returned [`Registration`] is
	/// needed for [`login`](Registration::login), typically this is saved in a
	/// database.
	///
	/// # Errors
	/// [`Error::Registration`] on registration failure.
	pub fn finish(self, response: &client::RegistrationResponse) -> Result<Registration> {
		let response =
			RegistrationUpload::deserialize(response.message()).map_err(|_| Error::Registration)?;

		let file = self
			.state
			.0
			.finish(response)
			.map_err(|_| Error::Registration)?;

		Ok(Registration {
			config: self.config,
			file: ServerRegistration(file),
			private_key: self.private_key,
		})
	}
}

/// Wraps around [`ServerLogin`](ServerLogin) because common traits aren't
/// implemented in the dependency.
struct LoginState(ServerLogin<Config>);

/// Wraps around [`ServerRegistration`](opaque_ke::ServerRegistration) because
/// common traits aren't implemented in the dependency.
struct ServerRegistration(opaque_ke::ServerRegistration<Config>);

/// Send this back to the client to drive the login process.
#[must_use = "Does nothing if not sent to the client"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LoginResponse(Vec<u8>);

impl LoginResponse {
	/// Getter for message.
	pub(crate) fn message(&self) -> &[u8] {
		&self.0
	}
}

/// Send this back to the client to drive the registration process.
#[must_use = "Does nothing if not sent to the client"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RegistrationResponse(Vec<u8>);

impl RegistrationResponse {
	/// Getter for message.
	pub(crate) fn message(&self) -> &[u8] {
		&self.0
	}
}
