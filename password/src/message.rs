//! Message object passed between server and client during login and
//! registration.

use serde::{Deserialize, Serialize};

use crate::{cipher_suite, Config};

/// Send this to the server to drive the registration process. See
/// [`ServerRegistration::register()`](crate::ServerRegistration::register).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationRequest {
	/// [`Config`] used to create this [`RegistrationRequest`].
	pub(crate) config: Config,
	/// Wrapped [opaque-ke](opaque_ke) type.
	pub(crate) message: cipher_suite::RegistrationRequest,
}

impl RegistrationRequest {
	/// Returns [`Config`] used to create this [`RegistrationRequest`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}

/// Send this back to the client to drive the registration process. See
/// [`ClientRegistration::finish()`](crate::ClientRegistration::finish).
#[must_use = "Does nothing if not sent to the client"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationResponse {
	/// [`Config`] used to create this [`RegistrationResponse`].
	pub(crate) config: Config,
	/// Wrapped [opaque-ke](opaque_ke) type.
	pub(crate) message: cipher_suite::RegistrationResponse,
}

impl RegistrationResponse {
	/// Returns [`Config`] used to create this [`RegistrationResponse`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}

/// Send this back to the server to finish the registration process. See
/// [`ServerRegistration::finish()`](crate::ServerRegistration::finish).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RegistrationFinalization {
	/// [`Config`] used to create this [`RegistrationFinalization`].
	pub(crate) config: Config,
	/// Wrapped [opaque-ke](opaque_ke) type.
	pub(crate) message: cipher_suite::RegistrationFinalization,
}

impl RegistrationFinalization {
	/// Returns [`Config`] used to create this [`RegistrationFinalization`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}

/// Send this to the server to drive the login process. See
/// [`ServerLogin::login()`](crate::ServerLogin::login).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginRequest {
	/// [`Config`] used to create this [`LoginRequest`].
	pub(crate) config: Config,
	/// Wrapped [opaque-ke](opaque_ke) type.
	pub(crate) message: cipher_suite::LoginRequest,
}

impl LoginRequest {
	/// Returns [`Config`] used to create this [`LoginRequest`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}

/// Send this back to the client to drive the login process. See
/// [`ClientLogin::finish()`](crate::ClientLogin::finish).
#[must_use = "Does nothing if not sent to the client"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginResponse {
	/// [`Config`] used to create this [`LoginResponse`].
	pub(crate) config: Config,
	/// Wrapped [opaque-ke](opaque_ke) type.
	pub(crate) message: cipher_suite::LoginResponse,
}

impl LoginResponse {
	/// Returns [`Config`] used to create this [`LoginResponse`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}

/// Send this back to the server to finish the login process. See
/// [`ClientLogin::finish()`](crate::ClientLogin::finish).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LoginFinalization {
	/// [`Config`] used to create this [`LoginFinalization`].
	pub(crate) config: Config,
	/// Wrapped [opaque-ke](opaque_ke) type.
	pub(crate) message: cipher_suite::LoginFinalization,
}

impl LoginFinalization {
	/// Returns [`Config`] used to create this [`LoginFinalization`].
	#[must_use]
	pub const fn config(&self) -> Config {
		self.config
	}
}
