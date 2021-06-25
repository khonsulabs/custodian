//! Message object passed between server and client during login and
//! registration.

use opaque_ke::{CredentialFinalization, CredentialRequest, CredentialResponse};
use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;

/// Send this to the server to drive the registration process. See
/// [`ServerRegistration::register()`](crate::ServerRegistration::register).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationRequest(pub(crate) opaque_ke::RegistrationRequest<CipherSuite>);

/// Send this back to the client to drive the registration process. See
/// [`ClientRegistration::finish()`](crate::ClientRegistration::finish).
#[must_use = "Does nothing if not sent to the client"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationResponse(pub(crate) opaque_ke::RegistrationResponse<CipherSuite>);

/// Send this back to the server to finish the registration process. See
/// [`ServerRegistration::finish()`](crate::ServerRegistration::finish).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RegistrationFinalization(pub(crate) opaque_ke::RegistrationUpload<CipherSuite>);

/// Send this to the server to drive the login process. See
/// [`ServerLogin::login()`](crate::ServerLogin::login).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginRequest(pub(crate) CredentialRequest<CipherSuite>);

/// Send this back to the client to drive the login process. See
/// [`ClientLogin::finish()`](crate::ClientLogin::finish).
#[must_use = "Does nothing if not sent to the client"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginResponse(pub(crate) CredentialResponse<CipherSuite>);

/// Send this back to the client to finish the login process. See
/// [`ClientLogin::finish()`](crate::ClientLogin::finish).
#[must_use = "Does nothing if not sent to the server"]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginFinalization(pub(crate) CredentialFinalization<CipherSuite>);
