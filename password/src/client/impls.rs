//! Common trait implementations for [`ClientRegistration`].

use std::{
	cmp::Ordering,
	fmt,
	fmt::{Debug, Formatter},
	hash::{Hash, Hasher},
};

use opaque_ke::{ClientLogin, ClientRegistration};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::{LoginState, RegisterState};

impl Debug for LoginState {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("State")
			.field(&"opaque_ke::ClientLogin<CipherSuite>")
			.finish()
	}
}

impl Clone for LoginState {
	fn clone(&self) -> Self {
		Self(ClientLogin::deserialize(&self.0.serialize()).expect("failed to clone"))
	}
}

impl Eq for LoginState {}

impl PartialEq for LoginState {
	fn eq(&self, other: &Self) -> bool {
		self.0.serialize().eq(&other.0.serialize())
	}
}

impl Ord for LoginState {
	fn cmp(&self, other: &Self) -> Ordering {
		self.0.serialize().cmp(&other.0.serialize())
	}
}

impl PartialOrd for LoginState {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		self.0.serialize().partial_cmp(&other.0.serialize())
	}
}

impl Hash for LoginState {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.0.serialize().hash(state);
	}
}

impl<'de> Deserialize<'de> for LoginState {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let bytes = Vec::deserialize(deserializer)?;
		let state = ClientLogin::deserialize(&bytes).map_err(de::Error::custom)?;
		Ok(Self(state))
	}
}

impl Serialize for LoginState {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let state = self.0.serialize();
		serializer.serialize_bytes(&state)
	}
}

impl Debug for RegisterState {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("State")
			.field(&"opaque_ke::ClientRegistration<CipherSuite>")
			.finish()
	}
}

impl Clone for RegisterState {
	fn clone(&self) -> Self {
		Self(ClientRegistration::deserialize(&self.0.serialize()).expect("failed to clone"))
	}
}

impl Eq for RegisterState {}

impl PartialEq for RegisterState {
	fn eq(&self, other: &Self) -> bool {
		self.0.serialize().eq(&other.0.serialize())
	}
}

impl Ord for RegisterState {
	fn cmp(&self, other: &Self) -> Ordering {
		self.0.serialize().cmp(&other.0.serialize())
	}
}

impl PartialOrd for RegisterState {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		self.0.serialize().partial_cmp(&other.0.serialize())
	}
}

impl Hash for RegisterState {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.0.serialize().hash(state);
	}
}

impl<'de> Deserialize<'de> for RegisterState {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let bytes = Vec::deserialize(deserializer)?;
		let state = ClientRegistration::deserialize(&bytes).map_err(de::Error::custom)?;
		Ok(Self(state))
	}
}

impl Serialize for RegisterState {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let state = self.0.serialize();
		serializer.serialize_bytes(&state)
	}
}
