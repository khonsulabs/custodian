//! Common trait implementations for [`ServerRegistration`].

use std::{
	cmp::Ordering,
	fmt,
	fmt::{Debug, Formatter},
	hash::{Hash, Hasher},
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::{LoginState, ServerRegistration};

impl Debug for LoginState {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("LoginState")
			.field(&"opaque_ke::ServerLogin<CipherSuite>")
			.finish()
	}
}

impl Clone for LoginState {
	fn clone(&self) -> Self {
		Self(opaque_ke::ServerLogin::deserialize(&self.0.serialize()).expect("failed to clone"))
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
		let state = opaque_ke::ServerLogin::deserialize(&bytes).map_err(de::Error::custom)?;
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

impl Debug for ServerRegistration {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("State")
			.field(&"opaque_ke::ServerRegistration<CipherSuite>")
			.finish()
	}
}

impl Clone for ServerRegistration {
	fn clone(&self) -> Self {
		Self(
			opaque_ke::ServerRegistration::deserialize(&self.0.serialize())
				.expect("failed to clone"),
		)
	}
}

impl Eq for ServerRegistration {}

impl PartialEq for ServerRegistration {
	fn eq(&self, other: &Self) -> bool {
		self.0.serialize().eq(&other.0.serialize())
	}
}

impl Ord for ServerRegistration {
	fn cmp(&self, other: &Self) -> Ordering {
		self.0.serialize().cmp(&other.0.serialize())
	}
}

impl PartialOrd for ServerRegistration {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		self.0.serialize().partial_cmp(&other.0.serialize())
	}
}

impl Hash for ServerRegistration {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.0.serialize().hash(state);
	}
}

impl<'de> Deserialize<'de> for ServerRegistration {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let bytes = Vec::deserialize(deserializer)?;
		let state =
			opaque_ke::ServerRegistration::deserialize(&bytes).map_err(de::Error::custom)?;
		Ok(Self(state))
	}
}

impl Serialize for ServerRegistration {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let state = self.0.serialize();
		serializer.serialize_bytes(&state)
	}
}
