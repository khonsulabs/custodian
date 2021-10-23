#![deny(unsafe_code)]
#![warn(
	clippy::cargo,
	clippy::nursery,
	clippy::pedantic,
	clippy::restriction,
	future_incompatible,
	rust_2018_idioms
)]
#![warn(
	box_pointers,
	macro_use_extern_crate,
	meta_variable_misuse,
	missing_copy_implementations,
	missing_debug_implementations,
	missing_docs,
	non_ascii_idents,
	single_use_lifetimes,
	trivial_casts,
	trivial_numeric_casts,
	unaligned_references,
	unreachable_pub,
	unused_import_braces,
	unused_lifetimes,
	unused_qualifications,
	variant_size_differences
)]
#![allow(
	clippy::blanket_clippy_restriction_lints,
	clippy::else_if_without_else,
	clippy::exhaustive_enums,
	clippy::exhaustive_structs,
	clippy::expect_used,
	clippy::future_not_send,
	clippy::implicit_return,
	clippy::map_err_ignore,
	clippy::missing_inline_in_public_items,
	clippy::non_ascii_literal,
	clippy::pattern_type_mismatch,
	clippy::redundant_pub_crate,
	clippy::shadow_reuse,
	clippy::shadow_unrelated,
	clippy::tabs_in_doc_comments,
	clippy::unreachable,
	clippy::wildcard_enum_match_arm,
	unreachable_pub,
	variant_size_differences
)]
#![cfg_attr(
	doc,
	warn(rustdoc::all),
	allow(rustdoc::missing_doc_code_examples, rustdoc::private_doc_tests)
)]
#![cfg_attr(
	test,
	allow(
		box_pointers,
		clippy::integer_arithmetic,
		clippy::panic,
		clippy::panic_in_result_fn,
		clippy::similar_names,
		clippy::unwrap_used,
	)
)]

//! TODO
// TODO: start registration and login process from `Server/ClientConfig`
// TODO: implement credential identifier
// TODO: option to save credential identifier in plaintext to support renaming
// TODO: expose custom identifier
// TODO: start `custodian-shared` for keypair types, algorithms and whatnot
// TODO: start `custodian-pki` for shared pki system and key generation
// TODO: expose server keypair with types from `custodian-shared` and enable
// optional external keypairs

pub(crate) mod cipher_suite;
mod client;
mod config;
pub mod error;
mod export_key;
mod message;
mod public_key;
mod server;

pub use arrayvec;
pub use serde;

pub use crate::{
	client::{ClientConfig, ClientFile, ClientLogin, ClientRegistration},
	config::{
		Ake, Argon2Algorithm, Argon2Params, Config, Group, Hash, Mhf, Pbkdf2Hash, Pbkdf2Params,
	},
	error::{Error, Result},
	export_key::ExportKey,
	message::{
		LoginFinalization, LoginRequest, LoginResponse, RegistrationFinalization,
		RegistrationRequest, RegistrationResponse,
	},
	public_key::PublicKey,
	server::{ServerConfig, ServerFile, ServerLogin, ServerRegistration},
};

#[test]
fn basic() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let server_config = ServerConfig::default();
	let client_config = ClientConfig::new(Config::default(), Some(server_config.public_key()))?;

	// registration process
	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;

	let (server, response) = ServerRegistration::register(&server_config, request)?;

	let (client_file, finalization, _) = client.finish(response)?;

	let server_file = server.finish(finalization)?;

	// login process
	let (client, request) = ClientLogin::login(client_config, Some(client_file), PASSWORD)?;

	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;

	let (_, finalization, _) = client.finish(response)?;

	server.finish(finalization)?;

	Ok(())
}

#[test]
fn consistency() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let server_config = ServerConfig::default();
	let client_config = ClientConfig::default();

	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (client_file, finalization, export_key) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let (client, request) = ClientLogin::login(client_config, None, PASSWORD)?;
	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	let (new_client_file, finalization, new_export_key) = client.finish(response)?;
	server.finish(finalization)?;

	assert_eq!(client_file, new_client_file);
	assert_eq!(export_key, new_export_key);

	Ok(())
}

#[test]
fn not_validated() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let server_config = ServerConfig::default();
	let client_config = ClientConfig::default();

	assert_eq!(client_config.public_key(), None);

	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;

	assert_eq!(client.config().public_key(), None);

	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (_, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let (client, request) = ClientLogin::login(client_config, None, PASSWORD)?;

	assert_eq!(client.config().public_key(), None);

	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	let (_, finalization, _) = client.finish(response)?;
	server.finish(finalization)?;

	Ok(())
}

#[test]
fn wrong_password() -> anyhow::Result<()> {
	let client_config = ClientConfig::default();
	let server_config = ServerConfig::default();

	let (client, request) = ClientRegistration::register(client_config, "right password")?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (_, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let (client, request) = ClientLogin::login(client_config, None, "wrong password")?;
	let (_, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	assert_eq!(client.finish(response), Err(Error::Credentials));

	Ok(())
}

#[test]
fn no_client() -> anyhow::Result<()> {
	let client_config = ClientConfig::default();
	let server_config = ServerConfig::default();

	let (client, request) = ClientLogin::login(client_config, None, "password")?;
	let (_, response) = ServerLogin::login(&server_config, None, request)?;
	assert_eq!(client.finish(response), Err(Error::Credentials));

	Ok(())
}

#[test]
fn wrong_server_register() -> anyhow::Result<()> {
	let server_config = ServerConfig::default();
	let server_config_wrong = ServerConfig::default();
	let client_config =
		ClientConfig::new(Config::default(), Some(server_config_wrong.public_key()))?;

	let (client, request) = ClientRegistration::register(client_config, "password")?;
	let (_, response) = ServerRegistration::register(&server_config, request)?;
	assert_eq!(client.finish(response), Err(Error::InvalidServer));

	Ok(())
}

#[test]
fn wrong_server_login() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let server_config = ServerConfig::default();
	let server_config_wrong = ServerConfig::default();

	let client_config = ClientConfig::new(Config::default(), None)?;
	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (_, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let client_config =
		ClientConfig::new(Config::default(), Some(server_config_wrong.public_key()))?;
	let (client, request) = ClientLogin::login(client_config, None, PASSWORD)?;
	let (_, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	assert_eq!(client.finish(response), Err(Error::InvalidServer));

	Ok(())
}

#[test]
fn wrong_server_config() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let client_config = ClientConfig::default();
	let server_config = ServerConfig::default();
	let server_config_wrong = ServerConfig::default();

	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (_, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let (_, request) = ClientLogin::login(client_config, None, PASSWORD)?;
	assert_eq!(
		ServerLogin::login(&server_config_wrong, Some(server_file), request),
		Err(Error::ServerFile)
	);

	Ok(())
}

#[test]
fn wrong_client_config() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let server_config = ServerConfig::default();
	let client_config = ClientConfig::new(Config::default(), Some(server_config.public_key()))?;
	let server_config_wrong = ServerConfig::default();
	let client_config_wrong =
		ClientConfig::new(Config::default(), Some(server_config_wrong.public_key()))?;

	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (client_file, finalization, _) = client.finish(response)?;
	let _server_file = server.finish(finalization)?;

	let (client, request) = ClientRegistration::register(client_config_wrong, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config_wrong, request)?;
	let (client_file_wrong, finalization, _) = client.finish(response)?;
	let _server_file_wrong = server.finish(finalization)?;

	assert_eq!(
		ClientLogin::login(client_config, Some(client_file_wrong), PASSWORD),
		Err(Error::ConfigPublicKey)
	);
	assert_eq!(
		ClientLogin::login(client_config_wrong, Some(client_file), PASSWORD),
		Err(Error::ConfigPublicKey)
	);

	Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn cipher_suites() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";

	fn cipher_suite(ake: Ake, group: Group, hash: Hash, mhf: Mhf) -> anyhow::Result<()> {
		let config = Config::new(ake, group, hash, mhf);

		assert_eq!(config.ake(), ake);
		assert_eq!(config.group(), group);
		assert_eq!(config.crypto_hash(), hash);
		assert_eq!(config.mhf(), mhf);

		let server_config = ServerConfig::new(config);
		let client_config = ClientConfig::new(config, Some(server_config.public_key()))?;

		let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
		let (server, response) = ServerRegistration::register(&server_config, request)?;
		let (client_file, finalization, export_key) = client.finish(response)?;
		let server_file = server.finish(finalization)?;

		let (client, request) = ClientLogin::login(client_config, Some(client_file), PASSWORD)?;
		let (server, response) =
			ServerLogin::login(&server_config, Some(server_file.clone()), request)?;
		let (new_client_file, finalization, new_export_key) = client.finish(response)?;
		server.finish(finalization)?;

		assert_eq!(client_file, new_client_file);
		assert_eq!(
			client_config.public_key().unwrap().to_bytes(),
			client_config.public_key().unwrap().to_bytes()
		);
		assert_eq!(
			client_file.public_key().to_bytes(),
			new_client_file.public_key().to_bytes()
		);
		assert_eq!(
			server_config.public_key().to_bytes(),
			server_config.public_key().to_bytes()
		);
		assert_eq!(
			server_file.public_key().to_bytes(),
			server_file.public_key().to_bytes()
		);
		assert_eq!(export_key, new_export_key);
		assert_eq!(export_key.as_bytes(), new_export_key.as_bytes());
		assert_eq!(export_key.as_ref(), new_export_key.as_ref());
		assert_eq!(&*export_key, &*new_export_key);

		Ok(())
	}

	let argon2id = Mhf::Argon2(Argon2Params::new(
		Argon2Algorithm::Argon2id,
		None,
		None,
		None,
	)?);
	let argon2d = Mhf::Argon2(Argon2Params::new(
		Argon2Algorithm::Argon2d,
		None,
		None,
		None,
	)?);
	#[cfg(feature = "pbkdf2")]
	let pbkdf2sha256 = Mhf::Pbkdf2(Pbkdf2Params::new(Pbkdf2Hash::Sha256, None)?);
	#[cfg(feature = "pbkdf2")]
	let pbkdf2sha512 = Mhf::Pbkdf2(Pbkdf2Params::new(Pbkdf2Hash::Sha512, None)?);

	let akes = [
		Ake::Ristretto255,
		Ake::X25519,
		#[cfg(feature = "p256")]
		Ake::P256,
	];

	let groups = [
		Group::Ristretto255,
		#[cfg(feature = "p256")]
		Group::P256,
	];

	let hashs = [
		Hash::Sha2,
		#[cfg(feature = "sha3")]
		Hash::Sha3,
		#[cfg(feature = "blake3")]
		Hash::Blake3,
	];

	let mhfs = [
		argon2id,
		argon2d,
		#[cfg(feature = "pbkdf2")]
		pbkdf2sha256,
		#[cfg(feature = "pbkdf2")]
		pbkdf2sha512,
	];

	for ake in akes {
		for group in groups {
			for hash in hashs {
				for mhf in mhfs {
					cipher_suite(ake, group, hash, mhf)?;
				}
			}
		}
	}

	Ok(())
}

#[test]
fn wrong_config() -> anyhow::Result<()> {
	// Configuration
	const PASSWORD: &[u8] = b"password";

	let config = Config::new(
		Ake::default(),
		Group::default(),
		Hash::default(),
		Mhf::Argon2(Argon2Params::new(
			Argon2Algorithm::Argon2id,
			None,
			None,
			None,
		)?),
	);
	let wrong_config = Config::new(
		Ake::default(),
		Group::default(),
		Hash::default(),
		Mhf::Argon2(Argon2Params::new(
			Argon2Algorithm::Argon2d,
			None,
			None,
			None,
		)?),
	);
	let server_config = ServerConfig::new(config);
	let wrong_server_config = ServerConfig::new(wrong_config);
	let client_config = ClientConfig::new(config, Some(server_config.public_key()))?;
	let wrong_client_config =
		ClientConfig::new(wrong_config, Some(wrong_server_config.public_key()))?;

	assert_eq!(
		ClientConfig::new(config, Some(wrong_server_config.public_key())),
		Err(Error::Config)
	);

	// Registration
	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request.clone())?;
	let (client_file, finalization, _) = client.clone().finish(response.clone())?;
	let server_file = server.clone().finish(finalization.clone())?;

	let (wrong_client, wrong_request) =
		ClientRegistration::register(wrong_client_config, PASSWORD)?;
	let (wrong_server, wrong_response) =
		ServerRegistration::register(&wrong_server_config, wrong_request.clone())?;
	let (wrong_client_file, wrong_finalization, _) =
		wrong_client.clone().finish(wrong_response.clone())?;
	let wrong_server_file = wrong_server.clone().finish(wrong_finalization.clone())?;

	assert_eq!(
		ServerRegistration::register(&wrong_server_config, request),
		Err(Error::Config)
	);
	assert_eq!(
		ServerRegistration::register(&server_config, wrong_request),
		Err(Error::Config)
	);

	assert_eq!(wrong_client.finish(response), Err(Error::Config));
	assert_eq!(client.finish(wrong_response), Err(Error::Config));

	assert_eq!(wrong_server.finish(finalization), Err(Error::Config));
	assert_eq!(server.finish(wrong_finalization), Err(Error::Config));

	// Login
	let (client, request) = ClientLogin::login(client_config, Some(client_file), PASSWORD)?;
	let (server, response) =
		ServerLogin::login(&server_config, Some(server_file.clone()), request.clone())?;
	let (_, finalization, _) = client.clone().finish(response.clone())?;
	server.clone().finish(finalization.clone())?;

	let (wrong_client, wrong_request) =
		ClientLogin::login(wrong_client_config, Some(wrong_client_file), PASSWORD)?;
	let (wrong_server, wrong_response) = ServerLogin::login(
		&wrong_server_config,
		Some(wrong_server_file.clone()),
		wrong_request.clone(),
	)?;
	let (_, wrong_finalization, _) = wrong_client.clone().finish(wrong_response.clone())?;
	wrong_server.clone().finish(wrong_finalization.clone())?;

	assert_eq!(
		ClientLogin::login(wrong_client_config, Some(client_file), PASSWORD),
		Err(Error::Config)
	);
	assert_eq!(
		ClientLogin::login(client_config, Some(wrong_client_file), PASSWORD),
		Err(Error::Config)
	);

	assert_eq!(
		ServerLogin::login(
			&wrong_server_config,
			Some(server_file.clone()),
			request.clone()
		),
		Err(Error::Config)
	);
	assert_eq!(
		ServerLogin::login(&server_config, Some(wrong_server_file), request),
		Err(Error::ServerFile)
	);
	assert_eq!(
		ServerLogin::login(&server_config, Some(server_file), wrong_request),
		Err(Error::Config)
	);

	assert_eq!(wrong_client.finish(response), Err(Error::Config));
	assert_eq!(client.finish(wrong_response), Err(Error::Config));

	assert_eq!(wrong_server.finish(finalization), Err(Error::Config));
	assert_eq!(server.finish(wrong_finalization), Err(Error::Config));

	Ok(())
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn getters() -> anyhow::Result<()> {
	// Configuration
	const PASSWORD: &[u8] = b"password";

	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, Some(server_config.public_key()))?;
	let public_key = server_config.public_key();

	assert_eq!(server_config.config(), config);
	assert_eq!(client_config.config(), config);
	assert_eq!(client_config.public_key(), Some(server_config.public_key()));
	assert_eq!(public_key.config(), config);

	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;

	assert_eq!(client.config().config(), config);
	assert_eq!(client.config().public_key(), Some(public_key));
	assert_eq!(request.config(), config);

	let (server, response) = ServerRegistration::register(&server_config, request)?;

	assert_eq!(server.config(), config);
	assert_eq!(server.public_key(), public_key);
	assert_eq!(response.config(), config);

	let (client_file, finalization, export_key) = client.finish(response)?;

	assert_eq!(client_file.config(), config);
	assert_eq!(client_file.public_key(), public_key);
	assert_eq!(export_key.as_ref(), export_key.as_bytes());
	assert_eq!(&*export_key, export_key.as_bytes());
	assert_eq!(finalization.config(), config);

	let server_file = server.finish(finalization)?;

	assert_eq!(server_file.config(), config);
	assert_eq!(server_file.public_key(), public_key);

	let (client, request) = ClientLogin::login(client_config, Some(client_file), PASSWORD)?;

	assert_eq!(client.config().config(), config);
	assert_eq!(client.config().public_key(), Some(public_key));
	assert_eq!(request.config(), config);

	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;

	assert_eq!(server.config(), config);
	assert_eq!(response.config(), config);

	let (new_client_file, finalization, export_key) = client.finish(response)?;

	assert_eq!(new_client_file.config(), config);
	assert_eq!(new_client_file.public_key(), public_key);
	assert_eq!(export_key.as_ref(), export_key.as_bytes());
	assert_eq!(&*export_key, export_key.as_bytes());
	assert_eq!(finalization.config(), config);

	server.finish(finalization)?;

	Ok(())
}
