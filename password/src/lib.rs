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
	missing_crate_level_docs,
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
	unused_results,
	variant_size_differences
)]
#![allow(
	clippy::blanket_clippy_restriction_lints,
	clippy::else_if_without_else,
	clippy::exhaustive_enums,
	clippy::expect_used,
	clippy::future_not_send,
	clippy::implicit_return,
	clippy::map_err_ignore,
	clippy::missing_inline_in_public_items,
	clippy::non_ascii_literal,
	clippy::pattern_type_mismatch,
	clippy::redundant_pub_crate,
	clippy::shadow_reuse,
	clippy::tabs_in_doc_comments,
	clippy::unreachable,
	clippy::wildcard_enum_match_arm,
	unreachable_pub,
	variant_size_differences
)]
#![cfg_attr(
	doc,
	feature(doc_cfg),
	warn(rustdoc::all),
	allow(rustdoc::missing_doc_code_examples, rustdoc::private_doc_tests)
)]
#![cfg_attr(
	test,
	allow(
		box_pointers,
		clippy::integer_arithmetic,
		clippy::panic,
		clippy::panic_in_result_fn
	)
)]

//! TODO
// TODO: start registration and login process from `Server/ClientConfig`
// TODO: implement credential identifier
// TODO: option to save credential identifier in plaintext to support renaming
// TODO: expose session key
// TODO: implement encryption for export key
// TODO: expose custom identifier
// TODO: start `custodian-shared` for keypair types, algorithms and whatnot
// TODO: start `custodian-pki` for shared pki system and key generation
// TODO: expose server keypair with types from `custodian-shared` and enable
// optional external keypairs

mod cipher_suite;
mod client;
mod config;
pub mod error;
mod export_key;
mod messages;
mod public_key;
mod server;

pub use serde;

use crate::cipher_suite::CipherSuite;
pub use crate::{
	client::{ClientConfig, ClientFile, ClientLogin, ClientRegistration},
	config::Config,
	error::{Error, Result},
	export_key::ExportKey,
	messages::{
		LoginFinalization, LoginRequest, LoginResponse, RegistrationFinalization,
		RegistrationRequest, RegistrationResponse,
	},
	public_key::PublicKey,
	server::{ServerConfig, ServerFile, ServerLogin, ServerRegistration},
};

#[test]
fn basic() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, Some(server_config.public_key()));

	// registration process
	let (client, request) = ClientRegistration::register(&client_config, PASSWORD)?;

	let (server, response) = ServerRegistration::register(&server_config, request)?;

	let (client_file, finalization, export_key) = client.finish(response)?;

	let server_file = server.finish(finalization);

	// login process
	let (client, request) =
		ClientLogin::login(&client_config, Some(client_file.clone()), PASSWORD)?;

	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;

	let (new_client_file, finalization, new_export_key) = client.finish(response)?;

	server.finish(finalization)?;

	// checks
	assert_eq!(client_file, new_client_file);
	assert_eq!(export_key, new_export_key);

	Ok(())
}

#[test]
fn wrong_password() -> anyhow::Result<()> {
	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, None);

	let (client, request) = ClientRegistration::register(&client_config, "right password")?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (_, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization);

	let (client, request) = ClientLogin::login(&client_config, None, "wrong password")?;
	let (_, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	assert_eq!(client.finish(response), Err(Error::Credentials));

	Ok(())
}

#[test]
fn no_client() -> anyhow::Result<()> {
	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, None);

	let (client, request) = ClientLogin::login(&client_config, None, "wrong password")?;
	let (_, response) = ServerLogin::login(&server_config, None, request)?;
	assert_eq!(client.finish(response), Err(Error::Credentials));

	Ok(())
}

#[test]
fn wrong_server_register() -> anyhow::Result<()> {
	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let server_config_wrong = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, Some(server_config_wrong.public_key()));

	let (client, request) = ClientRegistration::register(&client_config, "password")?;
	let (_, response) = ServerRegistration::register(&server_config, request)?;
	assert_eq!(client.finish(response), Err(Error::InvalidServer));

	Ok(())
}

#[test]
fn wrong_server_login() -> anyhow::Result<()> {
	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let server_config_wrong = ServerConfig::new(config);

	let client_config = ClientConfig::new(config, None);
	let (client, request) = ClientRegistration::register(&client_config, "password")?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (_, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization);

	let client_config = ClientConfig::new(config, Some(server_config_wrong.public_key()));
	let (client, request) = ClientLogin::login(&client_config, None, "password")?;
	let (_, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	assert_eq!(client.finish(response), Err(Error::InvalidServer));

	Ok(())
}
