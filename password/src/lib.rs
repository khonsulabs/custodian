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

//! TODO: docs
//! TODO: improve errors
//! TODO: expose session key
//! TODO: expose export key
//! TODO: rename all structures and equalize them between client and server
//! TODO: move `Config` to a different module
//! TODO: turn `Config` into an `Arc`
//! TODO: expose custom identifier
//! TODO: expose further configurations
//! TODO: start `custodian-shared` for keypair types, algorithms and whatnot
//! TODO: start `custodian-pki` for shared pki system and key generation
//! TODO: expose server keypair with types from `custodian-shared` and enable
//! optional external keypairs

pub mod client;
pub mod server;

use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::{ciphersuite::CipherSuite, key_exchange::tripledh::TripleDH};
use scrypt::ScryptParams;
pub use serde;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use thiserror::Error;

/// [`Result`](std::result::Result) for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error`](std::error::Error) type for this crate.
#[derive(Clone, Copy, Debug, Error, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
	/// Error during registration.
	#[error("Error during registration")]
	Registration,
	/// Error during login.
	#[error("Error during login")]
	Login,
}

/// Common password configuration between server and client.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
// TODO: remove `non_exhaustive` and `allow(missing_copy_implementations)` when members are added
#[allow(missing_copy_implementations)]
#[non_exhaustive]
pub struct Config;

impl CipherSuite for Config {
	type Group = RistrettoPoint;
	type Hash = Sha512;
	type KeyExchange = TripleDH;
	type SlowHash = ScryptParams;
}

impl Config {
	/// Builds new default [`Config`].
	#[must_use]
	pub const fn new() -> Self {
		Self
	}
}

#[test]
fn basic() -> anyhow::Result<()> {
	const PASSWORD: &[u8] = b"password";
	let config = Config::default();

	// registration process
	let (client, request) = client::Register::register(config.clone(), PASSWORD)?;

	let (server, response) = server::RegistrationBuilder::register(config.clone(), &request)?;

	let response = client.finish(&response)?;

	let server = server.finish(&response)?;

	// login process
	let (client, request) = client::Login::login(config, PASSWORD)?;

	let (server, response) = server.login(&request)?;

	let response = client.finish(&response)?;

	server.finish(&response)?;

	/*
		// Session Key
		assert_eq!(
			client_login_finish_result.session_key,
			server_login_finish_result.session_key,
		);

		// Public Key Verification
		assert_eq!(&client_login_finish_result.server_s_pk, server_kp.public());

		// Export Key
		assert_eq!(
			client_registration_finish_result.export_key,
			client_login_finish_result.export_key,
		);
	*/

	Ok(())
}
