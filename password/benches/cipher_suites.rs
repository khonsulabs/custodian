use criterion::{criterion_group, criterion_main, Criterion};
use custodian_password::{
	Ake, Argon2Algorithm, Argon2Params, ClientConfig, ClientLogin, ClientRegistration, Config,
	Group, Hash, Mhf, Result, ServerConfig, ServerLogin, ServerRegistration,
};
#[cfg(feature = "pbkdf2")]
use custodian_password::{Pbkdf2Hash, Pbkdf2Params};

fn cipher_suite(ake: Ake, group: Group, hash: Hash, mhf_hash: Mhf) -> Result<()> {
	const PASSWORD: &[u8] = b"password";

	let config = Config::new(ake, group, hash, mhf_hash);
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, None)?;

	let (client, request) = ClientRegistration::register(client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (client_file, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let (client, request) = ClientLogin::login(client_config, Some(client_file), PASSWORD)?;
	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	let (_, finalization, _) = client.finish(response)?;
	server.finish(finalization)
}

fn cipher_suites(criterion: &mut Criterion) {
	let argon2id =
		Mhf::Argon2(Argon2Params::new(Argon2Algorithm::Argon2id, None, None, None).unwrap());
	let argon2d =
		Mhf::Argon2(Argon2Params::new(Argon2Algorithm::Argon2d, None, None, None).unwrap());
	#[cfg(feature = "pbkdf2")]
	let pbkdf2sha256 = Mhf::Pbkdf2(Pbkdf2Params::new(Pbkdf2Hash::Sha256, None).unwrap());
	#[cfg(feature = "pbkdf2")]
	let pbkdf2sha512 = Mhf::Pbkdf2(Pbkdf2Params::new(Pbkdf2Hash::Sha512, None).unwrap());

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
					criterion.bench_function(
						&format!("{:?} + {:?} + {:?} + {:?}", ake, group, hash, mhf),
						|bencher| bencher.iter(|| cipher_suite(ake, group, hash, mhf).unwrap()),
					);
				}
			}
		}
	}
}

criterion_group!(benches, cipher_suites);
criterion_main!(benches);
