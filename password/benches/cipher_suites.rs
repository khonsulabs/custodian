use criterion::{criterion_group, criterion_main, Criterion};
use custodian_password::{
	ClientConfig, ClientLogin, ClientRegistration, Config, Hash, Result, ServerConfig, ServerLogin,
	ServerRegistration, SlowHash,
};

fn cipher_suite(hash: Hash, slow_hash: SlowHash) -> Result<()> {
	const PASSWORD: &[u8] = b"password";

	let config = Config::new(hash, slow_hash);
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, None)?;

	let (client, request) = ClientRegistration::register(&client_config, PASSWORD)?;
	let (server, response) = ServerRegistration::register(&server_config, request)?;
	let (client_file, finalization, _) = client.finish(response)?;
	let server_file = server.finish(finalization)?;

	let (client, request) = ClientLogin::login(&client_config, Some(client_file), PASSWORD)?;
	let (server, response) = ServerLogin::login(&server_config, Some(server_file), request)?;
	let (_, finalization, _) = client.finish(response)?;
	server.finish(finalization)
}

fn cipher_suites(criterion: &mut Criterion) {
	criterion.bench_function("SHA-512 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Sha512, SlowHash::Argon2id).unwrap())
	});
	criterion.bench_function("SHA-512 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Sha512, SlowHash::Argon2d).unwrap())
	});
	#[cfg(feature = "pbkdf2")]
	criterion.bench_function("SHA-512 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Sha512, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(feature = "sha3")]
	criterion.bench_function("SHA3-512 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Sha3_512, SlowHash::Argon2id).unwrap())
	});
	#[cfg(feature = "sha3")]
	criterion.bench_function("SHA3-512 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Sha3_512, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "pbkdf2", feature = "sha3"))]
	criterion.bench_function("SHA3-512 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Sha3_512, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(feature = "blake3")]
	criterion.bench_function("BLAKE3 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Blake3, SlowHash::Argon2id).unwrap())
	});
	#[cfg(feature = "blake3")]
	criterion.bench_function("BLAKE3 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Blake3, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "pbkdf2", feature = "blake3"))]
	criterion.bench_function("BLAKE3 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Hash::Blake3, SlowHash::Pbkdf2).unwrap())
	});
}

criterion_group!(benches, cipher_suites);
criterion_main!(benches);
