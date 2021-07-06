use criterion::{criterion_group, criterion_main, Criterion};
use custodian_password::{
	ClientConfig, ClientLogin, ClientRegistration, Config, Group, Hash, Result, ServerConfig,
	ServerLogin, ServerRegistration, SlowHash,
};

fn cipher_suite(group: Group, hash: Hash, slow_hash: SlowHash) -> Result<()> {
	const PASSWORD: &[u8] = b"password";

	let config = Config::new(group, hash, slow_hash);
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
	criterion.bench_function("Ristretto225 + SHA-512 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Sha2, SlowHash::Argon2id).unwrap())
	});
	criterion.bench_function("Ristretto225 + SHA-512 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Sha2, SlowHash::Argon2d).unwrap())
	});
	#[cfg(feature = "pbkdf2")]
	criterion.bench_function("Ristretto225 + SHA-512 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Sha2, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(feature = "sha3")]
	criterion.bench_function("Ristretto225 + SHA3-512 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Sha3, SlowHash::Argon2id).unwrap())
	});
	#[cfg(feature = "sha3")]
	criterion.bench_function("Ristretto225 + SHA3-512 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Sha3, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "sha3", feature = "pbkdf2"))]
	criterion.bench_function("Ristretto225 + SHA3-512 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Sha3, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(feature = "blake3")]
	criterion.bench_function("Ristretto225 + BLAKE3 + Argon2id", |bencher| {
		bencher
			.iter(|| cipher_suite(Group::Ristretto255, Hash::Blake3, SlowHash::Argon2id).unwrap())
	});
	#[cfg(feature = "blake3")]
	criterion.bench_function("Ristretto225 + BLAKE3 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Blake3, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "blake3", feature = "pbkdf2"))]
	criterion.bench_function("Ristretto225 + BLAKE3 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Group::Ristretto255, Hash::Blake3, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(feature = "p256")]
	criterion.bench_function("P256 + SHA-256 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Sha2, SlowHash::Argon2id).unwrap())
	});
	#[cfg(feature = "p256")]
	criterion.bench_function("P256 + SHA-256 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Sha2, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "pbkdf2"))]
	criterion.bench_function("P256 + SHA-256 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Sha2, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "sha3"))]
	criterion.bench_function("P256 + SHA3-256 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Sha3, SlowHash::Argon2id).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "sha3"))]
	criterion.bench_function("P256 + SHA3-256 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Sha3, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "sha3", feature = "pbkdf2"))]
	criterion.bench_function("P256 + SHA3-256 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Sha3, SlowHash::Pbkdf2).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "blake3"))]
	criterion.bench_function("P256 + BLAKE3 + Argon2id", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Blake3, SlowHash::Argon2id).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "blake3"))]
	criterion.bench_function("P256 + BLAKE3 + Argon2d", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Blake3, SlowHash::Argon2d).unwrap())
	});
	#[cfg(all(feature = "p256", feature = "blake3", feature = "pbkdf2"))]
	criterion.bench_function("P256 + BLAKE3 + PBKDF2", |bencher| {
		bencher.iter(|| cipher_suite(Group::P256, Hash::Blake3, SlowHash::Pbkdf2).unwrap())
	});
}

criterion_group!(benches, cipher_suites);
criterion_main!(benches);
