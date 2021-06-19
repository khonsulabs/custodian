use std::{sync::mpsc, thread};

use anyhow::Result;
use custodian_password::{client, server, Config};
use serde::{de::DeserializeOwned, Serialize};

fn simulate_network() -> (Network, Network) {
	let (client_sender, server_receiver) = mpsc::channel();
	let (server_sender, client_receiver) = mpsc::channel();

	let client = Network {
		sender: client_sender,
		receiver: client_receiver,
	};

	let server = Network {
		sender: server_sender,
		receiver: server_receiver,
	};

	(client, server)
}

/// Simulates networking.
struct Network {
	sender: mpsc::Sender<Vec<u8>>,
	receiver: mpsc::Receiver<Vec<u8>>,
}

impl Network {
	fn send<T: Serialize>(&self, data: &T) -> Result<()> {
		self.sender.send(bincode::serialize(data)?)?;
		Ok(())
	}

	fn receive<T: DeserializeOwned>(&self) -> Result<T> {
		let result = bincode::deserialize(&self.receiver.recv()?)?;
		Ok(result)
	}
}

const PASSWORD: &[u8] = b"password";
const CONFIG: Config = Config::new();

fn main() -> Result<()> {
	let (client_network, server_network) = simulate_network();

	let client = thread::spawn(|| client(client_network));
	let server = thread::spawn(|| server(server_network));

	client.join().expect("client panicked")?;
	server.join().expect("server panicked")?;

	Ok(())
}

fn client(network: Network) -> Result<()> {
	// Registration
	let (client, request) = client::Register::register(CONFIG.clone(), PASSWORD)?;
	network.send(&request)?;

	let response = network.receive()?;
	let response = client.finish(&response)?;

	network.send(&response)?;

	// Login
	let (client, request) = client::Login::login(CONFIG.clone(), PASSWORD)?;
	network.send(&request)?;

	let response = network.receive()?;
	let response = client.finish(&response)?;

	network.send(&response)?;

	Ok(())
}

fn server(network: Network) -> Result<()> {
	// Registration
	let request = network.receive()?;

	let (server, response) = server::RegistrationBuilder::register(CONFIG.clone(), &request)?;
	network.send(&response)?;

	let response = network.receive()?;
	let server = server.finish(&response)?;

	// Login
	let request = network.receive()?;

	let (server, response) = server.login(&request)?;
	network.send(&response)?;

	let response = network.receive()?;
	server.finish(&response)?;

	Ok(())
}
