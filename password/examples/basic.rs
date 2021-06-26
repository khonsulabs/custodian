use std::{sync::mpsc, thread};

use anyhow::Result;
use custodian_password::{
	ClientConfig, ClientLogin, ClientRegistration, Config, ServerConfig, ServerLogin,
	ServerRegistration,
};
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

#[cfg_attr(test, test)]
fn main() -> Result<()> {
	let (client_network, server_network) = simulate_network();

	let config = Config::default();
	let server_config = ServerConfig::new(config);
	let client_config = ClientConfig::new(config, Some(server_config.public_key()))?;

	let client = thread::spawn(|| client(client_network, client_config));
	let server = thread::spawn(|| server(server_network, server_config));

	client.join().expect("client panicked")?;
	server.join().expect("server panicked")?;

	Ok(())
}

fn client(network: Network, config: ClientConfig) -> Result<()> {
	const PASSWORD: &[u8] = b"password";

	// Registration
	let (client, request) = ClientRegistration::register(&config, PASSWORD)?;
	network.send(&request)?;

	let response = network.receive()?;
	let (file, response, _) = client.finish(response)?;

	network.send(&response)?;

	// Login
	let (client, request) = ClientLogin::login(&config, Some(file), PASSWORD)?;
	network.send(&request)?;

	let response = network.receive()?;
	let (_, finalization, _) = client.finish(response)?;

	network.send(&finalization)?;

	Ok(())
}

fn server(network: Network, config: ServerConfig) -> Result<()> {
	// Registration
	let request = network.receive()?;

	let (server, response) = ServerRegistration::register(&config, request)?;
	network.send(&response)?;

	let finalization = network.receive()?;
	let file = server.finish(finalization)?;

	// Login
	let request = network.receive()?;

	let (server, response) = ServerLogin::login(&config, Some(file), request)?;
	network.send(&response)?;

	let response = network.receive()?;
	server.finish(response)?;

	Ok(())
}
