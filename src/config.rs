//! Command line configuration.

use clap::Parser;
use std::net::SocketAddr;

/// Default listen port.
pub const DEFAULT_PORT: u16 = 21226;

/// Kabuk bridge options.
#[derive(Parser, Debug, Clone)]
#[command(
	version,
	about = "Self-hostable Kabuk bridge. Moves bytes between a WebSocket and a TCP port."
)]
pub struct Config {
	/// TCP address for the WebSocket listener.
	#[arg(long, default_value = "0.0.0.0:21226")]
	pub bind: SocketAddr,
	/// Extra destination port to allow besides 22. Repeat for several.
	#[arg(long = "allow-port")]
	pub allow_ports: Vec<u16>,
	/// Most simultaneous connections per client address.
	#[arg(long, default_value_t = 8)]
	pub max_conns_per_ip: usize,
	/// Probe the listener at --bind and exit 0 if it accepts. For container health checks.
	#[arg(long)]
	pub health: bool,
}
