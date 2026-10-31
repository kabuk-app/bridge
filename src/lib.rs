//! Kabuk bridge: moves bytes between a browser WebSocket and a TCP port, so the web app can
//! reach SSH servers. SSH itself runs in the browser; the bridge never sees plaintext.
//! It stores nothing and logs no payload.

pub mod config;
pub mod limit;
pub mod policy;
pub mod server;

use config::Config;
use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

/// A future that completes when the bridge should stop.
pub type Shutdown = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Probes `addr` with a TCP connect. Unspecified addresses map to loopback.
pub async fn health(addr: std::net::SocketAddr) -> bool {
	let ip = match addr.ip() {
		ip if !ip.is_unspecified() => ip,
		std::net::IpAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
		std::net::IpAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
	};
	let target = std::net::SocketAddr::new(ip, addr.port());
	matches!(
		tokio::time::timeout(
			Duration::from_secs(2),
			tokio::net::TcpStream::connect(target)
		)
		.await,
		Ok(Ok(_))
	)
}

/// Runs the bridge, or the health probe, until `shutdown` completes.
pub async fn run(config: Config, shutdown: Shutdown) -> ExitCode {
	if config.health {
		return if health(config.bind).await {
			ExitCode::SUCCESS
		} else {
			ExitCode::FAILURE
		};
	}
	let policy = policy::Policy::new(&config.allow_ports);
	match server::start(config.bind, policy, config.max_conns_per_ip).await {
		Ok(running) => {
			shutdown.await;
			running.stop().await;
			ExitCode::SUCCESS
		}
		Err(e) => {
			eprintln!("kabuk-bridge: cannot start: {e}");
			ExitCode::FAILURE
		}
	}
}
