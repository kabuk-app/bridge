//! Real-socket tests: browser side is a WebSocket client, destination is a local TCP server.

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use kabuk_bridge::config::{Config, DEFAULT_PORT};
use kabuk_bridge::limit::ConnLimiter;
use kabuk_bridge::policy::Policy;
use kabuk_bridge::server::{Running, parse_target, start};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

type Client = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn connect(
	bridge: SocketAddr,
	query: &str,
) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
	tokio_tungstenite::connect_async(format!("ws://{bridge}/connect?{query}"))
		.await
		.map(|(c, _)| c)
}

/// An echo server that also reports what it saw, so tests can check the exact bytes.
async fn echo_server() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut buf = [0u8; 4096];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 || s.write_all(&buf[..n]).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

async fn bridge_to(dest: SocketAddr, max: usize) -> Running {
	let policy = Policy::new(&[dest.port()]).allow_any_address();
	start("127.0.0.1:0".parse().unwrap(), policy, max)
		.await
		.unwrap()
}

async fn strict_bridge() -> Running {
	start("127.0.0.1:0".parse().unwrap(), Policy::new(&[]), 8)
		.await
		.unwrap()
}

async fn expect_policy_close(mut c: Client) {
	match timeout(Duration::from_secs(5), c.next()).await.unwrap() {
		Some(Ok(Message::Close(Some(frame)))) => assert_eq!(frame.code, CloseCode::Policy),
		other => panic!("expected a policy close, got {other:?}"),
	}
}

#[tokio::test]
async fn copies_bytes_both_ways() {
	let dest = echo_server().await;
	let bridge = bridge_to(dest, 8).await;
	let mut c = connect(bridge.addr, &format!("host=127.0.0.1&port={}", dest.port()))
		.await
		.unwrap();
	for payload in [
		b"hello".to_vec(),
		vec![0u8; 1],
		(0..=255u8).collect::<Vec<_>>(),
		vec![7u8; 40_000],
	] {
		c.send(Message::Binary(payload.clone().into()))
			.await
			.unwrap();
		let mut got = Vec::new();
		while got.len() < payload.len() {
			match timeout(Duration::from_secs(5), c.next())
				.await
				.unwrap()
				.unwrap()
				.unwrap()
			{
				Message::Binary(b) => got.extend_from_slice(&b),
				other => panic!("unexpected {other:?}"),
			}
		}
		assert_eq!(got, payload);
	}
	c.send(Message::Text("ignored".into())).await.unwrap();
	c.close(None).await.unwrap();
	while c.next().await.is_some_and(|m| m.is_ok()) {}
	bridge.stop().await;
}

#[tokio::test]
async fn destination_closing_closes_the_websocket() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let dest = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, _) = listener.accept().await.unwrap();
		s.write_all(b"bye").await.unwrap();
	});
	let bridge = bridge_to(dest, 8).await;
	let mut c = connect(bridge.addr, &format!("host=127.0.0.1&port={}", dest.port()))
		.await
		.unwrap();
	let mut seen = Vec::new();
	while let Ok(Some(Ok(m))) = timeout(Duration::from_secs(5), c.next()).await {
		match m {
			Message::Binary(b) => seen.extend_from_slice(&b),
			Message::Close(_) => break,
			_ => {}
		}
	}
	assert_eq!(seen, b"bye");
	bridge.stop().await;
}

#[tokio::test]
async fn client_closing_closes_the_destination() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let dest = listener.local_addr().unwrap();
	let seen = tokio::spawn(async move {
		let (mut s, _) = listener.accept().await.unwrap();
		let mut all = Vec::new();
		s.read_to_end(&mut all).await.unwrap();
		all
	});
	let bridge = bridge_to(dest, 8).await;
	let mut c = connect(bridge.addr, &format!("host=127.0.0.1&port={}", dest.port()))
		.await
		.unwrap();
	c.send(Message::Binary(b"data".to_vec().into()))
		.await
		.unwrap();
	c.close(None).await.unwrap();
	assert_eq!(
		timeout(Duration::from_secs(5), seen)
			.await
			.unwrap()
			.unwrap(),
		b"data"
	);
	bridge.stop().await;
}

#[tokio::test]
async fn real_policy_refuses_internal_destinations_and_odd_ports() {
	let bridge = strict_bridge().await;
	for q in [
		"host=127.0.0.1",
		"host=localhost",
		"host=169.254.169.254",
		"host=10.0.0.1",
		"host=[::1]",
		"host=::1",
		"host=::ffff:127.0.0.1",
		"host=93.184.216.34&port=80",
		"host=93.184.216.34&port=0",
		"host=bad%20host",
		"host=",
		"port=22",
		"host=a&host=b",
		"host=a&evil=1",
		"host=a&port=notaport",
		"host=a&port=99999",
		"hostonly",
	] {
		expect_policy_close(connect(bridge.addr, q).await.unwrap()).await;
	}
	bridge.stop().await;
}

#[tokio::test]
async fn other_paths_are_refused() {
	let bridge = strict_bridge().await;
	let (c, _) = tokio_tungstenite::connect_async(format!("ws://{}/other?host=a", bridge.addr))
		.await
		.unwrap();
	expect_policy_close(c).await;
	bridge.stop().await;
}

#[tokio::test]
async fn unreachable_destination_reports_connect_failure() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let dead = listener.local_addr().unwrap();
	drop(listener);
	let bridge = bridge_to(dead, 8).await;
	let mut c = connect(bridge.addr, &format!("host=127.0.0.1&port={}", dead.port()))
		.await
		.unwrap();
	match timeout(Duration::from_secs(5), c.next()).await.unwrap() {
		Some(Ok(Message::Close(Some(f)))) => assert_eq!(f.code, CloseCode::Error),
		other => panic!("{other:?}"),
	}
	bridge.stop().await;
}

#[tokio::test]
async fn per_client_connection_cap() {
	let dest = echo_server().await;
	let bridge = bridge_to(dest, 1).await;
	let q = format!("host=127.0.0.1&port={}", dest.port());
	let mut first = connect(bridge.addr, &q).await.unwrap();
	assert!(connect(bridge.addr, &q).await.is_err());
	first.close(None).await.unwrap();
	while first.next().await.is_some_and(|m| m.is_ok()) {}
	// The slot is released after the first connection ends.
	let mut ok = false;
	for _ in 0..50 {
		if connect(bridge.addr, &q).await.is_ok() {
			ok = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert!(ok);
	bridge.stop().await;
}

#[tokio::test]
async fn non_websocket_and_abrupt_clients_are_survived() {
	let dest = echo_server().await;
	let bridge = bridge_to(dest, 8).await;
	let mut s = TcpStream::connect(bridge.addr).await.unwrap();
	s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
	let mut sink = Vec::new();
	let _ = timeout(Duration::from_secs(2), s.read_to_end(&mut sink)).await;
	let c = connect(bridge.addr, &format!("host=127.0.0.1&port={}", dest.port()))
		.await
		.unwrap();
	drop(c);
	tokio::time::sleep(Duration::from_millis(100)).await;
	bridge.stop().await;
}

#[tokio::test]
async fn stop_ends_open_tunnels() {
	let dest = echo_server().await;
	let bridge = bridge_to(dest, 8).await;
	let mut c = connect(bridge.addr, &format!("host=127.0.0.1&port={}", dest.port()))
		.await
		.unwrap();
	c.send(Message::Binary(b"x".to_vec().into())).await.unwrap();
	assert!(c.next().await.is_some());
	bridge.stop().await;
	assert!(
		timeout(Duration::from_secs(5), async {
			while c.next().await.is_some_and(|m| m.is_ok()) {}
		})
		.await
		.is_ok()
	);
}

#[tokio::test]
async fn bind_error_is_returned() {
	let a = strict_bridge().await;
	assert!(start(a.addr, Policy::new(&[]), 1).await.is_err());
	a.stop().await;
}

#[test]
fn target_parsing() {
	assert_eq!(
		parse_target("/connect?host=example.com"),
		Some(("example.com".into(), 22))
	);
	assert_eq!(
		parse_target("/connect?host=example.com&port=2222"),
		Some(("example.com".into(), 2222))
	);
	assert_eq!(
		parse_target("/connect?port=2222&host=h"),
		Some(("h".into(), 2222))
	);
	for bad in [
		"/",
		"/connect",
		"/connect?",
		"/connect?port=22",
		"/connect?host=h&port=",
		"/connect?host=h&port=-1",
		"/connectx?host=h",
		"/connect?host=h%2e",
		"/connect?host=a&host=b",
	] {
		assert_eq!(parse_target(bad), None, "{bad}");
	}
}

#[test]
fn connection_limiter_counts_and_releases() {
	let l = ConnLimiter::new(2);
	let (a, b) = ("1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap());
	let s1 = l.acquire(a).unwrap();
	let s2 = l.acquire(a).unwrap();
	assert!(l.acquire(a).is_none());
	assert!(l.acquire(b).is_some());
	assert_eq!(l.clients(), 1);
	drop(s1);
	let s3 = l.acquire(a).unwrap();
	drop((s2, s3));
	assert_eq!(l.clients(), 0);
}

#[test]
fn config_defaults_and_overrides() {
	let c = Config::parse_from(["kabuk-bridge"]);
	assert_eq!(
		(c.bind.port(), c.max_conns_per_ip, c.health),
		(DEFAULT_PORT, 8, false)
	);
	assert!(c.allow_ports.is_empty());
	let c = Config::parse_from([
		"kabuk-bridge",
		"--allow-port",
		"2222",
		"--allow-port",
		"2200",
		"--max-conns-per-ip",
		"3",
		"--health",
	]);
	assert_eq!(
		(c.allow_ports, c.max_conns_per_ip, c.health),
		(vec![2222, 2200], 3, true)
	);
}

fn cfg(bind: &str, health: bool) -> Config {
	let mut args = vec!["kabuk-bridge", "--bind", bind];
	if health {
		args.push("--health");
	}
	Config::parse_from(args)
}

#[tokio::test]
async fn run_modes() {
	let ready = || Box::pin(std::future::ready(()));
	assert_eq!(
		kabuk_bridge::run(cfg("127.0.0.1:0", false), ready()).await,
		ExitCode::SUCCESS
	);
	let up = strict_bridge().await;
	let taken = up.addr.to_string();
	assert_eq!(
		kabuk_bridge::run(cfg(&taken, false), ready()).await,
		ExitCode::FAILURE
	);
	assert_eq!(
		kabuk_bridge::run(cfg(&taken, true), ready()).await,
		ExitCode::SUCCESS
	);
	let port = up.addr.port();
	assert!(kabuk_bridge::health(format!("0.0.0.0:{port}").parse().unwrap()).await);
	up.stop().await;
	assert_eq!(
		kabuk_bridge::run(cfg(&taken, true), ready()).await,
		ExitCode::FAILURE
	);
	assert!(!kabuk_bridge::health("[::]:9".parse().unwrap()).await);
}
