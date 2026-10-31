//! WebSocket listener that copies bytes to and from a vetted TCP destination.
//!
//! The client asks for `/connect?host=HOST&port=PORT` (port defaults to 22). The bridge never
//! looks at the bytes it moves and never logs them.

use crate::limit::ConnLimiter;
use crate::policy::{DEFAULT_PORT, Policy};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, WebSocketConfig};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 16 * 1024;
const MAX_FRAME: usize = 64 * 1024;

type Ws = WebSocketStream<TcpStream>;

/// A started bridge. Drop does not stop it; call [`Running::stop`].
pub struct Running {
	/// Bound listener address.
	pub addr: SocketAddr,
	stop: watch::Sender<bool>,
	task: tokio::task::JoinHandle<()>,
}

impl Running {
	/// Stops the listener and every open connection.
	pub async fn stop(self) {
		let _ = self.stop.send(true);
		let _ = self.task.await;
	}
}

/// Binds `bind` and starts serving with `policy` and at most `max_conns_per_ip` connections
/// per client address.
pub async fn start(
	bind: SocketAddr,
	policy: Policy,
	max_conns_per_ip: usize,
) -> io::Result<Running> {
	let listener = TcpListener::bind(bind).await?;
	let addr = listener.local_addr()?;
	let (stop, rx) = watch::channel(false);
	let task = tokio::spawn(accept_loop(
		listener,
		Arc::new(policy),
		ConnLimiter::new(max_conns_per_ip),
		rx,
	));
	Ok(Running { addr, stop, task })
}

async fn accept_loop(
	listener: TcpListener,
	policy: Arc<Policy>,
	limiter: ConnLimiter,
	mut stop: watch::Receiver<bool>,
) {
	let mut conns = JoinSet::new();
	loop {
		tokio::select! {
			_ = stop.changed() => break,
			accepted = listener.accept() => {
				let Ok((stream, from)) = accepted else { continue };
				let Some(slot) = limiter.acquire(from.ip()) else { continue };
				let (policy, stop) = (policy.clone(), stop.clone());
				conns.spawn(async move {
					serve_conn(stream, &policy, stop).await;
					drop(slot);
				});
			}
		}
	}
	conns.shutdown().await;
}

/// Parses `/connect?host=HOST[&port=PORT]`. Returns `None` for anything else.
pub fn parse_target(uri: &str) -> Option<(String, u16)> {
	let query = uri.strip_prefix("/connect?")?;
	if query.contains('%') {
		return None;
	}
	let (mut host, mut port) = (None, None);
	for pair in query.split('&') {
		let (k, v) = pair.split_once('=')?;
		let slot = match k {
			"host" => &mut host,
			"port" => &mut port,
			_ => return None,
		};
		if slot.replace(v).is_some() {
			return None;
		}
	}
	let port = match port {
		None => DEFAULT_PORT,
		Some(p) => p.parse().ok()?,
	};
	Some((host?.to_owned(), port))
}

async fn refuse(mut ws: Ws, code: CloseCode, reason: &'static str) {
	let _ = ws
		.close(Some(CloseFrame {
			code,
			reason: reason.into(),
		}))
		.await;
}

// The handshake callback's error type is fixed by tungstenite.
#[allow(clippy::result_large_err)]
async fn serve_conn(stream: TcpStream, policy: &Policy, mut stop: watch::Receiver<bool>) {
	let mut uri = String::new();
	let config = WebSocketConfig::default()
		.max_message_size(Some(MAX_FRAME))
		.max_frame_size(Some(MAX_FRAME));
	let accepted = accept_hdr_async_with_config(
		stream,
		|req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
			uri = req.uri().to_string();
			Ok(resp)
		},
		Some(config),
	)
	.await;
	let Ok(ws) = accepted else { return };
	let Some((host, port)) = parse_target(&uri) else {
		return refuse(ws, CloseCode::Policy, "bad request").await;
	};
	let Ok(addrs) = policy.resolve(&host, port).await else {
		return refuse(ws, CloseCode::Policy, "destination not allowed").await;
	};
	let Some(tcp) = dial(&addrs).await else {
		return refuse(ws, CloseCode::Error, "connect failed").await;
	};
	let (tcp_r, tcp_w) = tcp.into_split();
	let (ws_tx, ws_rx) = ws.split();
	tokio::select! {
		_ = ws_to_tcp(ws_rx, tcp_w) => {}
		_ = tcp_to_ws(tcp_r, ws_tx) => {}
		_ = stop.changed() => {}
	}
}

async fn dial(addrs: &[SocketAddr]) -> Option<TcpStream> {
	for addr in addrs {
		if let Ok(Ok(tcp)) = timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await {
			return Some(tcp);
		}
	}
	None
}

/// Half-closes the destination so it sees end of stream, then ends the copy loop.
async fn finish(mut tcp: OwnedWriteHalf) -> Option<()> {
	tcp.shutdown().await.ok().and(None)
}

async fn ws_to_tcp(mut rx: SplitStream<Ws>, mut tcp: OwnedWriteHalf) -> Option<()> {
	loop {
		match rx.next().await {
			Some(Ok(Message::Binary(data))) => tcp.write_all(&data).await.ok()?,
			Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return finish(tcp).await,
			Some(Ok(_)) => {}
		}
	}
}

async fn tcp_to_ws(mut tcp: OwnedReadHalf, mut tx: SplitSink<Ws, Message>) -> Option<()> {
	let mut buf = vec![0u8; CHUNK];
	loop {
		let n = tcp.read(&mut buf).await.ok().filter(|n| *n > 0);
		let Some(n) = n else {
			let _ = tx.close().await;
			return None;
		};
		tx.send(Message::Binary(buf[..n].to_vec().into()))
			.await
			.ok()?;
	}
}
