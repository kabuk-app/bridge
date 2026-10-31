//! Runs the real binary, so main.rs is exercised too.

use std::process::Command;
use std::time::Duration;

fn bin() -> Command {
	Command::new(env!("CARGO_BIN_EXE_kabuk-bridge"))
}

#[test]
#[cfg(unix)]
fn health_fails_when_down_then_serves_and_exits_cleanly_on_sigint() {
	let port = {
		let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		s.local_addr().unwrap().port()
	};
	let addr = format!("127.0.0.1:{port}");
	assert!(
		!bin()
			.args(["--health", "--bind", &addr])
			.status()
			.unwrap()
			.success()
	);
	let mut child = bin().args(["--bind", &addr]).spawn().unwrap();
	let up = (0..50).any(|_| {
		std::thread::sleep(Duration::from_millis(100));
		bin()
			.args(["--health", "--bind", &addr])
			.status()
			.unwrap()
			.success()
	});
	assert!(up, "bridge did not come up");
	assert!(
		Command::new("kill")
			.args(["-INT", &child.id().to_string()])
			.status()
			.unwrap()
			.success()
	);
	assert!(child.wait().unwrap().success());
}
