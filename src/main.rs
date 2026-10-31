use clap::Parser;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
	let shutdown = Box::pin(async {
		let _ = tokio::signal::ctrl_c().await;
	});
	kabuk_bridge::run(kabuk_bridge::config::Config::parse(), shutdown).await
}
