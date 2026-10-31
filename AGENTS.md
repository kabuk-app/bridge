# bridge

`kabuk-bridge`: self-hostable WebSocket to TCP byte bridge (lib plus bin, tokio) so the web app can
reach SSH servers. Listens on 21226. Stores nothing and logs no payload (there is no logging).

Umbrella index: [../AGENTS.md](../AGENTS.md). Read
[connectivity](../docs/architecture/connectivity.md) (Bridge section) and
[security](../docs/architecture/security.md) before changing behaviour.

## Commands

- `cargo fmt --all --check`
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo llvm-cov --locked --fail-under-lines 100` (runs the tests)
- `docker build -t kabuk-bridge .`

## Rules

- `src/policy.rs` is security code (SSRF). Change it only with adversarial tests in
  `tests/policy.rs`. Never add a runtime switch that allows internal addresses. The
  `test-support` feature (dev-dependency only) is the single exception, for loopback tests.
- Vet resolved addresses and dial those, never the name again.
- All tests live in `tests/` and the lib has `test = false`, so cargo-llvm-cov does not count
  unused copies of code as uncovered. Keep it that way.
- Status: [docs/agents/status.md](docs/agents/status.md)
