# Status

- Done: destination policy (port allow list, IPv4 and IPv6 forbidden ranges, embedded IPv4 forms,
  metadata addresses, host validation, resolve-then-dial), WebSocket to TCP copy at
  `/connect?host=H&port=P`, per-client connection cap, `--health`, Dockerfile. 100% line coverage.
- Not done: per-client rate limit on new connections, TLS (use a proxy), origin checks, idle timeout,
  byte or time quotas. DNS rebinding is covered by dialling the vetted address only.
- Not yet verified: arm64 and Windows CI runs (only linux x64 was run locally).
