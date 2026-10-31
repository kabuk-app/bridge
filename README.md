# Kabuk bridge

A small optional server that lets the Kabuk web app reach SSH servers. Browsers cannot open TCP
connections, so the web app opens a WebSocket to the bridge and the bridge passes the bytes on.
The SSH session itself is encrypted and checked inside your browser. The bridge only moves bytes,
stores nothing and does not log what passes through.

It is for people who want to run their own bridge. Most people never need it.

Kabuk is early and not released yet. The bridge is a skeleton and the web app does not use it yet.

## What it will connect to

By default only port 22. You can allow more ports on purpose with `--allow-port`. It refuses
private, loopback, link-local and other internal addresses, and cloud metadata addresses, so a
bridge on a public server cannot be used to poke at its own network. Names are resolved by the
bridge and only the checked address is used.

## Running it

With Docker:

```
docker compose up -d
```

It listens on port 21226. Put it behind a TLS proxy before pointing the web app at it. To check
that it is up:

```
docker compose exec bridge /kabuk-bridge --health
```

Without Docker, install a current stable Rust toolchain and run `cargo run --release`.
`--help` lists the options.

Licensed under the GNU General Public License v3.0 or later. See `LICENSE`.
