# Cowork Relay

This repository owns the self-hosted public relay and its local management CLI.
Keep business TLS opaque. Never add Agent execution, project grants, file access,
business credential storage, arbitrary forwarding targets or TLS bypasses.
Wire contracts and fixtures originate in cowork-protocol and are vendored at a
fixed digest. Public tests use synthetic devices and loopback listeners only.

Support Chinese and English product output. Code comments are Chinese. Keep
deployment decisions and private cross-repository evidence in cowork-internal.
Use rust-toolchain.toml. Before committing run cargo fmt --check, cargo clippy
--all-targets --locked -- -D warnings, cargo test --locked, cargo build --release
--locked and the public acceptance tests. Commit verified work with an English
subject and substantive body, wrapped at 72 columns. Do not push or publish
without an explicit request.
