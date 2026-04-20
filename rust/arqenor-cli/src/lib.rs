//! Internal library surface for the `arqenor` CLI.
//!
//! The CLI is primarily a binary crate (`src/main.rs`), but a thin library
//! target is exposed so that integration tests under `tests/` can exercise
//! the same helpers the binary uses — notably the IOC persistence wiring in
//! [`commands::watch`].
//!
//! Nothing here is a stable public API; consumers should embed `arqenor-core`
//! or `arqenor-store` directly.

pub mod commands;
