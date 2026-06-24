//! Domain ports (hexagonal architecture): trait-based interfaces that
//! inbound adapters (HTTP middleware) call, with no knowledge of the
//! concrete outbound adapter (in-memory, Redis, etc.).
pub mod session_store;
