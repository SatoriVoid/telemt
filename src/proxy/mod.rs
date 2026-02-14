//! Proxy Defs

pub mod client;
pub(crate) mod direct_relay;
pub mod handshake;
pub mod masking;
pub(crate) mod middle_relay;
pub mod relay;

pub use client::{ClientHandler, handle_client_stream};
pub use handshake::*;
pub use masking::*;
pub use relay::*;
