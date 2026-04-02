#[macro_use]
extern crate panic_handler;

#[cfg(not(target_arch = "wasm32"))]
mod batched_memory_stores;

use privacypass::Nonce;
const NONCE_BYTES: usize = std::mem::size_of::<Nonce>();

pub mod client;
mod config;
pub mod crystal;
#[cfg(not(target_arch = "wasm32"))]
pub mod server;

#[cfg(not(target_arch = "wasm32"))]
pub use config::GroupTokenType;
#[cfg(not(target_arch = "wasm32"))]
pub use server::{GenKeysError, PrivacyPass, RustKeypair, ValidateTokenError};
