// this file simply remaps some types to make the api.rs code generic

use voprf::Ristretto255;
pub type VoprfGroup = Ristretto255;

#[cfg(not(target_arch = "wasm32"))]
use crate::batched_memory_stores::MemoryKeyStoreRistretto255;
#[cfg(not(target_arch = "wasm32"))]
pub type MemoryKeyStore = MemoryKeyStoreRistretto255;

#[cfg(not(target_arch = "wasm32"))]
pub use privacypass::TokenType::PrivateRistretto255 as GroupTokenType;

// if true, debug messages are printed to stdout
#[cfg(not(target_arch = "wasm32"))]
pub const VERBOSE: bool = false;