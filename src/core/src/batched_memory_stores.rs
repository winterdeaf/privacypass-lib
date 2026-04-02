//
// Why keep unwrap/expect here? The mutex handles a single thread, so really this could be
// a HashMap. We leave it as is for similarity to the privacypass-rust example code.
// In this context, a thread that panics durinc access to the Mutex (and hence makes .lock() fail)
// is the only thread, and a further panic in this file will never be triggered.
// Just in case, we add a message to the panic.

use async_trait::async_trait;
use privacypass::{Nonce, NonceStore, TruncatedTokenKeyId};
use privacypass::common::store::PrivateKeyStore;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use voprf::{Ristretto255, VoprfServer};

#[derive(Default)]
pub struct MemoryNonceStore {
    nonces: Mutex<HashSet<Nonce>>,
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn reserve(&self, nonce: &Nonce) -> bool {
        let mut nonces = self
            .nonces
            .lock()
            .expect("MemoryNonceStore .lock() failed on .reserve()");
        nonces.insert(*nonce)
    }

    async fn commit(&self, _nonce: &Nonce) {
        // Already inserted in reserve(); nothing more to do for this in-memory store.
    }

    async fn release(&self, nonce: &Nonce) {
        let mut nonces = self
            .nonces
            .lock()
            .expect("MemoryNonceStore .lock() failed on .release()");
        nonces.remove(nonce);
    }
}

#[derive(Default)]
pub struct MemoryKeyStoreRistretto255 {
    keys: Mutex<HashMap<TruncatedTokenKeyId, VoprfServer<Ristretto255>>>,
}

#[async_trait]
impl PrivateKeyStore for MemoryKeyStoreRistretto255 {
    type CS = Ristretto255;

    async fn insert(
        &self,
        truncated_token_key_id: TruncatedTokenKeyId,
        server: VoprfServer<Ristretto255>,
    ) -> bool {
        let mut keys = self
            .keys
            .lock()
            .expect("MemoryKeyStoreRistretto255 .lock() failed on .insert()");
        if keys.contains_key(&truncated_token_key_id) {
            return false;
        }
        keys.insert(truncated_token_key_id, server);
        true
    }

    async fn get(
        &self,
        truncated_token_key_id: &TruncatedTokenKeyId,
    ) -> Option<VoprfServer<Ristretto255>> {
        self.keys
            .lock()
            .expect("MemoryKeyStoreRistretto255 .lock() failed on .get()")
            .get(truncated_token_key_id)
            .cloned()
    }

    async fn remove(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> bool {
        let mut keys = self
            .keys
            .lock()
            .expect("MemoryKeyStoreRistretto255 .lock() failed on .remove()");
        keys.remove(truncated_token_key_id).is_some()
    }
}

