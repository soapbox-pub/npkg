//! Nostr events (NIP-01): parsing, verification, and — for tests and tools —
//! signing.

#[cfg(test)]
use secp256k1::Keypair;
use secp256k1::{XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// The id NIP-01 defines: the sha256 of the event's canonical
    /// serialization.
    pub fn compute_id(pubkey: &str, created_at: i64, kind: i64, tags: &[Vec<String>], content: &str) -> String {
        let canonical = serde_json::to_string(&(0, pubkey, created_at, kind, tags, content)).unwrap_or_default();
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    /// Whether the id is the hash of the event and the signature is its
    /// author's.
    pub fn verify(&self) -> bool {
        if !is_hex64(&self.id) || !is_hex64(&self.pubkey) || self.sig.len() != 128 {
            return false;
        }
        if Self::compute_id(&self.pubkey, self.created_at, self.kind, &self.tags, &self.content) != self.id {
            return false;
        }

        let (mut id, mut pubkey, mut sig) = ([0u8; 32], [0u8; 32], [0u8; 64]);
        if hex::decode_to_slice(&self.id, &mut id).is_err()
            || hex::decode_to_slice(&self.pubkey, &mut pubkey).is_err()
            || hex::decode_to_slice(&self.sig, &mut sig).is_err()
        {
            return false;
        }
        let Ok(pubkey) = XOnlyPublicKey::from_byte_array(pubkey) else { return false };

        schnorr::Signature::from_byte_array(sig).verify(&id, &pubkey).is_ok()
    }

    /// The value of the first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|tag| tag.first().map(String::as_str) == Some(name)).and_then(|tag| tag.get(1)).map(String::as_str)
    }

    /// Sign a new event with `secret` (hex). For tests.
    #[cfg(test)]
    pub fn sign(secret: &str, created_at: i64, kind: i64, tags: Vec<Vec<String>>, content: &str) -> Event {
        let keypair = keypair(secret);
        let pubkey = hex::encode(keypair.x_only_public_key().0.to_byte_array());
        let id = Self::compute_id(&pubkey, created_at, kind, &tags, content);
        let digest = hex::decode(&id).expect("hex");
        let sig = keypair.sign_schnorr_no_aux_rand(&digest);

        Event { id, pubkey, created_at, kind, tags, content: content.to_string(), sig: hex::encode(sig.to_byte_array()) }
    }
}

/// The public key of a hex secret key.
#[cfg(test)]
pub fn public_key(secret: &str) -> String {
    hex::encode(keypair(secret).x_only_public_key().0.to_byte_array())
}

#[cfg(test)]
fn keypair(secret: &str) -> Keypair {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(secret, &mut bytes).expect("a hex secret key");
    Keypair::from_secret_bytes(bytes).expect("a valid secret key")
}

/// Whether a string is 64 lowercase hex characters.
pub fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn signs_and_verifies() {
        let event = Event::sign(SECRET, 1_700_000_000, 1, vec![vec!["t".into(), "x\n\"y\"".into()]], "héllo\u{1}");
        assert!(event.verify());
        assert_eq!(event.pubkey, public_key(SECRET));

        let mut tampered = event.clone();
        tampered.content = "other".into();
        assert!(!tampered.verify());
    }

    /// An event signed by nostr-tools, as a relay would send it.
    #[test]
    fn verifies_foreign_events() {
        let json = r#"{"kind":1,"created_at":1700000000,"tags":[["t","nostr"]],"content":"hello \"world\"\n\u0001é","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","id":"8b8ca1b4d0e7cee7c0b58c9e1e38bb8f9f8d7c6a1a1b8f4b8b7f0c6e5c3f2a10","sig":"00"}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        // Wrong id and signature: rejected rather than panicking.
        assert!(!event.verify());
        let id = Event::compute_id(&event.pubkey, event.created_at, event.kind, &event.tags, &event.content);
        assert_eq!(id.len(), 64);
    }
}
