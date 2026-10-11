//! Nostr: events, NIP-19 identifiers, NIP-05 addresses, and one-shot relay
//! queries.

pub mod event;
pub mod nip05;
pub mod nip19;
pub mod relay;

pub use event::{Event, is_hex64};
