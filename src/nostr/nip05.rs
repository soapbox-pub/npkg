//! NIP-05 addresses: `name@domain`, or a bare domain for `_@domain`, looked
//! up in the domain's `/.well-known/nostr.json`.
//!
//! Every file apt or dnf fetches names its repository's owner, so lookups are
//! cached for as long as a repository is, and a domain that stops answering
//! keeps resolving to the key it last gave. That key is kept in the database,
//! so it outlasts a restart too.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::time::Instant;

use super::is_hex64;
use crate::db::Db;

/// The largest `nostr.json` read. Real ones list a few names; some list
/// thousands, but a lookup with `?name=` should get one.
const MAX_BODY: usize = 256 << 10;

/// How long a failed lookup is remembered before the next request tries again.
const FAILURE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub name: String,
    pub domain: String,
}

impl Address {
    /// `name@domain` or `domain`, in any case. Only names a public domain:
    /// no IP addresses, ports, or single-label hosts like `localhost`.
    pub fn parse(value: &str) -> Option<Address> {
        let value = value.to_ascii_lowercase();
        let (name, domain) = value.split_once('@').unwrap_or(("_", &value));
        let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        let labels: Vec<&str> = domain.split('.').collect();
        let domain_ok = domain.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            // A numeric top-level label is an IPv4 address.
            && !labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()));
        (name_ok && domain_ok).then(|| Address { name: name.to_string(), domain: domain.to_string() })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.name, self.domain)
    }
}

#[derive(Clone, Debug)]
pub enum LookupError {
    /// The domain answered, and doesn't list the name.
    NotFound(String),
    /// The domain couldn't be asked, or answered with something unreadable.
    Failed(String),
}

#[derive(Default)]
struct Entry {
    /// Whether `good` has been read from the database yet.
    loaded: bool,
    /// The key, and when to look it up again.
    good: Option<(Instant, String)>,
    failed: Option<(Instant, LookupError)>,
}

#[derive(Default)]
struct Slot {
    /// Held across a lookup nothing is known for yet, so the requests that
    /// arrive meanwhile (apt asks for several files at once) share it.
    entry: tokio::sync::Mutex<Entry>,
    refreshing: AtomicBool,
}

pub struct Resolver {
    http: reqwest::Client,
    ttl: Duration,
    db: Db,
    /// Where every domain's `nostr.json` is fetched from instead, in tests.
    origin: Option<String>,
    /// Never held across an await.
    slots: std::sync::Mutex<HashMap<Address, Arc<Slot>>>,
}

impl Resolver {
    pub fn new(ttl: Duration, db: Db) -> anyhow::Result<Arc<Resolver>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("npkg-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // NIP-05: fetchers must ignore redirects.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Arc::new(Resolver { http, ttl, db, origin: None, slots: Default::default() }))
    }

    /// The hex pubkey `address` names. Only an address with no key known
    /// waits on its domain; a key past `ttl` is given while it's looked up
    /// again in the background.
    pub async fn resolve(self: &Arc<Self>, address: &Address) -> Result<String, LookupError> {
        let slot = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(address.clone()).or_default().clone();
        let mut entry = slot.entry.lock().await;
        if !entry.loaded {
            match self.db.nip05(&address.name, &address.domain).await {
                Ok(row) => {
                    entry.good = row.map(|(pubkey, age)| (Instant::now() + self.ttl.saturating_sub(age), pubkey));
                }
                Err(error) => tracing::warn!(%address, ?error, "couldn't read a stored NIP-05 key"),
            }
            entry.loaded = true;
        }
        let cooling = entry.failed.as_ref().filter(|(at, _)| at.elapsed() < FAILURE_TTL).map(|(_, error)| error.clone());

        if let Some((refresh_at, pubkey)) = &entry.good {
            // A domain that just failed isn't asked again on every request.
            if Instant::now() >= *refresh_at && cooling.is_none() && !slot.refreshing.swap(true, Ordering::AcqRel) {
                let (resolver, slot, address) = (self.clone(), slot.clone(), address.clone());
                tokio::spawn(async move {
                    let result = resolver.lookup(&address).await;
                    resolver.record(&mut *slot.entry.lock().await, &address, &result).await;
                    slot.refreshing.store(false, Ordering::Release);
                });
            }
            return Ok(pubkey.clone());
        }
        if let Some(error) = cooling {
            return Err(error);
        }

        let result = self.lookup(address).await;
        self.record(&mut entry, address, &result).await;
        result
    }

    /// Remember what a lookup found, here and in the database.
    async fn record(&self, entry: &mut Entry, address: &Address, result: &Result<String, LookupError>) {
        let stored = match result {
            Ok(pubkey) => {
                entry.good = Some((Instant::now() + self.ttl, pubkey.clone()));
                entry.failed = None;
                self.db.store_nip05(&address.name, &address.domain, pubkey).await
            }
            // The domain says the name is gone: believe it.
            Err(error @ LookupError::NotFound(_)) => {
                entry.good = None;
                entry.failed = Some((Instant::now(), error.clone()));
                self.db.forget_nip05(&address.name, &address.domain).await
            }
            // The domain is down: the key it last gave stands.
            Err(error) => {
                tracing::warn!(%address, ?error, "NIP-05 lookup failed");
                entry.failed = Some((Instant::now(), error.clone()));
                Ok(())
            }
        };
        if let Err(error) = stored {
            tracing::warn!(%address, ?error, "couldn't store a NIP-05 lookup");
        }
    }

    async fn lookup(&self, address: &Address) -> Result<String, LookupError> {
        let Address { name, domain } = address;
        let failed = |why: String| LookupError::Failed(format!("Couldn't look up {address}: {why}. Try again later."));
        // `parse` only lets through characters that need no escaping.
        let origin = self.origin.clone().unwrap_or_else(|| format!("https://{domain}"));
        let url = format!("{origin}/.well-known/nostr.json?name={name}");
        let mut response = self.http.get(&url).send().await.map_err(|error| failed(format!("{domain} didn't answer ({error})")))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(LookupError::NotFound(format!("{domain} doesn't have a NIP-05 nostr.json, so {address} names no one.")));
        }
        if status.is_redirection() {
            return Err(failed(format!("{domain} redirected, which NIP-05 doesn't allow")));
        }
        if !status.is_success() {
            return Err(failed(format!("{domain} answered {status}")));
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| failed(format!("{domain} stopped answering ({error})")))? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                return Err(failed(format!("{domain}'s nostr.json is larger than {} KiB", MAX_BODY >> 10)));
            }
        }
        pubkey_in(&body, name).map_err(|why| match why {
            None => LookupError::NotFound(format!("{domain} doesn't list a Nostr key for {name:?}.")),
            Some(why) => failed(format!("{domain}'s nostr.json {why}")),
        })
    }
}

/// The pubkey a `nostr.json` gives `name`. `Err(None)` when it gives none;
/// `Err(Some(why))` when it isn't a `nostr.json` at all.
fn pubkey_in(body: &[u8], name: &str) -> Result<String, Option<&'static str>> {
    let json: Value = serde_json::from_slice(body).map_err(|_| Some("isn't JSON"))?;
    let names = json.get("names").and_then(Value::as_object).ok_or(Some("has no \"names\""))?;
    let pubkey = names.get(name).and_then(Value::as_str).ok_or(None)?.to_ascii_lowercase();
    if !is_hex64(&pubkey) {
        return Err(Some("gives a key that isn't a hex pubkey"));
    }
    Ok(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(name: &str, domain: &str) -> Option<Address> {
        Some(Address { name: name.into(), domain: domain.into() })
    }

    #[test]
    fn parses_addresses() {
        assert_eq!(Address::parse("alex@gleasonator.com"), address("alex", "gleasonator.com"));
        assert_eq!(Address::parse("_@soapbox.pub"), address("_", "soapbox.pub"));
        assert_eq!(Address::parse("soapbox.pub"), address("_", "soapbox.pub"));
        assert_eq!(Address::parse("Alex@Gleasonator.COM"), address("alex", "gleasonator.com"));
        assert_eq!(Address::parse("a.b-c_d@x.y.z"), address("a.b-c_d", "x.y.z"));
    }

    #[test]
    fn rejects_what_isnt_a_public_domain() {
        for value in [
            "npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj",
            "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5",
            "localhost",
            "alex@localhost",
            "127.0.0.1",
            "alex@10.0.0.1",
            "[::1]",
            "example.com:8080",
            "@example.com",
            "a b@example.com",
            "a@b@example.com",
            "-x.com",
            "x..com",
            "",
        ] {
            assert_eq!(Address::parse(value), None, "{value}");
        }
    }

    #[test]
    fn reads_nostr_json() {
        let key = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5";
        let body = format!(r#"{{"names":{{"_":"{}","bad":"npub1x"}}}}"#, key.to_uppercase());
        assert_eq!(pubkey_in(body.as_bytes(), "_"), Ok(key.to_string()));
        assert_eq!(pubkey_in(body.as_bytes(), "alex"), Err(None));
        assert!(matches!(pubkey_in(body.as_bytes(), "bad"), Err(Some(_))));
        assert!(matches!(pubkey_in(b"<html>", "_"), Err(Some(_))));
        assert!(matches!(pubkey_in(b"{}", "_"), Err(Some(_))));
    }

    /// A `nostr.json` server whose answer can be changed, and that counts
    /// how often it's asked.
    struct Domain {
        origin: String,
        names: Arc<std::sync::Mutex<Value>>,
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Domain {
        async fn start(delay: Duration) -> Domain {
            let names = Arc::new(std::sync::Mutex::new(serde_json::json!({})));
            let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (served, counted) = (names.clone(), hits.clone());
            let app = axum::Router::new().route(
                "/.well-known/nostr.json",
                axum::routing::get(move || async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let names = served.lock().unwrap().clone();
                    serde_json::json!({ "names": names }).to_string()
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await });
            Domain { origin, names, hits }
        }

        fn names(&self, names: Value) {
            *self.names.lock().unwrap() = names;
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    fn resolver(ttl: Duration, db: &Db, origin: &str) -> Arc<Resolver> {
        let mut resolver = Resolver::new(ttl, db.clone()).unwrap();
        Arc::get_mut(&mut resolver).unwrap().origin = Some(origin.to_string());
        resolver
    }

    fn key(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// Wait for a background lookup to leave the database as `want`.
    async fn stored(db: &Db, want: Option<String>) {
        for _ in 0..500 {
            if db.nip05("alex", "example.com").await.unwrap().map(|(pubkey, _)| pubkey) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the database never held {want:?}");
    }

    #[tokio::test]
    async fn keeps_the_last_key_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let address = Address::parse("alex@example.com").unwrap();
        let domain = Domain::start(Duration::ZERO).await;
        domain.names(serde_json::json!({ "alex": key('a') }));
        let db = Db::open(&path).unwrap();
        assert_eq!(resolver(Duration::from_secs(300), &db, &domain.origin).resolve(&address).await.unwrap(), key('a'));
        drop(db);

        // Nothing answers there.
        let db = Db::open(&path).unwrap();
        assert_eq!(resolver(Duration::from_secs(300), &db, "http://127.0.0.1:9").resolve(&address).await.unwrap(), key('a'));
        // Nor once the key is past its ttl: it's the last one given.
        assert_eq!(resolver(Duration::ZERO, &db, "http://127.0.0.1:9").resolve(&address).await.unwrap(), key('a'));
    }

    #[tokio::test]
    async fn gives_an_old_key_while_looking_it_up_again() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let address = Address::parse("alex@example.com").unwrap();
        let domain = Domain::start(Duration::ZERO).await;
        let resolver = resolver(Duration::ZERO, &db, &domain.origin);

        domain.names(serde_json::json!({ "alex": key('a') }));
        assert_eq!(resolver.resolve(&address).await.unwrap(), key('a'));
        domain.names(serde_json::json!({ "alex": key('b') }));
        assert_eq!(resolver.resolve(&address).await.unwrap(), key('a'));
        stored(&db, Some(key('b'))).await;

        // The domain says the name is gone: so it is, here and stored.
        domain.names(serde_json::json!({}));
        assert_eq!(resolver.resolve(&address).await.unwrap(), key('b'));
        stored(&db, None).await;
        while resolver.slots.lock().unwrap()[&address].refreshing.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(matches!(resolver.resolve(&address).await, Err(LookupError::NotFound(_))));
    }

    #[tokio::test]
    async fn looks_up_an_unknown_address_once_for_everyone_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let address = Address::parse("alex@example.com").unwrap();
        let domain = Domain::start(Duration::from_millis(200)).await;
        domain.names(serde_json::json!({ "alex": key('a') }));
        let resolver = resolver(Duration::from_secs(300), &db, &domain.origin);

        let (first, second, third) = tokio::join!(resolver.resolve(&address), resolver.resolve(&address), resolver.resolve(&address));
        assert_eq!([first.unwrap(), second.unwrap(), third.unwrap()], [key('a'), key('a'), key('a')]);
        assert_eq!(domain.hits(), 1);
    }
}
