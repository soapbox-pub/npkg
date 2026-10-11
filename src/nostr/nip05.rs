//! NIP-05 addresses: `name@domain`, or a bare domain for `_@domain`, looked
//! up in the domain's `/.well-known/nostr.json`.
//!
//! Every file apt or dnf fetches names its repository's owner, and the paths
//! users are given don't change, so an address the gateway serves is looked
//! up once, stored, and then looked up again in the background once a day. A
//! key only stops being given when the domain says so: its `nostr.json` no
//! longer lists the name, or names someone off the team. A domain that's
//! down, or answers with anything else, leaves the key it last gave.
//!
//! Only addresses that name the team are remembered. Any other address costs
//! a lookup each time it's asked for, so the lookups a request can make the
//! gateway do are limited: per client, overall, and at once.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::time::Instant;

use super::is_hex64;
use crate::db::Db;
use crate::rate_limit::{RateLimit, RateLimiter};

/// The largest `nostr.json` read. Real ones list a few names; some list
/// thousands, but a lookup with `?name=` should get one.
const MAX_BODY: usize = 256 << 10;

/// How long a key is given before it's looked up again, in the background.
const REFRESH: Duration = Duration::from_secs(24 * 3600);

/// How long after a failed background lookup it's tried again.
const RETRY: Duration = Duration::from_secs(600);

/// Lookups of addresses not known yet, which a request has to wait on. Few
/// are ever needed: a team has a handful of addresses, each looked up once.
const PER_CLIENT: RateLimit = RateLimit { capacity: 10.0, refill: Duration::from_secs(3600) };
const OVERALL: RateLimit = RateLimit { capacity: 60.0, refill: Duration::from_secs(3600) };
const AT_ONCE: usize = 4;

/// Clients whose lookups are counted. Past this, the least recent are
/// forgotten.
const MAX_CLIENTS: usize = 10_000;

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
    /// The client, or everyone, has made the gateway do enough lookups.
    Limited(String),
}

#[derive(Default)]
struct Entry {
    /// Whether `key` has been read from the database yet.
    loaded: bool,
    /// A team key, and when to look it up again.
    key: Option<(Instant, String)>,
}

#[derive(Default)]
struct Slot {
    /// Held across a lookup nothing is known for yet, so the requests that
    /// arrive meanwhile (apt asks for several files at once) share it.
    entry: tokio::sync::Mutex<Entry>,
    refreshing: AtomicBool,
}

struct Limits {
    clients: RateLimiter<IpAddr>,
    overall: RateLimiter<()>,
}

pub struct Resolver {
    http: reqwest::Client,
    db: Db,
    /// The keys worth remembering an address for.
    team: HashSet<String>,
    refresh: Duration,
    retry: Duration,
    /// Where every domain's `nostr.json` is fetched from instead, in tests.
    origin: Option<String>,
    /// Never held across an await.
    slots: std::sync::Mutex<HashMap<Address, Arc<Slot>>>,
    /// Never held across an await.
    limits: std::sync::Mutex<Limits>,
    at_once: tokio::sync::Semaphore,
}

impl Resolver {
    pub fn new(db: Db, team: HashSet<String>) -> anyhow::Result<Arc<Resolver>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("npkg-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // NIP-05: fetchers must ignore redirects.
            .redirect(reqwest::redirect::Policy::none())
            // A domain anyone names could resolve to what's private here.
            .dns_resolver(crate::net::PublicResolver::new([]))
            .build()?;
        let limits = Limits { clients: RateLimiter::new(PER_CLIENT, MAX_CLIENTS), overall: RateLimiter::new(OVERALL, 1) };
        Ok(Arc::new(Resolver {
            http,
            db,
            team,
            refresh: REFRESH,
            retry: RETRY,
            origin: None,
            slots: Default::default(),
            limits: std::sync::Mutex::new(limits),
            at_once: tokio::sync::Semaphore::new(AT_ONCE),
        }))
    }

    /// The hex pubkey `address` names, for `client`. Only an address with
    /// no team key known waits on its domain, and counts against the limits.
    pub async fn resolve(self: &Arc<Self>, address: &Address, client: IpAddr) -> Result<String, LookupError> {
        let slot = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(address.clone()).or_default().clone();
        let mut entry = slot.entry.lock().await;
        if !entry.loaded {
            match self.db.nip05(&address.name, &address.domain).await {
                Ok(row) => entry.key = row.map(|(pubkey, age)| (Instant::now() + self.refresh.saturating_sub(age), pubkey)),
                Err(error) => tracing::warn!(%address, ?error, "couldn't read a stored NIP-05 key"),
            }
            entry.loaded = true;
        }

        if let Some((refresh_at, pubkey)) = &entry.key {
            if Instant::now() >= *refresh_at && !slot.refreshing.swap(true, Ordering::AcqRel) {
                let (resolver, slot, address) = (self.clone(), slot.clone(), address.clone());
                tokio::spawn(async move {
                    let result = resolver.lookup(&address).await;
                    resolver.refreshed(&mut *slot.entry.lock().await, &address, result).await;
                    slot.refreshing.store(false, Ordering::Release);
                });
            }
            return Ok(pubkey.clone());
        }

        let result = match self.admit(client) {
            Ok(_permit) => self.lookup(address).await,
            Err(error) => Err(error),
        };
        match &result {
            Ok(pubkey) if self.team.contains(pubkey) => {
                entry.key = Some((Instant::now() + self.refresh, pubkey.clone()));
                if let Err(error) = self.db.store_nip05(&address.name, &address.domain, pubkey).await {
                    tracing::warn!(%address, ?error, "couldn't store a NIP-05 key");
                }
            }
            // Nothing worth keeping: an address nobody asks for again shouldn't
            // take up room.
            _ => {
                drop(entry);
                let mut slots = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if slots.get(address).is_some_and(|current| Arc::ptr_eq(current, &slot)) {
                    slots.remove(address);
                }
            }
        }
        result
    }

    /// Permission for a request to make one lookup, held while it runs.
    fn admit(&self, client: IpAddr) -> Result<tokio::sync::SemaphorePermit<'_>, LookupError> {
        let busy = || {
            LookupError::Limited(
                "The gateway is looking up too many NIP-05 addresses right now. Try again in a minute, or use the npub.".into(),
            )
        };
        let permit = self.at_once.try_acquire().map_err(|_| busy())?;
        let mut limits = self.limits.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Checked before either is spent, so a client turned away by one
        // doesn't use up the other.
        if !limits.clients.check(&client) {
            return Err(LookupError::Limited(
                "You've made the gateway look up too many NIP-05 addresses. Try again later, or use the npub.".into(),
            ));
        }
        if !limits.overall.check(&()) {
            return Err(busy());
        }
        limits.clients.take(&client);
        limits.overall.take(&());
        Ok(permit)
    }

    /// Act on a background lookup of an address that names the team.
    async fn refreshed(&self, entry: &mut Entry, address: &Address, result: Result<String, LookupError>) {
        let stored = match result {
            Ok(pubkey) if self.team.contains(&pubkey) => {
                entry.key = Some((Instant::now() + self.refresh, pubkey.clone()));
                self.db.store_nip05(&address.name, &address.domain, &pubkey).await
            }
            // The domain says the name is gone, or is someone else's now:
            // believe it.
            Ok(_) | Err(LookupError::NotFound(_)) => {
                tracing::info!(%address, "NIP-05 address no longer names the team");
                entry.key = None;
                self.db.forget_nip05(&address.name, &address.domain).await
            }
            // The domain is down, or broken: the key it last gave stands.
            Err(error) => {
                tracing::warn!(%address, ?error, "NIP-05 lookup failed");
                if let Some((refresh_at, _)) = &mut entry.key {
                    *refresh_at = Instant::now() + self.retry;
                }
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
        // Not NotFound: a missing file is as likely a broken site as a
        // decision, and only a decision drops a key.
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(failed(format!("{domain} has no NIP-05 nostr.json")));
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
    /// how often it's asked. `null` names answer 404.
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
                    if names.is_null() {
                        return (axum::http::StatusCode::NOT_FOUND, String::new());
                    }
                    (axum::http::StatusCode::OK, serde_json::json!({ "names": names }).to_string())
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

    fn key(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// A resolver whose team is keys `a` and `b`.
    fn resolver(refresh: Duration, db: &Db, origin: &str) -> Arc<Resolver> {
        let mut resolver = Resolver::new(db.clone(), HashSet::from([key('a'), key('b')])).unwrap();
        let inner = Arc::get_mut(&mut resolver).unwrap();
        inner.origin = Some(origin.to_string());
        inner.refresh = refresh;
        inner.retry = refresh;
        resolver
    }

    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// Wait for background lookups to finish.
    async fn settle(resolver: &Resolver, address: &Address) {
        loop {
            let slot = resolver.slots.lock().unwrap().get(address).cloned();
            if !slot.is_some_and(|slot| slot.refreshing.load(Ordering::Acquire)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn stored(db: &Db) -> Option<String> {
        db.nip05("alex", "example.com").await.unwrap().map(|(pubkey, _)| pubkey)
    }

    #[tokio::test]
    async fn keeps_the_last_key_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let address = Address::parse("alex@example.com").unwrap();
        let domain = Domain::start(Duration::ZERO).await;
        domain.names(serde_json::json!({ "alex": key('a') }));
        let db = Db::open(&path).unwrap();
        assert_eq!(resolver(REFRESH, &db, &domain.origin).resolve(&address, CLIENT).await.unwrap(), key('a'));
        drop(db);

        // Nothing answers there, even once the key is due a lookup.
        let db = Db::open(&path).unwrap();
        let down = resolver(Duration::ZERO, &db, "http://127.0.0.1:9");
        assert_eq!(down.resolve(&address, CLIENT).await.unwrap(), key('a'));
        settle(&down, &address).await;
        assert_eq!(down.resolve(&address, CLIENT).await.unwrap(), key('a'));
        assert_eq!(stored(&db).await, Some(key('a')));
    }

    #[tokio::test]
    async fn drops_a_key_only_when_the_domain_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let address = Address::parse("alex@example.com").unwrap();
        let domain = Domain::start(Duration::ZERO).await;
        let resolver = resolver(Duration::ZERO, &db, &domain.origin);
        let resolve = || async {
            let result = resolver.resolve(&address, CLIENT).await;
            settle(&resolver, &address).await;
            result
        };

        domain.names(serde_json::json!({ "alex": key('a') }));
        assert_eq!(resolve().await.unwrap(), key('a'));
        // Another team key: the old one is given while it's looked up.
        domain.names(serde_json::json!({ "alex": key('b') }));
        assert_eq!(resolve().await.unwrap(), key('a'));
        assert_eq!(stored(&db).await, Some(key('b')));

        // No nostr.json at all reads as a broken site, not a decision.
        domain.names(Value::Null);
        assert_eq!(resolve().await.unwrap(), key('b'));
        assert_eq!(stored(&db).await, Some(key('b')));

        // A nostr.json that doesn't list the name is a decision.
        domain.names(serde_json::json!({}));
        assert_eq!(resolve().await.unwrap(), key('b'));
        assert_eq!(stored(&db).await, None);
        assert!(matches!(resolve().await, Err(LookupError::NotFound(_))));

        // So is naming someone off the team, who isn't remembered.
        domain.names(serde_json::json!({ "alex": key('c') }));
        assert_eq!(resolve().await.unwrap(), key('c'));
        assert_eq!(stored(&db).await, None);
        assert!(resolver.slots.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn looks_up_an_unknown_address_once_for_everyone_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let address = Address::parse("alex@example.com").unwrap();
        let domain = Domain::start(Duration::from_millis(200)).await;
        domain.names(serde_json::json!({ "alex": key('a') }));
        let resolver = resolver(REFRESH, &db, &domain.origin);

        let (first, second, third) =
            tokio::join!(resolver.resolve(&address, CLIENT), resolver.resolve(&address, CLIENT), resolver.resolve(&address, CLIENT));
        assert_eq!([first.unwrap(), second.unwrap(), third.unwrap()], [key('a'), key('a'), key('a')]);
        assert_eq!(domain.hits(), 1);
    }

    #[tokio::test]
    async fn limits_the_lookups_a_client_can_force() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let domain = Domain::start(Duration::ZERO).await;
        domain.names(serde_json::json!({ "alex": key('a') }));
        let resolver = resolver(REFRESH, &db, &domain.origin);

        let other = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        for i in 0..PER_CLIENT.capacity as usize {
            let address = Address::parse(&format!("x{i}@example.com")).unwrap();
            assert!(matches!(resolver.resolve(&address, other).await, Err(LookupError::NotFound(_))));
        }
        let address = Address::parse("y@example.com").unwrap();
        assert!(matches!(resolver.resolve(&address, other).await, Err(LookupError::Limited(_))));
        assert_eq!(domain.hits(), PER_CLIENT.capacity as usize);
        // Nothing was remembered of those, and someone else isn't held up.
        assert!(resolver.slots.lock().unwrap().is_empty());
        let address = Address::parse("alex@example.com").unwrap();
        assert_eq!(resolver.resolve(&address, CLIENT).await.unwrap(), key('a'));
    }
}
