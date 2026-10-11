//! NIP-05 addresses: `name@domain`, or a bare domain for `_@domain`, looked
//! up in the domain's `/.well-known/nostr.json`.
//!
//! Every file apt or dnf fetches names its repository's owner, so lookups are
//! cached for as long as a repository is, and a domain that stops answering
//! keeps resolving to the key it last gave.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;
use tokio::time::Instant;

use super::is_hex64;

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
    good: Option<(Instant, String)>,
    failed: Option<(Instant, LookupError)>,
}

pub struct Resolver {
    http: reqwest::Client,
    ttl: Duration,
    /// Never held across an await.
    cache: std::sync::Mutex<HashMap<Address, Entry>>,
}

impl Resolver {
    pub fn new(ttl: Duration) -> anyhow::Result<Resolver> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("npkg-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // NIP-05: fetchers must ignore redirects.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Resolver { http, ttl, cache: Default::default() })
    }

    /// The hex pubkey `address` names.
    pub async fn resolve(&self, address: &Address) -> Result<String, LookupError> {
        let stale = {
            let cache = self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = cache.get(address);
            let good = entry.and_then(|entry| entry.good.clone());
            if let Some((at, pubkey)) = &good
                && at.elapsed() < self.ttl
            {
                return Ok(pubkey.clone());
            }
            if let Some((at, error)) = entry.and_then(|entry| entry.failed.as_ref())
                && at.elapsed() < FAILURE_TTL
            {
                return good.map(|(_, pubkey)| pubkey).ok_or_else(|| error.clone());
            }
            good.map(|(_, pubkey)| pubkey)
        };

        let result = self.lookup(address).await;
        let mut cache = self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = cache.entry(address.clone()).or_default();
        match result {
            Ok(pubkey) => {
                *entry = Entry { good: Some((Instant::now(), pubkey.clone())), failed: None };
                Ok(pubkey)
            }
            // The domain says the name is gone: believe it.
            Err(error @ LookupError::NotFound(_)) => {
                *entry = Entry { good: None, failed: Some((Instant::now(), error.clone())) };
                Err(error)
            }
            // The domain is down: the key it last gave stands.
            Err(error) => {
                tracing::warn!(%address, ?error, "NIP-05 lookup failed");
                entry.failed = Some((Instant::now(), error.clone()));
                stale.ok_or(error)
            }
        }
    }

    async fn lookup(&self, address: &Address) -> Result<String, LookupError> {
        let Address { name, domain } = address;
        let failed = |why: String| LookupError::Failed(format!("Couldn't look up {address}: {why}. Try again later."));
        // `parse` only lets through characters that need no escaping.
        let url = format!("https://{domain}/.well-known/nostr.json?name={name}");
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
}
