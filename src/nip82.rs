//! NIP-82 software applications (kind 32267), releases (kind 30063) and
//! assets (kind 3063): what one application's author has published, fetched
//! from relays.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::json;

use crate::nostr::{Event, is_hex64, relay};

pub const APPLICATION: i64 = 32267;
pub const RELEASE: i64 = 30063;
pub const ASSET: i64 = 3063;

pub const DEB_MIME: &str = "application/vnd.debian.binary-package";
pub const RPM_MIME: &str = "application/x-rpm";

/// How long a build waits on relays, per round of queries.
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);

/// Asset ids asked for in one filter.
const IDS_PER_FILTER: usize = 200;

#[derive(Clone, Debug, Default)]
pub struct Application {
    pub name: Option<String>,
    pub summary: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub channel: String,
    pub created_at: i64,
    pub assets: Vec<Asset>,
}

#[derive(Clone, Debug)]
pub struct Asset {
    pub mime: String,
    pub sha256: String,
    pub url: Option<String>,
    pub version: Option<String>,
    pub platforms: Vec<String>,
}

/// Everything one application's author has published about it.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub application: Option<Application>,
    pub releases: Vec<Release>,
}

/// The application `pubkey:d`, its releases, and their assets. Only events
/// signed by `pubkey` count: anyone can publish an event that points at
/// someone else's application.
pub async fn fetch(relays: &[String], pubkey: &str, d: &str) -> anyhow::Result<Snapshot> {
    let coordinate = format!("{APPLICATION}:{pubkey}:{d}");
    let events = relay::query(
        relays,
        &[
            json!({"kinds": [APPLICATION], "authors": [pubkey], "#d": [d]}),
            json!({"kinds": [RELEASE], "authors": [pubkey], "#a": [coordinate]}),
        ],
        QUERY_TIMEOUT,
    )
    .await?;
    let events: Vec<Event> = events.into_iter().filter(|event| event.pubkey == pubkey).collect();

    let application = events
        .iter()
        .filter(|event| event.kind == APPLICATION && event.tag("d") == Some(d))
        .max_by_key(|event| (event.created_at, std::cmp::Reverse(event.id.clone())))
        .map(|event| Application { name: event.tag("name").map(str::to_string), summary: event.tag("summary").map(str::to_string) });

    // Releases are addressable: of each `d`, the newest stands.
    let mut newest: HashMap<&str, &Event> = HashMap::new();
    for event in events.iter().filter(|event| event.kind == RELEASE) {
        let Some(release_d) = event.tag("d") else { continue };
        if !has_tag(event, "a", &coordinate) || event.tag("i") != Some(d) {
            continue;
        }
        let Some(version) = event.tag("version") else { continue };
        if release_d != format!("{d}@{version}") {
            continue;
        }
        let entry = newest.entry(release_d).or_insert(event);
        if (event.created_at, std::cmp::Reverse(&event.id)) > (entry.created_at, std::cmp::Reverse(&entry.id)) {
            *entry = event;
        }
    }

    let asset_ids: Vec<String> =
        newest.values().flat_map(|event| tag_values(event, "e")).filter(|id| is_hex64(id)).map(str::to_string).collect();
    let mut assets = HashMap::new();
    for ids in asset_ids.chunks(IDS_PER_FILTER) {
        let filter = json!({"ids": ids, "kinds": [ASSET], "authors": [pubkey]});
        for event in relay::query(relays, &[filter], QUERY_TIMEOUT).await? {
            if event.kind != ASSET || event.pubkey != pubkey || event.tag("i") != Some(d) {
                continue;
            }
            if let Some(asset) = parse_asset(&event) {
                assets.insert(event.id.clone(), asset);
            }
        }
    }

    let releases = newest
        .into_values()
        .map(|event| Release {
            version: event.tag("version").unwrap_or_default().to_string(),
            channel: event.tag("c").unwrap_or("main").to_string(),
            created_at: event.created_at,
            assets: tag_values(event, "e").filter_map(|id| assets.get(id).cloned()).collect(),
        })
        .collect();

    Ok(Snapshot { application, releases })
}

fn parse_asset(event: &Event) -> Option<Asset> {
    let sha256 = event.tag("x")?.to_ascii_lowercase();
    if !is_hex64(&sha256) {
        return None;
    }
    Some(Asset {
        mime: event.tag("m")?.to_ascii_lowercase(),
        sha256,
        url: event.tag("url").map(str::to_string),
        version: event.tag("version").map(str::to_string),
        platforms: tag_values(event, "f").map(str::to_string).collect(),
    })
}

fn tag_values<'a>(event: &'a Event, name: &'a str) -> impl Iterator<Item = &'a str> {
    event.tags.iter().filter(move |tag| tag.first().map(String::as_str) == Some(name)).filter_map(|tag| tag.get(1).map(String::as_str))
}

fn has_tag(event: &Event, name: &str, value: &str) -> bool {
    tag_values(event, name).any(|v| v == value)
}
