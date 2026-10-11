//! The sync worker: what keeps every repository current.
//!
//! Three things drive it:
//!
//! 1. At startup, every repository is built from the events already stored,
//!    without the network, so a restart serves what it served before in
//!    milliseconds.
//! 2. A live subscription to the team's NIP-82 events. A new one rebuilds its
//!    author's repositories once things have been quiet for [`SETTLE`]: CI
//!    publishes a release's assets and then the release, and one rebuild for
//!    the lot is enough.
//! 3. A full re-fetch every `resync_interval`, so an event missed on the wire
//!    (a relay down, a restart) is still picked up, and a file that couldn't
//!    be downloaded last time is tried again.
//!
//! A repository is only rebuilt when what it's built from changed, and a
//! failed rebuild leaves the last one up.
//!
//! Once a day, after a resync, the OSTree store is pruned of what no
//! repository's releases need any more. It happens here, between builds,
//! so it never deletes an object a bundle being unpacked is counting on.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::time::Instant;

use crate::db::Db;
use crate::nip82;
use crate::nostr::{Event, relay};
use crate::repo::{Lookup, Repos};

/// How long a full fetch waits on relays, per round of queries.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Asset ids asked for in one filter.
const IDS_PER_FILTER: usize = 200;

/// How long after the last new event its author's repositories are rebuilt.
const SETTLE: Duration = Duration::from_secs(3);

/// How often the OSTree store is pruned, and how old an object has to be to
/// go: younger ones may belong to a bundle not served yet.
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 3600);
const PRUNE_GRACE: Duration = Duration::from_secs(24 * 3600);

pub struct Worker {
    pub relays: Vec<String>,
    /// The hex pubkeys whose applications are followed.
    pub authors: HashSet<String>,
    pub resync_interval: Duration,
    pub db: Db,
    pub repos: Arc<Repos>,
}

impl Worker {
    pub fn start(self) {
        tokio::spawn(self.run());
    }

    async fn run(self) {
        match self.db.forget_authors_except(&self.authors).await {
            Ok(0) => {}
            Ok(forgotten) => tracing::info!(forgotten, "forgot the events of authors no longer listed"),
            Err(error) => tracing::warn!(?error, "couldn't forget the events of authors no longer listed"),
        }
        let authors: BTreeSet<String> = self.authors.iter().cloned().collect();
        for author in &authors {
            self.rebuild(author, false, false).await;
        }

        let filter = json!({"kinds": nip82::KINDS, "authors": authors});
        let mut live = relay::subscribe(&self.relays, vec![filter]);
        let mut resync = tokio::time::interval(self.resync_interval);
        resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut dirty = BTreeSet::new();
        let mut settled = Instant::now();
        let mut pruned: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = resync.tick() => {
                    for author in &authors {
                        self.resync(author).await;
                    }
                    self.repos.mark_synced();
                    // A full resync covered whatever was waiting.
                    dirty.clear();
                    if pruned.is_none_or(|at| at.elapsed() >= PRUNE_EVERY) {
                        self.prune().await;
                        pruned = Some(Instant::now());
                    }
                }
                Some(event) = live.recv() => {
                    if let Some(author) = self.store(event).await {
                        dirty.insert(author);
                        settled = Instant::now() + SETTLE;
                    }
                }
                _ = tokio::time::sleep_until(settled), if !dirty.is_empty() => {
                    for author in std::mem::take(&mut dirty) {
                        self.rebuild(&author, true, false).await;
                    }
                }
            }
        }
    }

    /// Delete the objects no repository's bundles need.
    async fn prune(&self) {
        let keep: HashSet<String> =
            self.repos.all().iter().flat_map(|repo| repo.bundles.iter().map(|bundle| bundle.bundle.commit.clone())).collect();
        let store = self.repos.store().clone();
        match tokio::task::spawn_blocking(move || store.prune(&keep, PRUNE_GRACE)).await {
            Ok(Ok((0, _))) => {}
            Ok(Ok((objects, bytes))) => tracing::info!(objects, bytes, "pruned the OSTree store"),
            Ok(Err(error)) => tracing::warn!(?error, "couldn't prune the OSTree store"),
            Err(error) => tracing::warn!(?error, "couldn't prune the OSTree store"),
        }
    }

    /// Store a live event, and say whose it was if it was new.
    async fn store(&self, event: Event) -> Option<String> {
        if !self.authors.contains(&event.pubkey) || !nip82::KINDS.contains(&event.kind) {
            return None;
        }
        let author = event.pubkey.clone();
        match self.db.store_events(vec![event]).await {
            Ok(0) => None,
            Ok(_) => Some(author),
            Err(error) => {
                tracing::warn!(?error, "couldn't store an event");
                None
            }
        }
    }

    /// Ask relays for everything `author` has published, then rebuild.
    async fn resync(&self, author: &str) {
        let filter = json!({"kinds": [nip82::APPLICATION, nip82::RELEASE], "authors": [author]});
        match relay::query(&self.relays, &[filter], QUERY_TIMEOUT).await {
            Ok(events) => {
                let events = events.into_iter().filter(|event| event.pubkey == author).collect();
                if let Err(error) = self.db.store_events(events).await {
                    tracing::warn!(author, ?error, "couldn't store events");
                }
            }
            Err(error) => tracing::warn!(author, %error, "resync failed"),
        }
        self.rebuild(author, true, true).await;
    }

    /// Rebuild each of `author`'s repositories whose events changed, and
    /// stop serving any that no longer has any. `online`, assets the
    /// releases list but the database lacks are fetched first, and package
    /// files not seen before are downloaded. `retry`, a repository missing a
    /// file it couldn't download is rebuilt even if nothing changed.
    async fn rebuild(&self, author: &str, online: bool, retry: bool) {
        let mut events = match self.db.events(author).await {
            Ok(events) => events,
            Err(error) => {
                tracing::warn!(author, ?error, "couldn't read stored events");
                return;
            }
        };
        if online && self.fetch_assets(author, &events).await {
            match self.db.events(author).await {
                Ok(fresh) => events = fresh,
                Err(error) => tracing::warn!(author, ?error, "couldn't read stored events"),
            }
        }

        let applications = nip82::applications(&events, author);
        for d in &applications {
            let snapshot = nip82::snapshot(&events, author, d);
            if let Lookup::Found(repo) = self.repos.get(author, d)
                && repo.snapshot == snapshot
                && !(retry && repo.incomplete)
            {
                continue;
            }
            match self.repos.build(author, d, &snapshot, !online).await {
                Ok(repo) => self.repos.publish(repo),
                Err(error) => tracing::warn!(author, d, ?error, "build failed"),
            }
        }
        self.repos.retain(|pubkey, d| pubkey != author || applications.contains(d));
    }

    /// Fetch the asset events `author`'s releases list that aren't stored,
    /// and say whether any turned up.
    async fn fetch_assets(&self, author: &str, events: &[Event]) -> bool {
        let missing = nip82::missing_assets(events, author);
        let mut found = false;
        for ids in missing.chunks(IDS_PER_FILTER) {
            let filter = json!({"ids": ids, "kinds": [nip82::ASSET], "authors": [author]});
            match relay::query(&self.relays, &[filter], QUERY_TIMEOUT).await {
                Ok(events) => {
                    let events = events.into_iter().filter(|event| event.pubkey == author && event.kind == nip82::ASSET).collect();
                    match self.db.store_events(events).await {
                        Ok(stored) => found |= stored > 0,
                        Err(error) => tracing::warn!(author, ?error, "couldn't store events"),
                    }
                }
                Err(error) => {
                    tracing::warn!(author, %error, "couldn't fetch assets");
                    break;
                }
            }
        }
        found
    }
}
