//! SQLite: the NIP-82 events the gateway follows, what each package file was
//! found to be, which commit each Flatpak bundle carried, which file each
//! package version is pinned to, and the key each NIP-05 address last named. With those, every repository is rebuilt
//! after a restart without the network.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};

use crate::inspect::{Format, Meta};
use crate::nostr::Event;
use crate::ostree::delta::Bundle;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

/// A package file, inspected. Keyed by its sha256, so it never goes stale.
#[derive(Clone, Debug)]
pub struct Inspected {
    pub size: u64,
    /// Where the file was found, and where downloads are sent.
    pub url: String,
    /// What it is, or why it isn't a package this gateway can serve.
    pub meta: Result<Meta, String>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        let conn = Connection::open(path).with_context(|| format!("Couldn't open the database at {}.", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS packages (
               sha256 TEXT PRIMARY KEY,
               size INTEGER NOT NULL,
               url TEXT NOT NULL,
               meta TEXT,
               error TEXT
             );
             CREATE TABLE IF NOT EXISTS pins (
               pubkey TEXT NOT NULL,
               d TEXT NOT NULL,
               format TEXT NOT NULL,
               package TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               pinned_at INTEGER NOT NULL DEFAULT (unixepoch()),
               PRIMARY KEY (pubkey, d, format, package)
             );
             CREATE TABLE IF NOT EXISTS nip05 (
               name TEXT NOT NULL,
               domain TEXT NOT NULL,
               pubkey TEXT NOT NULL,
               resolved_at INTEGER NOT NULL,
               PRIMARY KEY (name, domain)
             );
             CREATE TABLE IF NOT EXISTS events (
               id TEXT PRIMARY KEY,
               pubkey TEXT NOT NULL,
               kind INTEGER NOT NULL,
               -- An addressable event's d tag; NULL for any other.
               d TEXT,
               created_at INTEGER NOT NULL,
               json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS events_by_address ON events (pubkey, kind, d);
             CREATE TABLE IF NOT EXISTS bundles (
               sha256 TEXT PRIMARY KEY,
               -- The commit it carried, as JSON, or why it was refused.
               bundle TEXT,
               error TEXT
             );
             DROP TABLE IF EXISTS snapshots;",
        )?;
        Ok(Db { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Run `f` on the blocking pool, off the runtime's threads.
    async fn call<T: Send + 'static>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static) -> anyhow::Result<T> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&conn)
        })
        .await?
        .map_err(Into::into)
    }

    pub async fn inspected(&self, sha256: &str) -> anyhow::Result<Option<Inspected>> {
        let sha256 = sha256.to_string();
        let row = self
            .call(move |conn| {
                conn.query_row("SELECT size, url, meta, error FROM packages WHERE sha256 = ?", [sha256], |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .optional()
            })
            .await?;
        Ok(row.map(|(size, url, meta, error)| {
            let meta = match (meta, error) {
                (Some(meta), _) => serde_json::from_str(&meta).map_err(|error| format!("Stored metadata is unreadable: {error}")),
                (None, error) => Err(error.unwrap_or_default()),
            };
            Inspected { size, url, meta }
        }))
    }

    pub async fn store_inspected(&self, sha256: &str, inspected: &Inspected) -> anyhow::Result<()> {
        let (meta, error) = match &inspected.meta {
            Ok(meta) => (Some(serde_json::to_string(meta)?), None),
            Err(error) => (None, Some(error.clone())),
        };
        let (sha256, size, url) = (sha256.to_string(), inspected.size as i64, inspected.url.clone());
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO packages (sha256, size, url, meta, error) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (sha256) DO NOTHING",
                params![sha256, size, url, meta, error],
            )
        })
        .await?;
        Ok(())
    }

    /// The commit the Flatpak bundle with this hash carried, or why it was
    /// refused; `None` if it hasn't been unpacked.
    pub async fn bundle(&self, sha256: &str) -> anyhow::Result<Option<Result<Bundle, String>>> {
        let sha256 = sha256.to_string();
        let row = self
            .call(move |conn| {
                conn.query_row("SELECT bundle, error FROM bundles WHERE sha256 = ?", [sha256], |row| {
                    Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?))
                })
                .optional()
            })
            .await?;
        Ok(row.map(|(bundle, error)| match (bundle, error) {
            (Some(bundle), _) => serde_json::from_str(&bundle).map_err(|error| format!("Stored bundle is unreadable: {error}")),
            (None, error) => Err(error.unwrap_or_default()),
        }))
    }

    pub async fn store_bundle(&self, sha256: &str, bundle: &Result<Bundle, String>) -> anyhow::Result<()> {
        let (bundle, error) = match bundle {
            Ok(bundle) => (Some(serde_json::to_string(bundle)?), None),
            Err(error) => (None, Some(error.clone())),
        };
        let sha256 = sha256.to_string();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO bundles (sha256, bundle, error) VALUES (?, ?, ?)
                 ON CONFLICT (sha256) DO UPDATE SET bundle = excluded.bundle, error = excluded.error",
                params![sha256, bundle, error],
            )
        })
        .await?;
        Ok(())
    }

    /// Pin `sha256` as the file for `package` (its name, version and
    /// architecture) in this repository, unless one already is. Returns the
    /// file that is.
    pub async fn pin(&self, pubkey: &str, d: &str, format: Format, package: &str, sha256: &str) -> anyhow::Result<String> {
        let args = [pubkey, d, format.as_str(), package, sha256].map(str::to_string);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO pins (pubkey, d, format, package, sha256) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT DO NOTHING",
                params![args[0], args[1], args[2], args[3], args[4]],
            )?;
            conn.query_row(
                "SELECT sha256 FROM pins WHERE pubkey = ? AND d = ? AND format = ? AND package = ?",
                params![args[0], args[1], args[2], args[3]],
                |row| row.get(0),
            )
        })
        .await
    }

    /// The key `name@domain` last resolved to, and how long ago.
    pub async fn nip05(&self, name: &str, domain: &str) -> anyhow::Result<Option<(String, Duration)>> {
        let (name, domain) = (name.to_string(), domain.to_string());
        let row = self
            .call(move |conn| {
                conn.query_row("SELECT pubkey, resolved_at FROM nip05 WHERE name = ? AND domain = ?", [name, domain], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .optional()
            })
            .await?;
        Ok(row.map(|(pubkey, resolved_at)| (pubkey, age(resolved_at))))
    }

    pub async fn store_nip05(&self, name: &str, domain: &str, pubkey: &str) -> anyhow::Result<()> {
        let args = [name, domain, pubkey].map(str::to_string);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO nip05 (name, domain, pubkey, resolved_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT (name, domain) DO UPDATE SET pubkey = excluded.pubkey, resolved_at = excluded.resolved_at",
                params![args[0], args[1], args[2], unix_now()],
            )
        })
        .await?;
        Ok(())
    }

    pub async fn forget_nip05(&self, name: &str, domain: &str) -> anyhow::Result<()> {
        let (name, domain) = (name.to_string(), domain.to_string());
        self.call(move |conn| conn.execute("DELETE FROM nip05 WHERE name = ? AND domain = ?", [name, domain])).await?;
        Ok(())
    }

    /// Store whichever of `events` are new, and return how many were. Of
    /// addressable events (kinds 30000-39999) only the newest for each
    /// address is kept, as NIP-01 has relays do.
    pub async fn store_events(&self, events: Vec<Event>) -> anyhow::Result<usize> {
        let rows = events
            .into_iter()
            .map(|event| {
                let d = (30000..40000).contains(&event.kind).then(|| event.tag("d").unwrap_or_default().to_string());
                Ok((serde_json::to_string(&event)?, d, event))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.call(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let mut stored = 0;
            for (json, d, event) in rows {
                if let Some(d) = &d {
                    // NIP-01: the newest wins, and of two as new, the lower id.
                    let newer: bool = tx.query_row(
                        "SELECT EXISTS (SELECT 1 FROM events WHERE pubkey = ? AND kind = ? AND d = ?
                           AND (created_at > ? OR (created_at = ? AND id <= ?)))",
                        params![event.pubkey, event.kind, d, event.created_at, event.created_at, event.id],
                        |row| row.get(0),
                    )?;
                    if newer {
                        continue;
                    }
                    tx.execute("DELETE FROM events WHERE pubkey = ? AND kind = ? AND d = ?", params![event.pubkey, event.kind, d])?;
                }
                stored += tx.execute(
                    "INSERT OR IGNORE INTO events (id, pubkey, kind, d, created_at, json) VALUES (?, ?, ?, ?, ?, ?)",
                    params![event.id, event.pubkey, event.kind, d, event.created_at, json],
                )?;
            }
            tx.commit()?;
            Ok(stored)
        })
        .await
    }

    /// Every stored event by `pubkey`.
    pub async fn events(&self, pubkey: &str) -> anyhow::Result<Vec<Event>> {
        let pubkey = pubkey.to_string();
        let rows: Vec<String> = self
            .call(move |conn| conn.prepare("SELECT json FROM events WHERE pubkey = ?")?.query_map([pubkey], |row| row.get(0))?.collect())
            .await?;
        // A row this gateway wrote is always readable; skip one that isn't
        // rather than lose the rest.
        Ok(rows.iter().filter_map(|json| serde_json::from_str(json).ok()).collect())
    }

    /// Delete the events of every author not in `authors`.
    pub async fn forget_authors_except(&self, authors: &HashSet<String>) -> anyhow::Result<usize> {
        let authors = authors.clone();
        self.call(move |conn| {
            let stored: Vec<String> =
                conn.prepare("SELECT DISTINCT pubkey FROM events")?.query_map([], |row| row.get(0))?.collect::<Result<_, _>>()?;
            let mut forgotten = 0;
            for pubkey in stored.iter().filter(|pubkey| !authors.contains(*pubkey)) {
                forgotten += conn.execute("DELETE FROM events WHERE pubkey = ?", [pubkey])?;
            }
            Ok(forgotten)
        })
        .await
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)
}

/// How long ago a stored Unix time was.
fn age(then: i64) -> Duration {
    Duration::from_secs(unix_now().saturating_sub(then).max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nip82::{self, tests::published};

    #[tokio::test]
    async fn keeps_the_newest_of_each_address() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let old = published(secret, "1.0", 100);
        let new = published(secret, "1.0", 200);
        let pubkey = old[0].pubkey.clone();

        assert_eq!(db.store_events(old.clone()).await.unwrap(), 3);
        assert_eq!(db.store_events(old.clone()).await.unwrap(), 0);
        // The newer release and application replace the old; both assets stay.
        assert_eq!(db.store_events(new.clone()).await.unwrap(), 3);
        assert_eq!(db.store_events(old).await.unwrap(), 0);
        let stored = db.events(&pubkey).await.unwrap();
        assert_eq!(stored.len(), 4);
        let release = stored.iter().find(|event| event.kind == nip82::RELEASE).unwrap();
        assert_eq!(release.created_at, 200);

        assert_eq!(db.forget_authors_except(&HashSet::from([pubkey.clone()])).await.unwrap(), 0);
        assert_eq!(db.forget_authors_except(&HashSet::new()).await.unwrap(), 4);
        assert!(db.events(&pubkey).await.unwrap().is_empty());
    }
}
