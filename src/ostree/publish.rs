//! Publishing a bundle's commit as `flatpak build-commit-from` publishes a
//! build, which is how flat-manager, and so Flathub, does it: as a new
//! commit with the bundle's tree and metadata, on top of the ref's last one.
//!
//! The parents make a history, which `flatpak remote-info --log` lists and
//! `flatpak update --commit=` goes back along. Each is dated after its
//! parent, since Flatpak refuses an update older than what's installed: a
//! release withdrawn, putting an older one back at the head, is published
//! as a new commit too, which clients update to as to any other.

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::delta::Bundle;
use super::{COMMIT_TYPE, Kind, Store};
use crate::gvariant::{Type, Value};

/// The commit's own keys, which [`commit`] sets: the rest of the bundle's
/// metadata, such as `xa.metadata` and its sizes, is copied.
const OWN_KEYS: [&str; 5] =
    ["xa.ref", "xa.from_commit", "ostree.collection-binding", "ostree.collection-refs-binding", "ostree.ref-binding"];

/// A commit of `source`'s tree, on top of `parent`, with `subject` and
/// `body`: written to `store`, and its object returned.
pub fn commit(store: &Store, source: &Bundle, parent: Option<&str>, subject: &str, body: &str, timestamp: u64) -> Result<Vec<u8>> {
    let bytes = store.read(Kind::Commit, &source.commit)?;
    let original = Value::read(&bytes, &Type::parse(COMMIT_TYPE)?)?;
    let mut metadata = Value::vardict(vec![
        ("ostree.collection-binding", Value::str("")),
        ("ostree.ref-binding", Value::Array(Type::Str, vec![Value::str(&source.ref_name)])),
        ("xa.ref", Value::str(&source.ref_name)),
        ("xa.from_commit", Value::str(&source.commit)),
    ]);
    if let Value::Array(_, entries) = &mut metadata {
        for entry in original.get(0)?.items() {
            let Value::Entry(key, _) = entry else { continue };
            if !key.as_str().is_some_and(|key| OWN_KEYS.contains(&key)) {
                entries.push(entry.clone());
            }
        }
    }
    let parent = parent.map(hex::decode).transpose()?.unwrap_or_default();
    let object = Value::Tuple(vec![
        metadata,
        Value::bytes(parent),
        Value::Array(Type::parse("(say)")?, Vec::new()),
        Value::str(subject),
        Value::str(body),
        Value::U64(timestamp.swap_bytes()),
        original.get(6)?.clone(),
        original.get(7)?.clone(),
    ])
    .to_bytes();
    store.write(Kind::Commit, &checksum(&object), &object)?;
    Ok(object)
}

pub fn checksum(object: &[u8]) -> String {
    hex::encode(Sha256::digest(object))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ostree::{commit_root, delta};

    /// The parent a commit names, if any.
    pub fn parent(object: &[u8]) -> Option<String> {
        let commit = Value::read(object, &Type::parse(COMMIT_TYPE).unwrap()).unwrap();
        let parent = commit.get(1).unwrap().as_bytes().unwrap();
        (!parent.is_empty()).then(|| hex::encode(parent))
    }

    #[test]
    fn publishes_as_build_commit_from_does() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        let path = dir.path().join("hello.flatpak");
        std::fs::write(&path, include_bytes!("../../tests/fixtures/hello.flatpak")).unwrap();
        let bundle = delta::unpack(&path, &store).unwrap();

        let first = commit(&store, &bundle, None, "Hello 1.0", "", 100).unwrap();
        let second = commit(&store, &bundle, Some(&checksum(&first)), "Hello 1.0", "Again.", 101).unwrap();
        assert_eq!(parent(&first), None);
        assert_eq!(parent(&second), Some(checksum(&first)));

        // The same tree, so nothing new to fetch, and the app's metadata.
        let source = store.read(Kind::Commit, &bundle.commit).unwrap();
        assert_eq!(commit_root(&second).unwrap(), commit_root(&source).unwrap());
        assert_eq!(store.reachable(&checksum(&second)).unwrap().len(), store.reachable(&bundle.commit).unwrap().len());
        let value = Value::read(&second, &Type::parse(COMMIT_TYPE).unwrap()).unwrap();
        let metadata = value.get(0).unwrap();
        assert_eq!(metadata.lookup("xa.from_commit").and_then(Value::as_str), Some(bundle.commit.as_str()));
        assert_eq!(metadata.lookup("xa.metadata").and_then(Value::as_str), Some(bundle.metadata.as_str()));
        assert_eq!(
            metadata.items().iter().filter(|entry| matches!(entry, Value::Entry(key, _) if key.as_str() == Some("xa.ref"))).count(),
            1
        );
        assert_eq!(value.get(3).unwrap().as_str(), Some("Hello 1.0"));
        assert_eq!(value.get(5).unwrap().as_u64().map(u64::swap_bytes), Some(101));

        // The same inputs, the same commit.
        assert_eq!(commit(&store, &bundle, None, "Hello 1.0", "", 100).unwrap(), first);
    }
}
