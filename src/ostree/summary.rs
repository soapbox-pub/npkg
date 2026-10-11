//! A remote's `summary`: the refs it has and the commit each points at, and
//! the `xa.cache` Flatpak reads an app's size and metadata from before it
//! fetches anything else. It's written as `flatpak build-update-repo` writes
//! the plain `summary` file, which every Flatpak reads; the indexed summaries
//! newer versions prefer are an optimization for remotes with thousands of
//! refs, and they fall back to this without one.
//!
//! The summary is signed, and so is each commit, in a `.commitmeta` beside
//! it: Flatpak checks both against the key the `.flatpakrepo` gave it.

use crate::gvariant::{Type, Value};
use crate::ostree::delta::Bundle;
use crate::signing::Signer;

/// The summary for `refs`, each the commit a bundle carried. Dated by the
/// newest commit, so the same refs give the same bytes.
pub fn render(refs: &[&Bundle]) -> Vec<u8> {
    let mut refs: Vec<&Bundle> = refs.to_vec();
    refs.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
    let last_modified = refs.iter().map(|bundle| bundle.timestamp).max().unwrap_or(0);

    let entries = refs
        .iter()
        .map(|bundle| {
            Value::Tuple(vec![
                Value::str(&bundle.ref_name),
                Value::Tuple(vec![
                    Value::U64(bundle.commit_size),
                    Value::bytes(hex::decode(&bundle.commit).unwrap_or_default()),
                    Value::vardict(vec![("ostree.commit.timestamp", Value::U64(bundle.timestamp.swap_bytes()))]),
                ]),
            ])
        })
        .collect();
    let cache = refs
        .iter()
        .map(|bundle| {
            Value::Entry(
                Box::new(Value::str(&bundle.ref_name)),
                Box::new(Value::Tuple(vec![
                    Value::U64(bundle.installed_size.swap_bytes()),
                    Value::U64(bundle.download_size.swap_bytes()),
                    Value::str(&bundle.metadata),
                ])),
            )
        })
        .collect();

    let parse = |signature: &str| Type::parse(signature).unwrap_or(Type::Byte);
    Value::Tuple(vec![
        Value::Array(parse("(s(taya{sv}))"), entries),
        Value::vardict(vec![
            ("ostree.summary.mode", Value::str("archive-z2")),
            ("ostree.summary.tombstone-commits", Value::Bool(false)),
            ("ostree.summary.last-modified", Value::U64(last_modified.swap_bytes())),
            ("xa.cache-version", Value::U32(2)),
            // Flatpak has always wrapped this one in a second variant.
            ("xa.cache", Value::variant(Value::Array(parse("{s(tts)}"), cache))),
            ("xa.sparse-cache", Value::Array(parse("{sa{sv}}"), Vec::new())),
        ]),
    ])
    .to_bytes()
}

/// A signature over `data` as OSTree keeps one: `summary.sig`, or a commit's
/// `.commitmeta`.
pub fn signatures(signer: &Signer, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let signature = signer.sign_binary(data)?;
    let signatures = Value::Array(Type::Array(Box::new(Type::Byte)), vec![Value::bytes(signature)]);
    Ok(Value::vardict(vec![("ostree.gpgsigs", signatures)]).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_each_ref() {
        let bundle = Bundle {
            commit: "e4ac6214d95a1e8fdb20a63f534f49da0a616da573fc9738b00110510ce2dd27".into(),
            ref_name: "app/org.example.Hello/x86_64/stable".into(),
            commit_size: 612,
            timestamp: 1_767_225_600,
            installed_size: 1536,
            download_size: 38,
            metadata: "[Application]\nname=org.example.Hello\n".into(),
        };
        let bytes = render(&[&bundle]);
        let summary = Value::read(&bytes, &Type::parse("(a(s(taya{sv}))a{sv})").unwrap()).unwrap();
        assert_eq!(summary.to_bytes(), bytes);

        let entry = &summary.get(0).unwrap().items()[0];
        assert_eq!(entry.get(0).unwrap().as_str(), Some(bundle.ref_name.as_str()));
        let info = entry.get(1).unwrap();
        assert_eq!(info.get(0).unwrap().as_u64(), Some(612));
        assert_eq!(hex::encode(info.get(1).unwrap().as_bytes().unwrap()), bundle.commit);

        let meta = summary.get(1).unwrap();
        assert_eq!(meta.lookup("ostree.summary.last-modified").and_then(Value::as_u64).map(u64::swap_bytes), Some(1_767_225_600));
        let cache = meta.lookup("xa.cache").unwrap().unwrap_variant();
        let sizes = cache.lookup(&bundle.ref_name).unwrap();
        assert_eq!(sizes.get(0).unwrap().as_u64().map(u64::swap_bytes), Some(1536));
        assert_eq!(sizes.get(2).unwrap().as_str(), Some(bundle.metadata.as_str()));
        // The same refs, the same bytes.
        assert_eq!(render(&[&bundle]), bytes);
    }
}
