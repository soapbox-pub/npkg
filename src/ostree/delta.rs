//! Unpacking a Flatpak bundle into the object store.
//!
//! A bundle (`flatpak build-bundle`) is an OSTree static delta from nothing
//! to one commit, in a single file: a superblock whose metadata holds the
//! ref, the app's metadata and its data parts, followed by the commit itself
//! and the list of objects each part makes. A part is a table of file modes,
//! a table of xattrs, a blob of raw data, and a stream of operations that cut
//! objects out of the blob. Running those operations gives every object of
//! the commit, each checked against the checksum the part lists for it.
//!
//! Only what a delta from nothing uses is supported. The operations that
//! patch an object the client already has (`bspatch`, `set-read-source`)
//! can't appear in one, and a bundle that has them is refused.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{FileMeta, Kind, Store, checksum_hex, file_checksum};
use crate::gvariant::{Type, Value};

const SUPERBLOCK_TYPE: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";
const PART_TYPE: &str = "(a(uuu)aa(ayay)ayay)";

/// The part format OSTree writes, and the only one there is.
const PART_VERSION: u32 = 0;

/// The most a part may unpack to: twice the size of any app this serves.
const MAX_PART: u64 = 8 << 30;

/// A commit a bundle carried, as the summary describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub commit: String,
    /// `app/<id>/<arch>/<branch>`.
    pub ref_name: String,
    /// The size of the commit object.
    pub commit_size: u64,
    pub timestamp: u64,
    pub installed_size: u64,
    pub download_size: u64,
    /// The app's `metadata` file: its runtime, permissions, and so on.
    pub metadata: String,
}

/// Unpack the bundle at `path` into `store`, and describe the commit it
/// carried. The commit is written last, so its presence in the store means
/// every object it needs is there too.
pub fn unpack(path: &Path, store: &Store) -> Result<Bundle> {
    let file = File::open(path)?;
    // SAFETY: the file is the gateway's own download, in its own data
    // directory, and nothing writes to it while it's mapped.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    let superblock = Value::read(&map, &Type::parse(SUPERBLOCK_TYPE)?).context("The file isn't a Flatpak bundle")?;
    let metadata = superblock.get(0)?;

    match metadata.lookup("ostree.endianness").and_then(Value::as_byte) {
        None | Some(b'l') => {}
        Some(_) => bail!("The bundle was made on a big-endian machine, which this gateway doesn't read."),
    }
    ensure!(superblock.get(2)?.as_bytes().is_some_and(<[u8]>::is_empty), "The bundle is a delta from an earlier commit, not a whole one.");
    let to = superblock.get(3)?.as_bytes().ok_or_else(|| anyhow!("The bundle names no commit."))?;
    let commit_checksum = checksum_hex(to)?;
    ensure!(superblock.get(7)?.items().is_empty(), "The bundle leaves objects out, to be fetched from elsewhere.");

    // The commit object is checked now and written last.
    let commit = superblock.get(4)?;
    let commit_bytes = commit.to_bytes();
    ensure!(
        hex::encode(Sha256::digest(&commit_bytes)) == commit_checksum,
        "The bundle's commit doesn't match its checksum, {commit_checksum}."
    );
    let bundle = describe(commit, &commit_checksum, commit_bytes.len() as u64, metadata)?;

    let headers = superblock.get(6)?.items();
    for (i, header) in headers.iter().enumerate() {
        let version = header.get(0)?.as_u32().unwrap_or(u32::MAX);
        ensure!(version == PART_VERSION, "The bundle's part {i} is in format {version}, which this gateway doesn't read.");
        let expected = checksum_hex(header.get(1)?.as_bytes().unwrap_or_default())?;
        let objects = header.get(4)?.as_bytes().unwrap_or_default();
        let key = format!("deltas/{}/{i}", b64_path(to));
        let part = metadata.lookup(&key).ok_or_else(|| anyhow!("The bundle's part {i} isn't in it."))?;
        let (compression, payload) = match part.items() {
            [compression, payload] => (compression.as_byte(), payload.as_bytes()),
            _ => (None, None),
        };
        let (Some(compression), Some(payload)) = (compression, payload) else {
            bail!("The bundle's part {i} isn't a part.");
        };
        let mut hasher = Sha256::new();
        hasher.update([compression]);
        hasher.update(payload);
        ensure!(hex::encode(hasher.finalize()) == expected, "The bundle's part {i} doesn't match its checksum.");
        execute_part(compression, payload, objects, store).with_context(|| format!("In the bundle's part {i}"))?;
    }

    store.write(Kind::Commit, &commit_checksum, &commit_bytes)?;
    store.reachable(&commit_checksum).context("The bundle doesn't hold everything its commit needs")?;
    Ok(bundle)
}

/// The ref, sizes and app metadata the commit carries, which `flatpak
/// build-export` put there.
fn describe(commit: &Value, checksum: &str, commit_size: u64, bundle_metadata: &Value) -> Result<Bundle> {
    let metadata = commit.get(0)?;
    let ref_name = metadata
        .lookup("xa.ref")
        .or_else(|| bundle_metadata.lookup("ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("The bundle names no ref."))?
        .to_string();
    ensure!(valid_ref(&ref_name), "The bundle's ref, {ref_name:?}, isn't a Flatpak app's.");
    // A commit bound to refs can only be pulled under one of them.
    if let Some(binding) = metadata.lookup("ostree.ref-binding") {
        ensure!(
            binding.items().iter().any(|bound| bound.as_str() == Some(&ref_name)),
            "The bundle's commit isn't bound to its own ref, {ref_name}."
        );
    }
    let app_metadata = metadata
        .lookup("xa.metadata")
        .or_else(|| bundle_metadata.lookup("metadata"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("The bundle has no app metadata."))?
        .to_string();
    let big_endian = |key: &str| metadata.lookup(key).and_then(Value::as_u64).map(u64::swap_bytes);
    Ok(Bundle {
        commit: checksum.to_string(),
        ref_name,
        commit_size,
        timestamp: commit.get(5)?.as_u64().map(u64::swap_bytes).unwrap_or(0),
        installed_size: big_endian("xa.installed-size").unwrap_or(0),
        download_size: big_endian("xa.download-size").unwrap_or(0),
        metadata: app_metadata,
    })
}

/// `app/<id>/<arch>/<branch>`, in the characters Flatpak allows.
pub fn valid_ref(ref_name: &str) -> bool {
    let parts: Vec<&str> = ref_name.split('/').collect();
    parts.len() == 4
        && parts[0] == "app"
        && parts[1..].iter().all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
}

/// A checksum as OSTree names a delta by it: base64, `/` as `_`, unpadded,
/// split after two characters.
fn b64_path(checksum: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";
    let mut out = String::new();
    for chunk in checksum.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    format!("{}/{}", &out[..2], &out[2..])
}

fn execute_part(compression: u8, payload: &[u8], objects: &[u8], store: &Store) -> Result<()> {
    match compression {
        0 => execute(payload, objects, store),
        b'x' => {
            // Decompressed to a file and mapped: an app's part can be bigger
            // than the memory the gateway should use.
            let mut unpacked = tempfile::tempfile_in(store.tmp())?;
            {
                let mut limited = Limited { inner: BufWriter::new(&mut unpacked), left: MAX_PART };
                lzma_rs::xz_decompress(&mut BufReader::new(payload), &mut limited)
                    .map_err(|error| anyhow!("Couldn't decompress it: {error}"))?;
                limited.inner.flush()?;
            }
            // SAFETY: an anonymous temporary file only this function holds.
            let map = unsafe { memmap2::Mmap::map(&unpacked)? };
            execute(&map, objects, store)
        }
        other => bail!("It's compressed as {other:?}, which OSTree doesn't do."),
    }
}

/// A writer that fails once more than `left` bytes are written to it.
struct Limited<W> {
    inner: W,
    left: u64,
}

impl<W: Write> Write for Limited<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.left = self.left.checked_sub(buf.len() as u64).ok_or_else(|| std::io::Error::other("it unpacks to more than 8 GiB"))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Run a part's operations, writing every object it lists, in order.
fn execute(payload: &[u8], objects: &[u8], store: &Store) -> Result<()> {
    ensure!(objects.len().is_multiple_of(33), "Its object list is malformed.");
    let objects: Vec<(Kind, String)> = objects
        .chunks(33)
        .map(|entry| {
            Ok((Kind::from_byte(entry[0]).ok_or_else(|| anyhow!("It lists an object of type {}.", entry[0]))?, checksum_hex(&entry[1..])?))
        })
        .collect::<Result<_>>()?;
    if objects.is_empty() {
        return Ok(());
    }

    let part = Value::read(payload, &Type::parse(PART_TYPE)?)?;
    let modes = part.get(0)?.items();
    let xattrs = part.get(1)?.items();
    let raw = part.get(2)?.as_bytes().unwrap_or_default();
    let mut ops = Ops { data: part.get(3)?.as_bytes().unwrap_or_default(), at: 0 };

    let slice = |offset: u64, length: u64| -> Result<&[u8]> {
        let end = offset.checked_add(length).ok_or_else(|| anyhow!("An operation's range overflows."))?;
        raw.get(offset as usize..end as usize).ok_or_else(|| anyhow!("An operation reads past the end of the part's data."))
    };
    let file_meta = |ops: &mut Ops| -> Result<FileMeta> {
        let (mode, xattr) = (ops.varint()? as usize, ops.varint()? as usize);
        let mode = modes.get(mode).ok_or_else(|| anyhow!("An operation names mode {mode}, which isn't in the part."))?;
        let xattrs = xattrs.get(xattr).ok_or_else(|| anyhow!("An operation names xattrs {xattr}, which aren't in the part."))?;
        let number = |i: usize| mode.get(i).ok().and_then(Value::as_u32).map(u32::swap_bytes).unwrap_or_default();
        let xattrs = xattrs
            .items()
            .iter()
            .map(|pair| Ok((pair.get(0)?.as_bytes().unwrap_or_default().to_vec(), pair.get(1)?.as_bytes().unwrap_or_default().to_vec())))
            .collect::<Result<_>>()?;
        Ok(FileMeta { uid: number(0), gid: number(1), mode: number(2), xattrs })
    };

    let mut next = objects.iter();
    // A file `open` started and `write` is filling, until `close`.
    let mut open: Option<(Kind, String, FileMeta, Vec<u8>)> = None;
    while let Some(op) = ops.byte() {
        match op {
            b'S' => {
                let (kind, checksum) = next.next().ok_or_else(|| anyhow!("It makes more objects than it lists."))?;
                if *kind == Kind::File {
                    let meta = file_meta(&mut ops)?;
                    let (length, offset) = (ops.varint()?, ops.varint()?);
                    write_file(store, checksum, &meta, slice(offset, length)?)?;
                } else {
                    let (length, offset) = (ops.varint()?, ops.varint()?);
                    let bytes = slice(offset, length)?;
                    ensure!(*kind != Kind::Commit, "It makes a commit, which only the superblock holds.");
                    ensure!(
                        hex::encode(Sha256::digest(bytes)) == *checksum,
                        "Its {} {checksum} doesn't match its checksum.",
                        kind.extension()
                    );
                    store.write(*kind, checksum, bytes)?;
                }
            }
            b'o' => {
                ensure!(open.is_none(), "It opens an object before closing the last.");
                let (kind, checksum) = next.next().ok_or_else(|| anyhow!("It makes more objects than it lists."))?;
                ensure!(*kind == Kind::File, "It opens a {} to write in pieces, which only a file can be.", kind.extension());
                let meta = file_meta(&mut ops)?;
                let size = ops.varint()?;
                ensure!(size <= MAX_PART, "It opens a file of {size} bytes.");
                open = Some((*kind, checksum.clone(), meta, Vec::with_capacity(size as usize)));
            }
            b'w' => {
                let (length, offset) = (ops.varint()?, ops.varint()?);
                let (_, _, _, content) = open.as_mut().ok_or_else(|| anyhow!("It writes with no object open."))?;
                content.extend_from_slice(slice(offset, length)?);
            }
            b'c' => {
                let (_, checksum, meta, content) = open.take().ok_or_else(|| anyhow!("It closes with no object open."))?;
                write_file(store, &checksum, &meta, &content)?;
            }
            b'r' | b'R' | b'B' => bail!("It patches an object the client already has, which a bundle can't."),
            other => bail!("It has an operation {other:?} OSTree doesn't."),
        }
    }
    ensure!(open.is_none(), "It ends with an object still open.");
    ensure!(next.next().is_none(), "It makes fewer objects than it lists.");
    Ok(())
}

fn write_file(store: &Store, expected: &str, meta: &FileMeta, content: &[u8]) -> Result<()> {
    // One the store has already, from another version, was checked then.
    if store.has(Kind::File, expected) {
        return Ok(());
    }
    let checksum = file_checksum(meta, content)?;
    ensure!(checksum == expected, "Its file {expected} doesn't match its checksum.");
    store.write_file(meta, content)?;
    Ok(())
}

/// A part's operations: one byte each, then their arguments as varints.
struct Ops<'a> {
    data: &'a [u8],
    at: usize,
}

impl Ops<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    /// An unsigned LEB128 number, as protobuf has them.
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte().ok_or_else(|| anyhow!("An operation ends early."))?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("An operation's number is too long.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/hello.flatpak");
    const COMMIT: &str = "e4ac6214d95a1e8fdb20a63f534f49da0a616da573fc9738b00110510ce2dd27";

    fn bundle_file(dir: &Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join("bundle.flatpak");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn unpacks_what_flatpak_built() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        let bundle = unpack(&bundle_file(dir.path(), FIXTURE), &store).unwrap();
        assert_eq!(bundle.commit, COMMIT);
        assert_eq!(bundle.ref_name, "app/org.example.Hello/x86_64/stable");
        assert!(bundle.metadata.contains("command=hello"));
        assert_eq!(bundle.timestamp, 1_767_225_600);
        assert_eq!(bundle.commit_size, 612);
        // Every object `flatpak build-export` made: see tests/fixtures/README.md.
        let objects = store.reachable(COMMIT).unwrap();
        assert_eq!(objects.len(), 13);
        let mut listed: Vec<String> =
            store.list().unwrap().into_iter().map(|(kind, checksum, _)| format!("{checksum}.{}", kind.extension())).collect();
        listed.sort();
        assert_eq!(listed, include_str!("../../tests/fixtures/hello.objects").lines().collect::<Vec<_>>());

        // Again, into a store that has it all: nothing changes.
        assert_eq!(unpack(&bundle_file(dir.path(), FIXTURE), &store).unwrap(), bundle);
    }

    #[test]
    fn refuses_a_damaged_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        // Any one byte changed, anywhere, is caught.
        for at in (0..FIXTURE.len()).step_by(7) {
            let mut damaged = FIXTURE.to_vec();
            damaged[at] ^= 0x55;
            let result = unpack(&bundle_file(dir.path(), &damaged), &store);
            assert!(result.is_err() || result.as_ref().is_ok_and(|bundle| bundle.commit == COMMIT), "byte {at}");
        }
        assert!(unpack(&bundle_file(dir.path(), b"not a bundle"), &store).is_err());
    }

    /// A real bundle, named by `NPKG_BUNDLE`: `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn unpacks_a_real_bundle() {
        let path = std::env::var("NPKG_BUNDLE").expect("NPKG_BUNDLE names a .flatpak");
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        let started = std::time::Instant::now();
        let bundle = unpack(Path::new(&path), &store).unwrap();
        let objects = store.reachable(&bundle.commit).unwrap().len();
        eprintln!("{} {} objects in {:?}: {bundle:?}", bundle.ref_name, objects, started.elapsed());
    }

    #[test]
    fn names_deltas_as_ostree_does() {
        let to = hex::decode("636648e7dd532e91d0ba87803f2c135e1f5435ecb7e6482ac716cd677be5734f").unwrap();
        assert_eq!(b64_path(&to), "Y2/ZI591TLpHQuoeAPywTXh9UNey35kgqxxbNZ3vlc08");
    }

    #[test]
    fn reads_varints() {
        let mut ops = Ops { data: &[0x05, 0xac, 0x02, 0xff, 0xff, 0x03], at: 0 };
        assert_eq!(ops.varint().unwrap(), 5);
        assert_eq!(ops.varint().unwrap(), 300);
        assert_eq!(ops.varint().unwrap(), 65535);
        assert!(ops.varint().is_err());
    }
}
