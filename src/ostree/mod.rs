//! OSTree, as much of it as serving Flatpak needs: an `archive-z2` object
//! store that `ostree pull` and `flatpak` fetch from over HTTP, filled by
//! unpacking Flatpak bundles ([`delta`]), and the signed summaries that say
//! what's in it ([`summary`]).
//!
//! Objects are named by their checksums, so every application and version
//! shares one store, and a new version only adds the files that changed.

pub mod appstream;
pub mod delta;
pub mod summary;

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use sha2::{Digest, Sha256};

use crate::gvariant::{Type, Value};

pub const COMMIT_TYPE: &str = "(a{sv}aya(say)sstayay)";
const DIRTREE_TYPE: &str = "(a(say)a(sayay))";

/// OSTree's object types, by the numbers it gives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    File,
    DirTree,
    DirMeta,
    Commit,
}

impl Kind {
    pub fn from_byte(byte: u8) -> Option<Kind> {
        match byte {
            1 => Some(Kind::File),
            2 => Some(Kind::DirTree),
            3 => Some(Kind::DirMeta),
            4 => Some(Kind::Commit),
            _ => None,
        }
    }

    /// The extension of its file in an `archive-z2` repository.
    pub fn extension(self) -> &'static str {
        match self {
            Kind::File => "filez",
            Kind::DirTree => "dirtree",
            Kind::DirMeta => "dirmeta",
            Kind::Commit => "commit",
        }
    }

    pub fn from_extension(extension: &str) -> Option<Kind> {
        [Kind::File, Kind::DirTree, Kind::DirMeta, Kind::Commit].into_iter().find(|kind| kind.extension() == extension)
    }
}

/// Whether `s` is a checksum as OSTree names objects: 64 lowercase hex.
pub fn is_checksum(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A checksum as bytes, as hex.
pub fn checksum_hex(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() == 32, "a checksum is 32 bytes, not {}", bytes.len());
    Ok(hex::encode(bytes))
}

/// A file as the delta describes it: everything but its content.
#[derive(Clone, Debug)]
pub struct FileMeta {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    /// `(name, value)`, names NUL-terminated as OSTree keeps them.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

impl FileMeta {
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    /// A regular file owned by root, mode 0644, with no xattrs.
    pub fn plain_file() -> FileMeta {
        FileMeta { uid: 0, gid: 0, mode: S_IFREG | 0o644, xattrs: Vec::new() }
    }

    /// A symlink owned by root, as Flatpak makes them.
    pub fn plain_symlink() -> FileMeta {
        FileMeta { uid: 0, gid: 0, mode: S_IFLNK | 0o777, xattrs: Vec::new() }
    }

    fn xattrs_value(&self) -> Value<'static> {
        let mut xattrs = self.xattrs.clone();
        xattrs.sort();
        let items = xattrs.into_iter().map(|(name, value)| Value::Tuple(vec![Value::bytes(name), Value::bytes(value)])).collect();
        Value::Array(Type::parse("(ayay)").unwrap_or(Type::Byte), items)
    }

    /// The header a file object's checksum is taken over, before its
    /// content: `(uuuusa(ayay))`, its numbers big-endian.
    fn header(&self, symlink_target: &str) -> Vec<u8> {
        length_prefixed(Value::Tuple(vec![
            Value::U32(self.uid.swap_bytes()),
            Value::U32(self.gid.swap_bytes()),
            Value::U32(self.mode.swap_bytes()),
            Value::U32(0),
            Value::str(symlink_target),
            self.xattrs_value(),
        ]))
    }

    /// The header of the same file in an `archive-z2` repository, which adds
    /// its size: `(tuuuusa(ayay))`.
    fn archive_header(&self, size: u64, symlink_target: &str) -> Vec<u8> {
        length_prefixed(Value::Tuple(vec![
            Value::U64(size.swap_bytes()),
            Value::U32(self.uid.swap_bytes()),
            Value::U32(self.gid.swap_bytes()),
            Value::U32(self.mode.swap_bytes()),
            Value::U32(0),
            Value::str(symlink_target),
            self.xattrs_value(),
        ]))
    }
}

/// A file header as OSTree streams it: its length, big-endian, four NULs to
/// align it, then it.
fn length_prefixed(value: Value) -> Vec<u8> {
    let body = value.to_bytes();
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&body);
    out
}

/// A file object's checksum: for a symlink `content` is its target.
pub fn file_checksum(meta: &FileMeta, content: &[u8]) -> Result<String> {
    let (target, data) = split_content(meta, content)?;
    let mut hasher = Sha256::new();
    hasher.update(meta.header(target));
    hasher.update(data);
    Ok(hex::encode(hasher.finalize()))
}

/// A symlink's target and no data, or a regular file's data and no target.
fn split_content<'a>(meta: &FileMeta, content: &'a [u8]) -> Result<(&'a str, &'a [u8])> {
    if meta.is_symlink() {
        Ok((std::str::from_utf8(content).context("A symlink's target isn't UTF-8")?, &[]))
    } else if meta.is_regular() {
        Ok(("", content))
    } else {
        bail!("A file object is a regular file or a symlink, and mode {:o} is neither.", meta.mode)
    }
}

/// What a directory lists: its files by name, and its subdirectories by
/// name, with their trees and metadata. Sorted by name, as OSTree keeps
/// them.
#[derive(Default)]
pub struct DirTree {
    pub files: Vec<(String, String)>,
    pub dirs: Vec<(String, String, String)>,
}

impl DirTree {
    /// The object as OSTree writes it, and its checksum.
    pub fn to_object(&self) -> Result<(String, Vec<u8>)> {
        let mut files = self.files.clone();
        files.sort();
        let mut dirs = self.dirs.clone();
        dirs.sort();
        let files = files
            .into_iter()
            .map(|(name, checksum)| Ok(Value::Tuple(vec![Value::str(name), Value::bytes(hex::decode(checksum)?)])))
            .collect::<Result<_>>()?;
        let dirs = dirs
            .into_iter()
            .map(|(name, tree, meta)| {
                Ok(Value::Tuple(vec![Value::str(name), Value::bytes(hex::decode(tree)?), Value::bytes(hex::decode(meta)?)]))
            })
            .collect::<Result<_>>()?;
        let bytes = Value::Tuple(vec![Value::Array(Type::parse("(say)")?, files), Value::Array(Type::parse("(sayay)")?, dirs)]).to_bytes();
        Ok((hex::encode(Sha256::digest(&bytes)), bytes))
    }
}

pub fn read_dirtree(bytes: &[u8]) -> Result<DirTree> {
    let value = Value::read(bytes, &Type::parse(DIRTREE_TYPE)?)?;
    let mut tree = DirTree::default();
    for file in value.get(0)?.items() {
        let name = file.get(0)?.as_str().unwrap_or_default();
        ensure!(valid_name(name), "A directory lists a file named {name:?}.");
        tree.files.push((name.to_string(), checksum_hex(file.get(1)?.as_bytes().unwrap_or_default())?));
    }
    for dir in value.get(1)?.items() {
        let name = dir.get(0)?.as_str().unwrap_or_default();
        ensure!(valid_name(name), "A directory lists a directory named {name:?}.");
        tree.dirs.push((
            name.to_string(),
            checksum_hex(dir.get(1)?.as_bytes().unwrap_or_default())?,
            checksum_hex(dir.get(2)?.as_bytes().unwrap_or_default())?,
        ));
    }
    Ok(tree)
}

/// The metadata of a directory owned by root, mode 0755, with no xattrs:
/// what every directory Flatpak makes itself has.
pub fn plain_dirmeta() -> (String, Vec<u8>) {
    let bytes = Value::Tuple(vec![
        Value::U32(0),
        Value::U32(0),
        Value::U32(0o040755u32.swap_bytes()),
        Value::Array(Type::parse("(ayay)").unwrap_or(Type::Byte), Vec::new()),
    ])
    .to_bytes();
    (hex::encode(Sha256::digest(&bytes)), bytes)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/')
}

/// A commit's root tree and root directory metadata.
pub fn commit_root(bytes: &[u8]) -> Result<(String, String)> {
    let commit = Value::read(bytes, &Type::parse(COMMIT_TYPE)?)?;
    Ok((checksum_hex(commit.get(6)?.as_bytes().unwrap_or_default())?, checksum_hex(commit.get(7)?.as_bytes().unwrap_or_default())?))
}

/// The `archive-z2` object store at `<dir>/objects/ab/cdef….<kind>`.
#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir.join("objects")).with_context(|| format!("Couldn't create {}.", dir.display()))?;
        // What's left in tmp was being written when the gateway stopped.
        let _ = std::fs::remove_dir_all(dir.join("tmp"));
        std::fs::create_dir_all(dir.join("tmp"))?;
        Ok(Store { dir: dir.to_path_buf() })
    }

    /// Where temporary files go: on the same filesystem, so they can be
    /// renamed into place.
    pub fn tmp(&self) -> PathBuf {
        self.dir.join("tmp")
    }

    pub fn path(&self, kind: Kind, checksum: &str) -> PathBuf {
        self.dir.join("objects").join(&checksum[..2]).join(format!("{}.{}", &checksum[2..], kind.extension()))
    }

    pub fn has(&self, kind: Kind, checksum: &str) -> bool {
        self.path(kind, checksum).is_file()
    }

    pub fn read(&self, kind: Kind, checksum: &str) -> Result<Vec<u8>> {
        let path = self.path(kind, checksum);
        std::fs::read(&path).with_context(|| format!("Couldn't read the {} {checksum}.", kind.extension()))
    }

    /// Write an object, unless it's there already. It's synced before it's
    /// renamed into place, so a crash never leaves a partial object where a
    /// whole one is expected.
    pub fn write(&self, kind: Kind, checksum: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(kind, checksum);
        if path.is_file() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = tempfile::NamedTempFile::new_in(self.tmp())?;
        file.write_all(bytes)?;
        file.as_file().sync_data()?;
        file.persist(&path).map_err(|error| error.error)?;
        Ok(())
    }

    /// Write a file object as a `.filez`, unless it's there already, and
    /// return its checksum.
    pub fn write_file(&self, meta: &FileMeta, content: &[u8]) -> Result<String> {
        let checksum = file_checksum(meta, content)?;
        let path = self.path(Kind::File, &checksum);
        if path.is_file() {
            return Ok(checksum);
        }
        let (target, data) = split_content(meta, content)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = tempfile::NamedTempFile::new_in(self.tmp())?;
        file.write_all(&meta.archive_header(data.len() as u64, target))?;
        // A symlink has no data at all, not even an empty compressed stream.
        if meta.is_regular() {
            let mut encoder = DeflateEncoder::new(std::io::BufWriter::new(file.as_file_mut()), Compression::new(6));
            encoder.write_all(data)?;
            encoder.finish()?.flush()?;
        }
        file.as_file().sync_data()?;
        file.persist(&path).map_err(|error| error.error)?;
        Ok(checksum)
    }

    /// Every object reachable from `commit`, the commit included. An error if
    /// any is missing.
    pub fn reachable(&self, commit: &str) -> Result<HashSet<(Kind, String)>> {
        let mut found = HashSet::from([(Kind::Commit, commit.to_string())]);
        let (tree, meta) = commit_root(&self.read(Kind::Commit, commit)?)?;
        let mut pending = vec![(tree, meta)];
        while let Some((tree, meta)) = pending.pop() {
            ensure!(self.has(Kind::DirMeta, &meta), "The dirmeta {meta} is missing.");
            found.insert((Kind::DirMeta, meta));
            if !found.insert((Kind::DirTree, tree.clone())) {
                continue;
            }
            let dirtree = read_dirtree(&self.read(Kind::DirTree, &tree)?)?;
            for (_, file) in dirtree.files {
                ensure!(self.has(Kind::File, &file), "The file {file} is missing.");
                found.insert((Kind::File, file));
            }
            pending.extend(dirtree.dirs.into_iter().map(|(_, tree, meta)| (tree, meta)));
        }
        Ok(found)
    }

    /// The file at `path` (`a/b/c`) in `commit`'s tree, by checksum.
    pub fn lookup(&self, commit: &str, path: &str) -> Result<Option<String>> {
        let (mut tree, _) = commit_root(&self.read(Kind::Commit, commit)?)?;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            let dirtree = read_dirtree(&self.read(Kind::DirTree, &tree)?)?;
            if parts.peek().is_none() {
                return Ok(dirtree.files.into_iter().find(|(name, _)| name == part).map(|(_, checksum)| checksum));
            }
            match dirtree.dirs.into_iter().find(|(name, _, _)| name == part) {
                Some((_, subtree, _)) => tree = subtree,
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// A regular file's content, from its `.filez`, if it's no more than
    /// `max` bytes.
    pub fn file_content(&self, checksum: &str, max: u64) -> Result<Vec<u8>> {
        let filez = self.read(Kind::File, checksum)?;
        let length = filez.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize).unwrap_or(usize::MAX);
        let header = filez.get(8..8usize.saturating_add(length)).ok_or_else(|| anyhow::anyhow!("The file {checksum} is truncated."))?;
        let header = Value::read(header, &Type::parse("(tuuuusa(ayay))")?)?;
        let mode = header.get(3)?.as_u32().map(u32::swap_bytes).unwrap_or_default();
        ensure!(mode & S_IFMT == S_IFREG, "The file {checksum} isn't a regular file.");
        let size = header.get(0)?.as_u64().map(u64::swap_bytes).unwrap_or_default();
        ensure!(size <= max, "The file {checksum} is {size} bytes, more than {max}.");
        let mut content = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(flate2::read::DeflateDecoder::new(&filez[8 + length..]), max + 1),
            &mut content,
        )?;
        ensure!(content.len() as u64 == size, "The file {checksum} isn't the size it says.");
        Ok(content)
    }

    /// The size of an object on disk: what a client downloads to get it.
    pub fn size(&self, kind: Kind, checksum: &str) -> u64 {
        std::fs::metadata(self.path(kind, checksum)).map_or(0, |metadata| metadata.len())
    }

    /// Delete every object not reachable from `keep` and older than
    /// `grace`, and return how many went and their size. A commit in `keep`
    /// that's missing keeps nothing, and isn't an error: its bundle is
    /// unpacked again when it's next needed.
    pub fn prune(&self, keep: &HashSet<String>, grace: std::time::Duration) -> Result<(usize, u64)> {
        let mut reachable = HashSet::new();
        for commit in keep {
            if let Ok(objects) = self.reachable(commit) {
                reachable.extend(objects);
            }
        }
        let cutoff = std::time::SystemTime::now() - grace;
        let (mut count, mut size) = (0, 0);
        for (kind, checksum, modified) in self.list()? {
            if modified > cutoff || reachable.contains(&(kind, checksum.clone())) {
                continue;
            }
            size += std::fs::metadata(self.path(kind, &checksum)).map_or(0, |metadata| metadata.len());
            self.delete(kind, &checksum)?;
            count += 1;
        }
        Ok((count, size))
    }

    /// Every object in the store, and when it was written.
    pub fn list(&self) -> Result<Vec<(Kind, String, std::time::SystemTime)>> {
        let mut objects = Vec::new();
        for prefix in std::fs::read_dir(self.dir.join("objects"))? {
            let prefix = prefix?;
            let prefix_name = prefix.file_name().to_string_lossy().into_owned();
            for entry in std::fs::read_dir(prefix.path())? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some((rest, extension)) = name.split_once('.') else { continue };
                let (Some(kind), checksum) = (Kind::from_extension(extension), format!("{prefix_name}{rest}")) else { continue };
                if is_checksum(&checksum) {
                    objects.push((kind, checksum, entry.metadata()?.modified()?));
                }
            }
        }
        Ok(objects)
    }

    pub fn delete(&self, kind: Kind, checksum: &str) -> Result<()> {
        match std::fs::remove_file(self.path(kind, checksum)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_only_what_nothing_needs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        let path = dir.path().join("hello.flatpak");
        std::fs::write(&path, include_bytes!("../../tests/fixtures/hello.flatpak")).unwrap();
        let commit = delta::unpack(&path, &store).unwrap().commit;
        let meta = FileMeta { uid: 0, gid: 0, mode: S_IFREG | 0o644, xattrs: Vec::new() };
        let stray = store.write_file(&meta, b"no commit lists this").unwrap();

        // Everything is new, so nothing goes yet.
        assert_eq!(store.prune(&HashSet::new(), std::time::Duration::from_secs(3600)).unwrap().0, 0);
        // Only what the commit doesn't need goes.
        assert_eq!(store.prune(&HashSet::from([commit.clone()]), std::time::Duration::ZERO).unwrap().0, 1);
        assert!(!store.has(Kind::File, &stray));
        assert_eq!(store.reachable(&commit).unwrap().len(), 22);
        // With no commit kept, everything goes.
        assert_eq!(store.prune(&HashSet::new(), std::time::Duration::ZERO).unwrap().0, 22);
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn checksums_files_as_ostree_does() {
        // From the fixture: share/hello/data.txt, and the symlink beside it.
        let regular = FileMeta { uid: 0, gid: 0, mode: S_IFREG | 0o644, xattrs: Vec::new() };
        let symlink = FileMeta { uid: 0, gid: 0, mode: S_IFLNK | 0o777, xattrs: Vec::new() };
        let objects = include_str!("../../tests/fixtures/hello.objects");
        for checksum in [file_checksum(&regular, b"some data\n").unwrap(), file_checksum(&symlink, b"data.txt").unwrap()] {
            assert!(objects.contains(&format!("{checksum}.filez")), "{checksum}");
        }
        assert!(file_checksum(&FileMeta { mode: 0o040755, ..regular }, b"").is_err());
    }
}
