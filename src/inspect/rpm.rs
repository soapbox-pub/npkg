//! Reading an .rpm's header: the lead, the signature header, then the header
//! that holds everything repodata describes. The payload is never opened.

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};

const LEAD_SIZE: usize = 96;
const HEADER_MAGIC: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];

/// Header tags, as rpm's rpmtag.h numbers them.
mod tag {
    pub const NAME: u32 = 1000;
    pub const VERSION: u32 = 1001;
    pub const RELEASE: u32 = 1002;
    pub const EPOCH: u32 = 1003;
    pub const SUMMARY: u32 = 1004;
    pub const DESCRIPTION: u32 = 1005;
    pub const BUILDTIME: u32 = 1006;
    pub const BUILDHOST: u32 = 1007;
    pub const SIZE: u32 = 1009;
    pub const VENDOR: u32 = 1011;
    pub const LICENSE: u32 = 1014;
    pub const PACKAGER: u32 = 1015;
    pub const GROUP: u32 = 1016;
    pub const URL: u32 = 1020;
    pub const ARCH: u32 = 1022;
    pub const OLDFILENAMES: u32 = 1027;
    pub const FILEMODES: u32 = 1030;
    pub const FILEFLAGS: u32 = 1037;
    pub const SOURCERPM: u32 = 1044;
    pub const ARCHIVESIZE: u32 = 1046;
    pub const PROVIDENAME: u32 = 1047;
    pub const REQUIREFLAGS: u32 = 1048;
    pub const REQUIRENAME: u32 = 1049;
    pub const REQUIREVERSION: u32 = 1050;
    pub const CONFLICTFLAGS: u32 = 1053;
    pub const CONFLICTNAME: u32 = 1054;
    pub const CONFLICTVERSION: u32 = 1055;
    pub const OBSOLETENAME: u32 = 1090;
    pub const PROVIDEFLAGS: u32 = 1112;
    pub const PROVIDEVERSION: u32 = 1113;
    pub const OBSOLETEFLAGS: u32 = 1114;
    pub const OBSOLETEVERSION: u32 = 1115;
    pub const DIRINDEXES: u32 = 1116;
    pub const BASENAMES: u32 = 1117;
    pub const DIRNAMES: u32 = 1118;
    pub const LONGSIZE: u32 = 5009;
    pub const RECOMMENDNAME: u32 = 5046;
    pub const RECOMMENDVERSION: u32 = 5047;
    pub const RECOMMENDFLAGS: u32 = 5048;
    pub const SUGGESTNAME: u32 = 5049;
    pub const SUGGESTVERSION: u32 = 5050;
    pub const SUGGESTFLAGS: u32 = 5051;
    pub const SUPPLEMENTNAME: u32 = 5052;
    pub const SUPPLEMENTVERSION: u32 = 5053;
    pub const SUPPLEMENTFLAGS: u32 = 5054;
    pub const ENHANCENAME: u32 = 5055;
    pub const ENHANCEVERSION: u32 = 5056;
    pub const ENHANCEFLAGS: u32 = 5057;

    /// In the signature header: the payload's uncompressed size.
    pub const SIG_PAYLOADSIZE: u32 = 1007;
}

const SENSE_LESS: u32 = 1 << 1;
const SENSE_GREATER: u32 = 1 << 2;
const SENSE_EQUAL: u32 = 1 << 3;
const SENSE_PREREQ: u32 = 1 << 6;
const SENSE_SCRIPT_PRE: u32 = 1 << 9;
const SENSE_SCRIPT_POST: u32 = 1 << 10;
const SENSE_RPMLIB: u32 = 1 << 24;

const FILE_GHOST: u32 = 1 << 6;
const MODE_TYPE: u32 = 0o170000;
const MODE_DIR: u32 = 0o040000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpmMeta {
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub summary: String,
    pub description: String,
    pub packager: String,
    pub url: String,
    pub license: String,
    pub vendor: String,
    pub group: String,
    pub buildhost: String,
    pub sourcerpm: String,
    pub build_time: u64,
    pub installed_size: u64,
    pub archive_size: u64,
    /// The main header's byte range in the file, as repodata's
    /// `rpm:header-range` gives it.
    pub header_start: u64,
    pub header_end: u64,
    pub provides: Vec<Dependency>,
    pub requires: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub obsoletes: Vec<Dependency>,
    pub recommends: Vec<Dependency>,
    pub suggests: Vec<Dependency>,
    pub supplements: Vec<Dependency>,
    pub enhances: Vec<Dependency>,
    pub files: Vec<File>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub flags: u32,
    /// `[epoch:]version[-release]`, or empty.
    pub evr: String,
}

impl Dependency {
    /// The comparison, as repodata spells it.
    pub fn comparison(&self) -> Option<&'static str> {
        match self.flags & (SENSE_LESS | SENSE_GREATER | SENSE_EQUAL) {
            SENSE_LESS => Some("LT"),
            SENSE_GREATER => Some("GT"),
            SENSE_EQUAL => Some("EQ"),
            f if f == SENSE_LESS | SENSE_EQUAL => Some("LE"),
            f if f == SENSE_GREATER | SENSE_EQUAL => Some("GE"),
            _ => None,
        }
    }

    /// Whether it must be installed before the package's scripts run.
    pub fn pre(&self) -> bool {
        self.flags & (SENSE_PREREQ | SENSE_SCRIPT_PRE | SENSE_SCRIPT_POST) != 0
    }

    /// An `rpmlib(...)` requirement: rpm's own, left out of repodata.
    pub fn rpmlib(&self) -> bool {
        self.flags & SENSE_RPMLIB != 0 || self.name.starts_with("rpmlib(")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    pub path: String,
    pub dir: bool,
    pub ghost: bool,
}

pub fn inspect(bytes: &[u8]) -> anyhow::Result<RpmMeta> {
    ensure!(bytes.len() >= LEAD_SIZE && bytes[..4] == [0xed, 0xab, 0xee, 0xdb], "The file isn't an .rpm.");
    ensure!(u16::from_be_bytes([bytes[6], bytes[7]]) == 0, "The .rpm is a source package.");

    let (signature, signature_len) = Header::parse(&bytes[LEAD_SIZE..]).context("The .rpm's signature header is damaged.")?;
    // The signature header is padded to a multiple of 8 bytes.
    let start = LEAD_SIZE + signature_len.next_multiple_of(8);
    let (header, header_len) =
        Header::parse(bytes.get(start..).context("The .rpm is truncated.")?).context("The .rpm's header is damaged.")?;

    let string = |tag| header.string(tag).unwrap_or_default();
    let mut files = Vec::new();
    let modes = header.ints(tag::FILEMODES);
    let flags = header.ints(tag::FILEFLAGS);
    let paths = match (header.strings(tag::BASENAMES), header.strings(tag::DIRNAMES), header.ints(tag::DIRINDEXES)) {
        (basenames, dirnames, indexes) if !basenames.is_empty() => {
            ensure!(basenames.len() == indexes.len(), "The .rpm's file list is damaged.");
            basenames
                .iter()
                .zip(&indexes)
                .map(|(base, &index)| {
                    let dir = dirnames.get(index as usize).context("The .rpm's file list is damaged.")?;
                    Ok(format!("{dir}{base}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        }
        _ => header.strings(tag::OLDFILENAMES),
    };
    for (i, path) in paths.into_iter().enumerate() {
        let mode = modes.get(i).copied().unwrap_or_default();
        let flags = flags.get(i).copied().unwrap_or_default();
        files.push(File { path, dir: mode & MODE_TYPE == MODE_DIR, ghost: flags & FILE_GHOST != 0 });
    }

    let meta = RpmMeta {
        name: string(tag::NAME),
        epoch: header.ints(tag::EPOCH).first().copied().unwrap_or(0),
        version: string(tag::VERSION),
        release: string(tag::RELEASE),
        arch: string(tag::ARCH),
        summary: string(tag::SUMMARY),
        description: string(tag::DESCRIPTION),
        packager: string(tag::PACKAGER),
        url: string(tag::URL),
        license: string(tag::LICENSE),
        vendor: string(tag::VENDOR),
        group: string(tag::GROUP),
        buildhost: string(tag::BUILDHOST),
        sourcerpm: string(tag::SOURCERPM),
        build_time: header.ints(tag::BUILDTIME).first().copied().unwrap_or(0).into(),
        installed_size: header
            .int64s(tag::LONGSIZE)
            .first()
            .copied()
            .unwrap_or_else(|| header.ints(tag::SIZE).first().copied().unwrap_or(0).into()),
        archive_size: header.ints(tag::ARCHIVESIZE).first().or(signature.ints(tag::SIG_PAYLOADSIZE).first()).copied().unwrap_or(0).into(),
        header_start: start as u64,
        header_end: (start + header_len) as u64,
        provides: header.dependencies(tag::PROVIDENAME, tag::PROVIDEFLAGS, tag::PROVIDEVERSION)?,
        requires: header.dependencies(tag::REQUIRENAME, tag::REQUIREFLAGS, tag::REQUIREVERSION)?,
        conflicts: header.dependencies(tag::CONFLICTNAME, tag::CONFLICTFLAGS, tag::CONFLICTVERSION)?,
        obsoletes: header.dependencies(tag::OBSOLETENAME, tag::OBSOLETEFLAGS, tag::OBSOLETEVERSION)?,
        recommends: header.dependencies(tag::RECOMMENDNAME, tag::RECOMMENDFLAGS, tag::RECOMMENDVERSION)?,
        suggests: header.dependencies(tag::SUGGESTNAME, tag::SUGGESTFLAGS, tag::SUGGESTVERSION)?,
        supplements: header.dependencies(tag::SUPPLEMENTNAME, tag::SUPPLEMENTFLAGS, tag::SUPPLEMENTVERSION)?,
        enhances: header.dependencies(tag::ENHANCENAME, tag::ENHANCEFLAGS, tag::ENHANCEVERSION)?,
        files,
    };
    ensure!(!meta.name.is_empty() && !meta.version.is_empty() && !meta.arch.is_empty(), "The .rpm has no name, version or architecture.");
    Ok(meta)
}

/// One header structure: its index, and the data store the index points into.
struct Header<'a> {
    entries: Vec<Entry>,
    store: &'a [u8],
}

struct Entry {
    tag: u32,
    kind: u32,
    offset: usize,
    count: usize,
}

const TYPE_INT16: u32 = 3;
const TYPE_INT32: u32 = 4;
const TYPE_INT64: u32 = 5;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

impl<'a> Header<'a> {
    /// The header at the start of `bytes`, and its length.
    fn parse(bytes: &'a [u8]) -> anyhow::Result<(Header<'a>, usize)> {
        ensure!(bytes.len() >= 16 && bytes[..4] == HEADER_MAGIC, "bad header magic");
        let count = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
        let store_len = u32::from_be_bytes(bytes[12..16].try_into()?) as usize;
        ensure!(count < 1 << 16 && store_len < 256 << 20, "header too large");
        let index_end = 16 + count * 16;
        let len = index_end + store_len;
        ensure!(bytes.len() >= len, "header truncated");

        let entries = bytes[16..index_end]
            .as_chunks::<16>()
            .0
            .iter()
            .map(|raw| {
                let word = |i: usize| u32::from_be_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
                Entry { tag: word(0), kind: word(4), offset: word(8) as usize, count: word(12) as usize }
            })
            .collect();
        Ok((Header { entries, store: &bytes[index_end..len] }, len))
    }

    fn entry(&self, tag: u32) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.tag == tag)
    }

    fn strings(&self, tag: u32) -> Vec<String> {
        let Some(entry) = self.entry(tag) else { return Vec::new() };
        if !matches!(entry.kind, TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING) {
            return Vec::new();
        }
        let count = if entry.kind == TYPE_STRING { 1 } else { entry.count };
        let mut out = Vec::new();
        let mut rest = self.store.get(entry.offset..).unwrap_or_default();
        for _ in 0..count {
            let Some(end) = rest.iter().position(|&b| b == 0) else { break };
            out.push(String::from_utf8_lossy(&rest[..end]).into_owned());
            rest = &rest[end + 1..];
        }
        out
    }

    fn string(&self, tag: u32) -> Option<String> {
        self.strings(tag).into_iter().next()
    }

    fn ints(&self, tag: u32) -> Vec<u32> {
        let Some(entry) = self.entry(tag) else { return Vec::new() };
        let width = match entry.kind {
            TYPE_INT16 => 2,
            TYPE_INT32 => 4,
            _ => return Vec::new(),
        };
        let Some(data) = self.store.get(entry.offset..entry.offset + entry.count * width) else { return Vec::new() };
        data.chunks_exact(width)
            .map(|b| if width == 2 { u16::from_be_bytes([b[0], b[1]]).into() } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) })
            .collect()
    }

    fn int64s(&self, tag: u32) -> Vec<u64> {
        let Some(entry) = self.entry(tag).filter(|entry| entry.kind == TYPE_INT64) else { return Vec::new() };
        let Some(data) = self.store.get(entry.offset..entry.offset + entry.count * 8) else { return Vec::new() };
        data.as_chunks::<8>().0.iter().map(|b| u64::from_be_bytes(*b)).collect()
    }

    fn dependencies(&self, names: u32, flags: u32, versions: u32) -> anyhow::Result<Vec<Dependency>> {
        let names = self.strings(names);
        let flags = self.ints(flags);
        let versions = self.strings(versions);
        if names.is_empty() {
            return Ok(Vec::new());
        }
        if flags.len() != names.len() || versions.len() != names.len() {
            bail!("The .rpm's dependency lists are damaged.");
        }
        Ok(names.into_iter().zip(flags).zip(versions).map(|((name, flags), evr)| Dependency { name, flags, evr }).collect())
    }
}

/// `[epoch:]version[-release]`, split.
pub fn split_evr(evr: &str) -> (Option<&str>, &str, Option<&str>) {
    let (epoch, rest) = match evr.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => (Some(epoch), rest),
        _ => (None, evr),
    };
    match rest.rsplit_once('-') {
        Some((version, release)) => (epoch, version, Some(release)),
        None => (epoch, rest, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_evrs() {
        assert_eq!(split_evr("1:2.3-4.fc40"), (Some("1"), "2.3", Some("4.fc40")));
        assert_eq!(split_evr("2.3"), (None, "2.3", None));
        assert_eq!(split_evr("2.3~rc.1-1"), (None, "2.3~rc.1", Some("1")));
    }

    #[test]
    fn refuses_what_isnt_an_rpm() {
        assert!(inspect(b"").is_err());
        assert!(inspect(&[0u8; 200]).is_err());
    }

    /// A real package nfpm built: see tests/fixtures/README.md.
    #[test]
    fn reads_an_nfpm_package() {
        let meta = inspect(include_bytes!("../../tests/fixtures/hello-1.2.0-rc.1.x86_64.rpm")).unwrap();
        assert_eq!(meta.name, "hello");
        assert_eq!(meta.version, "1.2.0~rc.1");
        assert_eq!(meta.arch, "x86_64");
        assert!(meta.files.iter().any(|file| file.path == "/usr/bin/hello" && !file.dir));
        assert!(meta.header_end > meta.header_start);
    }
}
