//! Reading an APK: its manifest, from the binary XML `AndroidManifest.xml`;
//! the ABIs it has native code for; and the certificates it's signed with,
//! from its APK Signing Block or its JAR signature.

use std::collections::BTreeSet;
use std::io::Read;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::der;

/// How much of a decompressed zip entry is read. A manifest is a few
/// kilobytes; this only bounds a compression bomb.
const MAX_ENTRY: u64 = 4 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkMeta {
    pub package: String,
    pub version_code: u64,
    pub version_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub max_sdk: Option<u32>,
    pub permissions: Vec<Permission>,
    /// `uses-permission-sdk-23`: asked for on Android 6 and later only.
    pub permissions_sdk23: Vec<Permission>,
    /// The features it can't run without.
    pub features: Vec<String>,
    /// The ABIs it has native code for, from its `lib/<abi>/` directories.
    pub nativecode: Vec<String>,
    /// The SHA-256 of each signer's certificate, which is what F-Droid
    /// compares with an installed app's.
    pub signers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub max_sdk: Option<u32>,
}

impl ApkMeta {
    /// What sets it apart from another build of the same version: the ABIs
    /// it runs on.
    pub fn arch(&self) -> String {
        if self.nativecode.is_empty() { "all".to_string() } else { self.nativecode.join(",") }
    }
}

pub fn inspect(bytes: &[u8]) -> anyhow::Result<ApkMeta> {
    let zip = Zip::open(bytes)?;
    let manifest = zip.entry("AndroidManifest.xml")?.context("The APK has no AndroidManifest.xml.")?;
    let mut meta = parse_manifest(&manifest)?;
    let abis: BTreeSet<&str> = zip
        .entries
        .iter()
        .filter_map(|entry| entry.name.strip_prefix("lib/")?.split_once('/').map(|(abi, _)| abi))
        .filter(|abi| !abi.is_empty())
        .collect();
    meta.nativecode = abis.into_iter().map(str::to_string).collect();
    meta.signers = signers(&zip)?.iter().map(|cert| hex::encode(Sha256::digest(cert))).collect();
    if meta.signers.is_empty() {
        bail!("The APK isn't signed, so Android won't install it.");
    }
    Ok(meta)
}

/// The certificate of each signer, in the order fdroidserver looks for
/// them, so a signer here is the one F-Droid's own repositories list: the
/// JAR signature (v1), then APK Signature Schemes v2 and v3. Only an app
/// whose key was rotated has different ones in each.
fn signers<'a>(zip: &'a Zip<'a>) -> anyhow::Result<Vec<Vec<u8>>> {
    let blocks: Vec<&ZipEntry> = zip
        .entries
        .iter()
        .filter(|entry| {
            entry
                .name
                .strip_prefix("META-INF/")
                .is_some_and(|name| !name.contains('/') && [".RSA", ".DSA", ".EC"].iter().any(|extension| name.ends_with(extension)))
        })
        .collect();
    if let [block] = blocks[..] {
        let pkcs7 = zip.read(block)?;
        let cert = pkcs7_certificate(&pkcs7).with_context(|| format!("The APK's {} isn't a PKCS#7 signature.", block.name))?;
        return Ok(vec![cert.to_vec()]);
    }
    let pairs = signing_block(zip.bytes, zip.central_directory).unwrap_or_default();
    for id in [SCHEME_V2, SCHEME_V3] {
        if let Some((_, value)) = pairs.iter().find(|(pair, _)| *pair == id) {
            return scheme_signers(value).context("The APK's signing block is damaged.");
        }
    }
    Ok(Vec::new())
}

const SCHEME_V2: u32 = 0x7109871a;
const SCHEME_V3: u32 = 0xf05368c0;

/// The ID-value pairs of the APK Signing Block, which sits just before the
/// central directory.
fn signing_block(bytes: &[u8], central_directory: usize) -> Option<Vec<(u32, &[u8])>> {
    let footer = bytes.get(central_directory.checked_sub(24)?..central_directory)?;
    if &footer[8..] != b"APK Sig Block 42" {
        return None;
    }
    let size = usize::try_from(u64::from_le_bytes(footer[..8].try_into().ok()?)).ok()?;
    let start = central_directory.checked_sub(size.checked_add(8)?)?;
    let mut pairs = bytes.get(start.checked_add(8)?..central_directory - 24)?;
    let mut found = Vec::new();
    while !pairs.is_empty() {
        let len = usize::try_from(u64::from_le_bytes(pairs.get(..8)?.try_into().ok()?)).ok()?;
        let pair = pairs.get(8..8usize.checked_add(len)?)?;
        found.push((u32::from_le_bytes(pair.get(..4)?.try_into().ok()?), &pair[4..]));
        pairs = &pairs[8 + len..];
    }
    Some(found)
}

/// The first certificate of each signer in a v2 or v3 scheme's block. Both
/// begin a signer's signed data with its digests, then its certificates.
fn scheme_signers(value: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (mut signers, _) = prefixed(value)?;
    let mut certs = Vec::new();
    while !signers.is_empty() {
        let (signer, rest) = prefixed(signers)?;
        signers = rest;
        let (signed_data, _) = prefixed(signer)?;
        let (_digests, rest) = prefixed(signed_data)?;
        let (certificates, _) = prefixed(rest)?;
        let (cert, _) = prefixed(certificates)?;
        certs.push(cert.to_vec());
    }
    Some(certs)
}

/// A value with a little-endian u32 length before it, and what follows.
fn prefixed(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(input.get(..4)?.try_into().ok()?) as usize;
    Some((input.get(4..4usize.checked_add(len)?)?, &input[4 + len..]))
}

/// The first certificate in a PKCS#7 SignedData.
pub fn pkcs7_certificate(bytes: &[u8]) -> Option<&[u8]> {
    let content_info = der::expect(bytes, der::SEQUENCE)?;
    let content_type = der::read(content_info.content)?;
    let explicit = der::expect(content_type.rest, der::CONTEXT_0)?;
    let signed_data = der::expect(explicit.content, der::SEQUENCE)?;
    let version = der::expect(signed_data.content, der::INTEGER)?;
    let digest_algorithms = der::expect(version.rest, der::SET)?;
    let content = der::expect(digest_algorithms.rest, der::SEQUENCE)?;
    let certificates = der::expect(content.rest, der::CONTEXT_0)?;
    Some(der::expect(certificates.content, der::SEQUENCE)?.whole)
}

/// A zip archive's central directory: enough to find and read its entries.
struct Zip<'a> {
    bytes: &'a [u8],
    entries: Vec<ZipEntry>,
    central_directory: usize,
}

struct ZipEntry {
    name: String,
    method: u16,
    compressed: usize,
    local_header: usize,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

impl<'a> Zip<'a> {
    fn open(bytes: &'a [u8]) -> anyhow::Result<Zip<'a>> {
        // The end of central directory record, which a comment of up to
        // 64 KiB can follow.
        let earliest = bytes.len().saturating_sub(22 + 0xffff);
        let end = (earliest..=bytes.len().saturating_sub(22))
            .rev()
            .find(|&at| {
                bytes[at..].starts_with(b"PK\x05\x06") && u16_at(bytes, at + 20).is_some_and(|len| at + 22 + len as usize == bytes.len())
            })
            .context("The file isn't an APK: it isn't a zip archive.")?;
        let damaged = || anyhow::anyhow!("The APK's zip archive is damaged.");
        let count = u16_at(bytes, end + 10).ok_or_else(damaged)?;
        let central_directory = u32_at(bytes, end + 16).ok_or_else(damaged)? as usize;
        if central_directory == 0xffff_ffff {
            bail!("The APK is a zip64 archive, which this gateway doesn't read.");
        }
        let mut entries = Vec::with_capacity(count as usize);
        let mut at = central_directory;
        for _ in 0..count {
            if bytes.get(at..at + 4) != Some(b"PK\x01\x02") {
                return Err(damaged());
            }
            let field = |offset| u16_at(bytes, at + offset).map(usize::from).ok_or_else(damaged);
            let (name_len, extra_len, comment_len) = (field(28)?, field(30)?, field(32)?);
            let name = bytes.get(at + 46..at + 46 + name_len).ok_or_else(damaged)?;
            entries.push(ZipEntry {
                name: String::from_utf8_lossy(name).into_owned(),
                method: field(10)? as u16,
                compressed: u32_at(bytes, at + 20).ok_or_else(damaged)? as usize,
                local_header: u32_at(bytes, at + 42).ok_or_else(damaged)? as usize,
            });
            at += 46 + name_len + extra_len + comment_len;
        }
        Ok(Zip { bytes, entries, central_directory })
    }

    /// The entry called `name`, decompressed, if there is one.
    fn entry(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.entries.iter().find(|entry| entry.name == name).map(|entry| self.read(entry)).transpose()
    }

    fn read(&self, entry: &ZipEntry) -> anyhow::Result<Vec<u8>> {
        let damaged = || anyhow::anyhow!("The APK's {} is damaged.", entry.name);
        let at = entry.local_header;
        if self.bytes.get(at..at + 4) != Some(b"PK\x03\x04") {
            return Err(damaged());
        }
        let name_len = u16_at(self.bytes, at + 26).ok_or_else(damaged)? as usize;
        let extra_len = u16_at(self.bytes, at + 28).ok_or_else(damaged)? as usize;
        let start = at + 30 + name_len + extra_len;
        let data = self.bytes.get(start..start + entry.compressed).ok_or_else(damaged)?;
        let mut out = Vec::new();
        match entry.method {
            0 => data.take(MAX_ENTRY + 1).read_to_end(&mut out)?,
            8 => flate2::read::DeflateDecoder::new(data).take(MAX_ENTRY + 1).read_to_end(&mut out).map_err(|_| damaged())?,
            method => bail!("The APK's {} is compressed with method {method}, which this gateway doesn't read.", entry.name),
        };
        if out.len() as u64 > MAX_ENTRY {
            bail!("The APK's {} is larger than {MAX_ENTRY} bytes.", entry.name);
        }
        Ok(out)
    }
}

// The resource IDs of the manifest attributes read, from
// android.R.attr. An attribute is known by its ID where it has one, since
// a shrinker can strip its name.
const ATTR_NAME: u32 = 0x01010003;
const ATTR_VERSION_CODE: u32 = 0x0101021b;
const ATTR_VERSION_NAME: u32 = 0x0101021c;
const ATTR_MIN_SDK: u32 = 0x0101020c;
const ATTR_TARGET_SDK: u32 = 0x01010270;
const ATTR_MAX_SDK: u32 = 0x01010271;
const ATTR_REQUIRED: u32 = 0x0101028e;
const ATTR_VERSION_CODE_MAJOR: u32 = 0x01010576;

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// An attribute of an element in Android's binary XML.
struct Attr {
    /// Its resource ID, if the resource map gives it one.
    id: Option<u32>,
    namespace: String,
    name: String,
    raw: Option<String>,
    kind: u8,
    data: u32,
}

const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_BOOLEAN: u8 = 0x12;

impl Attr {
    fn int(&self) -> Option<u32> {
        match self.kind {
            TYPE_INT_DEC | TYPE_INT_HEX => Some(self.data),
            _ => self.raw.as_deref()?.trim().parse().ok(),
        }
    }

    fn string(&self) -> Option<String> {
        match self.kind {
            TYPE_INT_DEC | TYPE_INT_HEX => Some(self.data.to_string()),
            _ => self.raw.clone(),
        }
    }

    fn bool(&self) -> Option<bool> {
        match self.kind {
            TYPE_BOOLEAN => Some(self.data != 0),
            _ => self.raw.as_deref()?.parse().ok(),
        }
    }
}

/// The attribute `id`, also called `name` in the android namespace.
fn find<'a>(attrs: &'a [Attr], id: u32, name: &str) -> Option<&'a Attr> {
    attrs.iter().find(|attr| match attr.id {
        Some(attr_id) => attr_id == id,
        None => attr.name == name && attr.namespace == ANDROID_NS,
    })
}

/// What a binary `AndroidManifest.xml` says, short of the native code and
/// signers, which come from the rest of the APK.
fn parse_manifest(xml: &[u8]) -> anyhow::Result<ApkMeta> {
    let damaged = || anyhow::anyhow!("The APK's AndroidManifest.xml is damaged.");
    if u16_at(xml, 0) != Some(0x0003) {
        bail!("The APK's AndroidManifest.xml isn't binary XML.");
    }
    let mut strings: Vec<String> = Vec::new();
    let mut ids: Vec<u32> = Vec::new();
    let mut depth = 0usize;
    let mut manifest = None;
    let mut sdk = None;
    let (mut permissions, mut permissions_sdk23, mut features) = (Vec::new(), Vec::new(), Vec::new());

    let mut at = u16_at(xml, 2).ok_or_else(damaged)? as usize;
    while at + 8 <= xml.len() {
        let kind = u16_at(xml, at).ok_or_else(damaged)?;
        let header = u16_at(xml, at + 2).ok_or_else(damaged)? as usize;
        let size = u32_at(xml, at + 4).ok_or_else(damaged)? as usize;
        let chunk = xml.get(at..at.checked_add(size).ok_or_else(damaged)?).filter(|_| size >= 8).ok_or_else(damaged)?;
        match kind {
            0x0001 => strings = string_pool(chunk).ok_or_else(damaged)?,
            0x0180 => ids = chunk.get(header..).ok_or_else(damaged)?.as_chunks::<4>().0.iter().map(|id| u32::from_le_bytes(*id)).collect(),
            0x0102 => {
                depth += 1;
                let string = |index: u32| strings.get(index as usize).cloned();
                let ext = chunk.get(header..).ok_or_else(damaged)?;
                let element = string(u32_at(ext, 4).ok_or_else(damaged)?).unwrap_or_default();
                let start = u16_at(ext, 8).ok_or_else(damaged)? as usize;
                let stride = u16_at(ext, 10).ok_or_else(damaged)? as usize;
                let count = u16_at(ext, 12).ok_or_else(damaged)? as usize;
                let mut attrs = Vec::with_capacity(count);
                for i in 0..count {
                    let attr = ext.get(start + i * stride..start + i * stride + 20).ok_or_else(damaged)?;
                    let name = u32_at(attr, 4).ok_or_else(damaged)?;
                    attrs.push(Attr {
                        id: ids.get(name as usize).copied().filter(|&id| id != 0),
                        namespace: string(u32_at(attr, 0).ok_or_else(damaged)?).unwrap_or_default(),
                        name: string(name).unwrap_or_default(),
                        raw: match attr[15] {
                            TYPE_STRING => string(u32_at(attr, 16).ok_or_else(damaged)?),
                            _ => string(u32_at(attr, 8).ok_or_else(damaged)?),
                        },
                        kind: attr[15],
                        data: u32_at(attr, 16).ok_or_else(damaged)?,
                    });
                }
                match (depth, element.as_str()) {
                    (1, "manifest") => manifest = Some(attrs),
                    (1, other) => bail!("The APK's AndroidManifest.xml has <{other}> where <manifest> should be."),
                    (2, "uses-sdk") => sdk = Some(attrs),
                    (2, "uses-permission") => permissions.extend(permission(&attrs)),
                    (2, "uses-permission-sdk-23" | "uses-permission-sdk-m") => permissions_sdk23.extend(permission(&attrs)),
                    (2, "uses-feature") => {
                        if find(&attrs, ATTR_REQUIRED, "required").and_then(Attr::bool) != Some(false)
                            && let Some(name) = find(&attrs, ATTR_NAME, "name").and_then(Attr::string)
                        {
                            features.push(name);
                        }
                    }
                    _ => {}
                }
            }
            0x0103 => depth = depth.saturating_sub(1),
            _ => {}
        }
        at += size;
    }

    let manifest = manifest.context("The APK's AndroidManifest.xml has no <manifest>.")?;
    let package = manifest
        .iter()
        .find(|attr| attr.name == "package" && attr.namespace.is_empty())
        .and_then(Attr::string)
        .context("The APK's manifest has no package name.")?;
    let version_code =
        find(&manifest, ATTR_VERSION_CODE, "versionCode").and_then(Attr::int).context("The APK's manifest has no versionCode.")?;
    let major = find(&manifest, ATTR_VERSION_CODE_MAJOR, "versionCodeMajor").and_then(Attr::int).unwrap_or(0);
    let version_code = u64::from(major) << 32 | u64::from(version_code);
    // A versionName can be a reference to a string resource, which isn't
    // read: the versionCode stands in for it.
    let version_name = find(&manifest, ATTR_VERSION_NAME, "versionName")
        .filter(|attr| attr.kind == TYPE_STRING || attr.kind == TYPE_INT_DEC)
        .and_then(Attr::string)
        .unwrap_or_else(|| version_code.to_string());
    let sdk = sdk.unwrap_or_default();
    let sdk_version = |id, name| -> anyhow::Result<Option<u32>> {
        match find(&sdk, id, name) {
            None => Ok(None),
            Some(attr) => match attr.int() {
                Some(version) => Ok(Some(version)),
                None => bail!("The APK's {name} is {:?}, a preview's, which F-Droid can't list.", attr.raw.as_deref().unwrap_or_default()),
            },
        }
    };
    let min_sdk = sdk_version(ATTR_MIN_SDK, "minSdkVersion")?.unwrap_or(1);
    Ok(ApkMeta {
        package,
        version_code,
        version_name,
        min_sdk,
        target_sdk: sdk_version(ATTR_TARGET_SDK, "targetSdkVersion")?.unwrap_or(min_sdk),
        max_sdk: sdk_version(ATTR_MAX_SDK, "maxSdkVersion")?,
        permissions,
        permissions_sdk23,
        features,
        nativecode: Vec::new(),
        signers: Vec::new(),
    })
}

fn permission(attrs: &[Attr]) -> Option<Permission> {
    Some(Permission {
        name: find(attrs, ATTR_NAME, "name").and_then(Attr::string)?,
        max_sdk: find(attrs, ATTR_MAX_SDK, "maxSdkVersion").and_then(Attr::int),
    })
}

/// The strings of a string pool chunk, UTF-8 or UTF-16.
fn string_pool(chunk: &[u8]) -> Option<Vec<String>> {
    let header = u16_at(chunk, 2)? as usize;
    let count = u32_at(chunk, 8)? as usize;
    let utf8 = u32_at(chunk, 16)? & 0x100 != 0;
    let start = u32_at(chunk, 20)? as usize;
    let mut strings = Vec::with_capacity(count.min(chunk.len() / 4));
    for i in 0..count {
        let at = start.checked_add(u32_at(chunk, header.checked_add(i.checked_mul(4)?)?)? as usize)?;
        if utf8 {
            // The length in UTF-16 units, then in bytes: each one byte, or
            // two with the top bit set.
            let len8 = |at: usize| -> Option<(usize, usize)> {
                let first = *chunk.get(at)? as usize;
                if first & 0x80 == 0 { Some((first, 1)) } else { Some(((first & 0x7f) << 8 | *chunk.get(at + 1)? as usize, 2)) }
            };
            let (_, skip) = len8(at)?;
            let (len, skip2) = len8(at + skip)?;
            let begin = at + skip + skip2;
            strings.push(String::from_utf8_lossy(chunk.get(begin..begin.checked_add(len)?)?).into_owned());
        } else {
            let first = u16_at(chunk, at)? as usize;
            let (len, skip) = if first & 0x8000 == 0 { (first, 2) } else { ((first & 0x7fff) << 16 | u16_at(chunk, at + 2)? as usize, 4) };
            let begin = at + skip;
            let units: Vec<u16> = chunk
                .get(begin..begin.checked_add(len.checked_mul(2)?)?)?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_le_bytes(*unit))
                .collect();
            strings.push(String::from_utf16_lossy(&units));
        }
    }
    Some(strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &[u8] = include_bytes!("../../tests/fixtures/hello.apk");

    #[test]
    fn reads_what_aapt2_and_apksigner_do() {
        let meta = inspect(HELLO).unwrap();
        assert_eq!(meta.package, "org.example.hello");
        assert_eq!((meta.version_code, meta.version_name.as_str()), (10203, "1.2.3-rc.1"));
        assert_eq!((meta.min_sdk, meta.target_sdk, meta.max_sdk), (24, 34, None));
        let permission = |name: &str, max_sdk| Permission { name: name.into(), max_sdk };
        assert_eq!(meta.permissions, [permission("android.permission.INTERNET", None), permission("android.permission.CAMERA", Some(28))]);
        assert_eq!(meta.permissions_sdk23, [permission("android.permission.ACCESS_FINE_LOCATION", None)]);
        // The camera isn't required, and OpenGL ES has no name.
        assert_eq!(meta.features, ["android.hardware.bluetooth"]);
        assert_eq!(meta.nativecode, ["arm64-v8a", "x86_64"]);
        assert_eq!(meta.arch(), "arm64-v8a,x86_64");
        assert_eq!(meta.signers, [SIGNER]);
    }

    /// `apksigner verify --print-certs`'s certificate SHA-256 for the fixture.
    const SIGNER: &str = "6009f605151b88399b7cc2e406f1c5d862ba6cb8091bccc439ba45a68aadfb04";

    #[test]
    fn reads_the_same_signer_from_every_scheme() {
        let zip = Zip::open(HELLO).unwrap();
        let pairs = signing_block(HELLO, zip.central_directory).unwrap();
        for id in [SCHEME_V2, SCHEME_V3] {
            let (_, value) = pairs.iter().find(|(pair, _)| *pair == id).unwrap();
            assert_eq!(scheme_signers(value).unwrap().iter().map(|cert| hex::encode(Sha256::digest(cert))).collect::<Vec<_>>(), [SIGNER]);
        }
        let pkcs7 = zip.entry("META-INF/HELLO.RSA").unwrap().unwrap();
        assert_eq!(hex::encode(Sha256::digest(pkcs7_certificate(&pkcs7).unwrap())), SIGNER);
    }

    #[test]
    fn refuses_what_isnt_an_apk() {
        assert!(inspect(b"not an apk").is_err());
        assert!(inspect(include_bytes!("../../tests/fixtures/hello_1.2.0-rc.1_amd64.deb")).is_err());
        // Cut short, or damaged anywhere, it's an error, not a panic.
        for len in (0..HELLO.len()).step_by(97) {
            let _ = inspect(&HELLO[..len]);
        }
        for at in (0..HELLO.len()).step_by(31) {
            let mut damaged = HELLO.to_vec();
            damaged[at] ^= 0xff;
            let _ = inspect(&damaged);
        }
    }
}
