//! An F-Droid repository (index v2): `entry.jar`, `entry.json` and
//! `index-v2.json`, for one application's APKs.
//!
//! F-Droid knows a repository by the certificate that signs its `entry.jar`,
//! so each application gets a key of its own, and adding one doesn't trust
//! the rest of the team's. The keys are P-256, derived from the gateway's
//! OpenPGP key, so they needn't be stored or backed up: the same application
//! always gets the same key, and its fingerprint never changes. ECDSA's
//! signatures are deterministic (RFC 6979), so the same index always makes
//! the same `entry.jar`.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use base64::Engine;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::der;
use crate::inspect::Meta;
use crate::nip82::{self, Application};
use crate::nostr::nip19;
use crate::repo::{Package, Release};
use crate::signing::Signer;

/// The index format version F-Droid's own repositories publish.
const INDEX_VERSION: u64 = 20002;

/// F-Droid's channel for anything less stable than a release: users opt in
/// app by app. NIP-82's beta, nightly and dev channels all go in it.
const BETA: &str = "Beta";

const LOCALE: &str = "en-US";

/// Whether `name` is a package name Android accepts: two or more dotted
/// parts, each a letter and then letters, digits or underscores.
pub fn valid_package(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            part.bytes().next().is_some_and(|b| b.is_ascii_alphabetic()) && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// One application's repository key, and its certificate.
pub struct Key {
    signing: SigningKey,
    pub certificate: Vec<u8>,
}

impl Key {
    /// The key for `pubkey`'s application `d`.
    pub fn derive(signer: &Signer, pubkey: &str, d: &str) -> Key {
        // `d` holds no control characters, so the label is unambiguous.
        let label = format!("F-Droid repository\0{pubkey}\0{d}");
        let mut seed = signer.derive(label.as_bytes());
        // Nearly every 32 bytes is a P-256 scalar; for the rest, hash again.
        let signing = loop {
            match SigningKey::from_slice(&seed) {
                Ok(key) => break key,
                Err(_) => seed = Sha256::digest(seed).into(),
            }
        };
        let certificate = certificate(&signing, pubkey, d);
        Key { signing, certificate }
    }

    /// What F-Droid calls the repository's fingerprint: the SHA-256 of its
    /// certificate.
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(&self.certificate))
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(data);
        signature.to_der().as_bytes().to_vec()
    }
}

const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const PKCS7_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const PKCS7_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];

/// The certificate's subject and issuer: who the key is for.
fn name(pubkey: &str, d: &str) -> Vec<u8> {
    let rdn = |oid: &[u64], value: &str| der::constructed(der::SET, &[&der::sequence(&[&der::oid(oid), &der::utf8_string(value)])]);
    der::sequence(&[
        &rdn(&[2, 5, 4, 3], "npkg"),
        &rdn(&[2, 5, 4, 10], &nip82::one_line(d)),
        &rdn(&[2, 5, 4, 11], &nip19::npub_encode(pubkey)),
    ])
}

fn serial(pubkey: &str, d: &str) -> Vec<u8> {
    let hash = Sha256::digest(format!("{pubkey}\0{d}"));
    der::unsigned(&[&[0x7f & hash[0]][..], &hash[1..16]].concat())
}

/// A self-signed X.509 certificate for `key`, which never expires and is
/// the same every time.
fn certificate(key: &SigningKey, pubkey: &str, d: &str) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let spki = der::sequence(&[&der::sequence(&[&der::oid(EC_PUBLIC_KEY), &der::oid(PRIME256V1)]), &der::bit_string(point.as_bytes())]);
    let algorithm = der::sequence(&[&der::oid(ECDSA_WITH_SHA256)]);
    let name = name(pubkey, d);
    let tbs = der::sequence(&[
        &der::tlv(der::CONTEXT_0, &der::unsigned(&[2])),
        &serial(pubkey, d),
        &algorithm,
        &name,
        &der::sequence(&[&der::time(0), &der::time(253_402_300_799)]),
        &name,
        &spki,
    ]);
    let signature: Signature = key.sign(&tbs);
    der::sequence(&[&tbs, &algorithm, &der::bit_string(signature.to_der().as_bytes())])
}

/// A detached PKCS#7 signature over `data`, as apksigner makes one for an
/// EC key: no signed attributes, and the signature algorithm given as
/// `ecPublicKey`, which Android reads back to API 18.
fn pkcs7(key: &Key, pubkey: &str, d: &str, data: &[u8]) -> Vec<u8> {
    let digest = der::sequence(&[&der::oid(SHA256), &der::null()]);
    let signer_info = der::sequence(&[
        &der::unsigned(&[1]),
        &der::sequence(&[&name(pubkey, d), &serial(pubkey, d)]),
        &digest,
        &der::sequence(&[&der::oid(EC_PUBLIC_KEY), &der::null()]),
        &der::tlv(der::OCTET_STRING, &key.sign(data)),
    ]);
    let signed_data = der::sequence(&[
        &der::unsigned(&[1]),
        &der::constructed(der::SET, &[&digest]),
        &der::sequence(&[&der::oid(PKCS7_DATA)]),
        &der::tlv(der::CONTEXT_0, &key.certificate),
        &der::constructed(der::SET, &[&signer_info]),
    ]);
    der::sequence(&[&der::oid(PKCS7_SIGNED_DATA), &der::tlv(der::CONTEXT_0, &signed_data)])
}

fn base64_sha256(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data))
}

/// A JAR holding `name`, with `content`, signed by `key` as jarsigner
/// would: SHA-256 digests only, since F-Droid refuses MD5 and SHA-1.
fn jar(key: &Key, pubkey: &str, d: &str, name: &str, content: &[u8]) -> Vec<u8> {
    let section = format!("Name: {name}\r\nSHA-256-Digest: {}\r\n\r\n", base64_sha256(content));
    let manifest = format!("Manifest-Version: 1.0\r\nCreated-By: npkg\r\n\r\n{section}");
    let sf = format!(
        "Signature-Version: 1.0\r\nCreated-By: npkg\r\nSHA-256-Digest-Manifest: {}\r\n\r\nName: {name}\r\nSHA-256-Digest: {}\r\n\r\n",
        base64_sha256(manifest.as_bytes()),
        base64_sha256(section.as_bytes())
    );
    let block = pkcs7(key, pubkey, d, sf.as_bytes());
    zip(&[
        ("META-INF/MANIFEST.MF", manifest.as_bytes()),
        ("META-INF/NPKG.SF", sf.as_bytes()),
        ("META-INF/NPKG.EC", &block),
        (name, content),
    ])
}

/// A zip archive of `entries`, stored, dated 1980-01-01 so that the same
/// entries make the same archive.
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, data) in entries {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let (crc, size, offset) = (crc.sum(), data.len() as u32, out.len() as u32);
        // Version needed, flags, method, time, date, CRC, both sizes, and
        // the name's length: the same in both headers.
        let mut common = Vec::new();
        for value in [10u16, 0, 0, 0, 0x21] {
            common.extend(value.to_le_bytes());
        }
        for value in [crc, size, size] {
            common.extend(value.to_le_bytes());
        }
        common.extend((name.len() as u16).to_le_bytes());

        out.extend(b"PK\x03\x04");
        out.extend(&common);
        out.extend(0u16.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(*data);

        central.extend(b"PK\x01\x02");
        central.extend(20u16.to_le_bytes());
        central.extend(&common);
        // Extra and comment lengths, disk, attributes, and where it starts.
        central.extend([0; 12]);
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let (start, len, count) = (out.len() as u32, central.len() as u32, entries.len() as u16);
    out.extend(central);
    out.extend(b"PK\x05\x06\0\0\0\0");
    out.extend(count.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend(len.to_le_bytes());
    out.extend(start.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

/// What the index says about the repository and its application, besides
/// its packages.
pub struct About<'a> {
    pub address: &'a str,
    pub d: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub application: Option<&'a Application>,
    pub icon: Option<&'a File>,
}

/// A file F-Droid fetches from the repository, by its path below it.
pub struct File {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

fn localized(text: &str) -> Value {
    json!({ LOCALE: text })
}

/// `index-v2.json`, dated `timestamp` (in milliseconds, as F-Droid has it).
/// Each APK is listed by its hash, under the package it says it is.
pub fn index(about: &About, packages: &[&Package], releases: &[Release], timestamp: i64) -> Vec<u8> {
    let mut by_name: BTreeMap<&str, Vec<(&Package, &crate::inspect::ApkMeta)>> = BTreeMap::new();
    for package in packages {
        if let Meta::Apk(apk) = &package.meta {
            by_name.entry(&apk.package).or_default().push((package, apk));
        }
    }
    let only = by_name.len() == 1;
    let mut index_packages = serde_json::Map::new();
    for (name, apks) in &by_name {
        let mut versions = serde_json::Map::new();
        for (package, apk) in apks {
            let release = releases.iter().find(|release| release.version == package.release && release.created_at == package.created_at);
            let beta = package.channel > 0 || nip82::is_prerelease(&package.release);
            let permissions = |permissions: &[crate::inspect::apk::Permission]| -> Vec<Value> {
                permissions
                    .iter()
                    .map(|permission| match permission.max_sdk {
                        Some(max_sdk) => json!({"name": permission.name, "maxSdkVersion": max_sdk}),
                        None => json!({"name": permission.name}),
                    })
                    .collect()
            };
            let mut manifest = json!({
                "versionName": apk.version_name,
                "versionCode": apk.version_code,
                "usesSdk": {"minSdkVersion": apk.min_sdk, "targetSdkVersion": apk.target_sdk},
                "signer": {"sha256": apk.signers},
                "usesPermission": permissions(&apk.permissions),
                "usesPermissionSdk23": permissions(&apk.permissions_sdk23),
                "nativecode": apk.nativecode,
                "features": apk.features.iter().map(|feature| json!({"name": feature})).collect::<Vec<_>>(),
            });
            if let Some(max_sdk) = apk.max_sdk {
                manifest["maxSdkVersion"] = json!(max_sdk);
            }
            let mut version = json!({
                "added": package.created_at.max(0) * 1000,
                "file": {"name": format!("/{}/{}", package.sha256, file_name(apk)), "sha256": package.sha256, "size": package.size},
                "manifest": manifest,
            });
            if beta {
                version["releaseChannels"] = json!([BETA]);
            }
            if let Some(notes) = release.map(|release| release.notes.trim()).filter(|notes| !notes.is_empty()) {
                version["whatsNew"] = localized(notes);
            }
            versions.insert(package.sha256.clone(), version);
        }
        let added = apks.iter().map(|(package, _)| package.created_at).min().unwrap_or(0).max(0) * 1000;
        let updated = apks.iter().map(|(package, _)| package.created_at).max().unwrap_or(0).max(0) * 1000;
        let mut metadata = json!({"added": added, "lastUpdated": updated, "name": localized(name)});
        // The application's own description is its main package's: the one
        // named like it, or the only one.
        if let Some(app) = about.application.filter(|_| only || *name == about.d) {
            metadata["name"] = localized(app.name.as_deref().unwrap_or(name));
            if let Some(summary) = &app.summary {
                metadata["summary"] = localized(summary);
            }
            if !app.description.trim().is_empty() {
                metadata["description"] = localized(app.description.trim());
            }
            let https = |url: &Option<String>| url.as_deref().filter(|url| url.starts_with("https://")).map(str::to_string);
            if let Some(website) = https(&app.website) {
                metadata["webSite"] = json!(website);
            }
            if let Some(source) = https(&app.repository) {
                metadata["sourceCode"] = json!(source);
            }
            if let Some(license) = &app.license {
                metadata["license"] = json!(license);
            }
            if let Some(icon) = about.icon {
                metadata["icon"] = json!({ LOCALE: {"name": icon.name, "sha256": icon.sha256, "size": icon.size} });
            }
        }
        index_packages.insert(name.to_string(), json!({"metadata": metadata, "versions": versions}));
    }
    let index = json!({
        "repo": {
            "name": localized(about.name),
            "description": localized(about.description),
            "address": about.address,
            "timestamp": timestamp,
        },
        "packages": index_packages,
    });
    serde_json::to_vec(&index).unwrap_or_default()
}

/// What an APK is called in its download URL: only the hash before it is
/// read back.
fn file_name(apk: &crate::inspect::ApkMeta) -> String {
    format!("{}_{}.apk", apk.package, apk.version_code)
}

/// The repository's files: `index-v2.json`, and the `entry.json` that
/// names it by hash, alone and signed in `entry.jar`.
pub fn render(key: &Key, pubkey: &str, d: &str, index: Vec<u8>, packages: usize, timestamp: i64) -> HashMap<String, Vec<u8>> {
    let entry = json!({
        "timestamp": timestamp,
        "version": INDEX_VERSION,
        "index": {
            "name": "/index-v2.json",
            "sha256": hex::encode(Sha256::digest(&index)),
            "size": index.len(),
            "numPackages": packages,
        },
    });
    let entry = serde_json::to_vec(&entry).unwrap_or_default();
    let mut files = HashMap::new();
    files.insert("entry.jar".to_string(), jar(key, pubkey, d, "entry.json", &entry));
    files.insert("entry.json".to_string(), entry);
    files.insert("index-v2.json".to_string(), index);
    files
}

/// The address to add the repository by: with the fingerprint, so F-Droid
/// checks the key the first time too.
pub fn setup_url(address: &str, fingerprint: &str) -> String {
    let mut url = address.to_string();
    let _ = write!(url, "?fingerprint={fingerprint}");
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(dir: &std::path::Path) -> Signer {
        Signer::generate(&dir.join("key.asc"), "test").unwrap()
    }

    #[test]
    fn checks_package_names() {
        assert!(valid_package("buzz.armada.app"));
        assert!(valid_package("org.example.hello_2"));
        assert!(!valid_package("hello"));
        assert!(!valid_package("org.2example"));
        assert!(!valid_package("org..example"));
        assert!(!valid_package("org.exa-mple"));
    }

    #[test]
    fn derives_one_key_per_application() {
        let dir = tempfile::tempdir().unwrap();
        let signer = signer(dir.path());
        let pubkey = "a".repeat(64);
        let key = Key::derive(&signer, &pubkey, "buzz.armada.app");
        assert_eq!(
            key.certificate,
            Key::derive(&Signer::load(&dir.path().join("key.asc")).unwrap(), &pubkey, "buzz.armada.app").certificate
        );
        assert_ne!(key.fingerprint(), Key::derive(&signer, &pubkey, "other").fingerprint());
        assert_ne!(key.fingerprint(), Key::derive(&signer, &"b".repeat(64), "buzz.armada.app").fingerprint());
        // F-Droid refuses a certificate shorter than this.
        assert!(key.certificate.len() >= 256, "{}", key.certificate.len());
        // And the same index is signed the same way every time.
        let files = render(&key, &pubkey, "buzz.armada.app", b"{}".to_vec(), 0, 1);
        assert_eq!(files["entry.jar"], render(&key, &pubkey, "buzz.armada.app", b"{}".to_vec(), 0, 1)["entry.jar"]);
    }

    /// Whether openssl and the JDK, if they're installed, accept the
    /// certificate and the JAR. F-Droid itself reads the JAR with Java's
    /// JarFile.
    #[test]
    fn signs_what_openssl_and_jarsigner_verify() {
        let dir = tempfile::tempdir().unwrap();
        let signer = signer(dir.path());
        let pubkey = "a".repeat(64);
        let key = Key::derive(&signer, &pubkey, "hello");
        let files = render(&key, &pubkey, "hello", b"{\"repo\":{}}".to_vec(), 0, 1);
        std::fs::write(dir.path().join("cert.der"), &key.certificate).unwrap();
        std::fs::write(dir.path().join("entry.jar"), &files["entry.jar"]).unwrap();
        let run = |program: &str, args: &[&str]| {
            std::process::Command::new(program).args(args).current_dir(dir.path()).output().ok().map(|output| {
                (output.status.success(), String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr))
            })
        };
        if let Some((ok, output)) = run("openssl", &["x509", "-inform", "DER", "-in", "cert.der", "-noout", "-text"]) {
            assert!(ok && output.contains("prime256v1") && output.contains("CN = npkg"), "{output}");
            assert!(run("openssl", &["x509", "-inform", "DER", "-in", "cert.der", "-out", "cert.pem"]).unwrap().0);
            let (ok, output) = run("openssl", &["verify", "-check_ss_sig", "-CAfile", "cert.pem", "cert.pem"]).unwrap();
            assert!(ok, "{output}");
        }
        if let Some((ok, output)) = run("jarsigner", &["-verify", "entry.jar"]) {
            assert!(ok && output.contains("jar verified"), "{output}");
        }
    }
}
