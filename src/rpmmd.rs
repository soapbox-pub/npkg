//! rpm-md repodata, as createrepo_c writes it, for one channel.
//!
//! One repository holds every architecture: dnf picks the packages its
//! system can install by their `arch`.

use std::collections::HashMap;
use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::apt::gzip;
use crate::inspect::Meta;
use crate::inspect::rpm::{Dependency, RpmMeta, split_evr};
use crate::repo::Package;
use crate::signing::Signer;

/// The files of one channel's repository, by path below it.
pub fn render(packages: &[&Package], signer: &Signer) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let rpms: Vec<(&Package, &RpmMeta)> = packages
        .iter()
        .filter_map(|package| match &package.meta {
            Meta::Rpm(meta) => Some((*package, &**meta)),
            Meta::Deb(_) => None,
        })
        .collect();
    let count = rpms.len();

    let mut primary = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{count}\">\n"
    );
    let mut filelists = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"{count}\">\n"
    );
    let mut other = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"{count}\">\n"
    );

    for (package, meta) in &rpms {
        let version = format!("<version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>", meta.epoch, escape(&meta.version), escape(&meta.release));
        let ids = format!("pkgid=\"{}\" name=\"{}\" arch=\"{}\"", package.sha256, escape(&meta.name), escape(&meta.arch));

        writeln!(primary, "<package type=\"rpm\">")?;
        writeln!(primary, "  <name>{}</name>\n  <arch>{}</arch>\n  {version}", escape(&meta.name), escape(&meta.arch))?;
        writeln!(primary, "  <checksum type=\"sha256\" pkgid=\"YES\">{}</checksum>", package.sha256)?;
        writeln!(primary, "  <summary>{}</summary>", escape(&meta.summary))?;
        writeln!(primary, "  <description>{}</description>", escape(&meta.description))?;
        writeln!(primary, "  <packager>{}</packager>\n  <url>{}</url>", escape(&meta.packager), escape(&meta.url))?;
        writeln!(primary, "  <time file=\"{}\" build=\"{}\"/>", package.created_at.max(0), meta.build_time)?;
        writeln!(
            primary,
            "  <size package=\"{}\" installed=\"{}\" archive=\"{}\"/>",
            package.size, meta.installed_size, meta.archive_size
        )?;
        writeln!(primary, "  <location href=\"{}\"/>", escape(&location(package, meta)))?;
        writeln!(primary, "  <format>")?;
        for (name, value) in [
            ("license", &meta.license),
            ("vendor", &meta.vendor),
            ("group", &meta.group),
            ("buildhost", &meta.buildhost),
            ("sourcerpm", &meta.sourcerpm),
        ] {
            writeln!(primary, "    <rpm:{name}>{}</rpm:{name}>", escape(value))?;
        }
        writeln!(primary, "    <rpm:header-range start=\"{}\" end=\"{}\"/>", meta.header_start, meta.header_end)?;
        let requires: Vec<Dependency> = meta.requires.iter().filter(|dep| !dep.rpmlib()).cloned().collect();
        for (name, deps) in [
            ("provides", &meta.provides),
            ("requires", &requires),
            ("conflicts", &meta.conflicts),
            ("obsoletes", &meta.obsoletes),
            ("recommends", &meta.recommends),
            ("suggests", &meta.suggests),
            ("supplements", &meta.supplements),
            ("enhances", &meta.enhances),
        ] {
            write_dependencies(&mut primary, name, deps)?;
        }
        // Primary lists the files dependencies are commonly on, as createrepo
        // does; filelists has them all.
        for file in meta.files.iter().filter(|file| primary_file(&file.path)) {
            writeln!(primary, "    <file{}>{}</file>", file_type(file), escape(&file.path))?;
        }
        writeln!(primary, "  </format>\n</package>")?;

        writeln!(filelists, "<package {ids}>\n  {version}")?;
        for file in &meta.files {
            writeln!(filelists, "  <file{}>{}</file>", file_type(file), escape(&file.path))?;
        }
        writeln!(filelists, "</package>")?;

        writeln!(other, "<package {ids}>\n  {version}\n</package>")?;
    }
    primary.push_str("</metadata>\n");
    filelists.push_str("</filelists>\n");
    other.push_str("</otherdata>\n");

    // Stamped with the newest release in it, not the build, so that a
    // rebuild of the same packages is the same repomd.xml.
    let revision = packages.iter().map(|package| package.created_at).max().unwrap_or(0).max(0);
    let mut files = HashMap::new();
    let mut repomd = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n  <revision>{revision}</revision>\n"
    );
    for (kind, xml) in [("primary", primary), ("filelists", filelists), ("other", other)] {
        let gz = gzip(xml.as_bytes());
        let gz_sha = hex::encode(Sha256::digest(&gz));
        let path = format!("repodata/{gz_sha}-{kind}.xml.gz");
        write!(
            repomd,
            "  <data type=\"{kind}\">\n    <checksum type=\"sha256\">{gz_sha}</checksum>\n    <open-checksum type=\"sha256\">{}</open-checksum>\n    <location href=\"{path}\"/>\n    <timestamp>{revision}</timestamp>\n    <size>{}</size>\n    <open-size>{}</open-size>\n  </data>\n",
            hex::encode(Sha256::digest(&xml)),
            gz.len(),
            xml.len()
        )?;
        files.insert(path, gz);
    }
    repomd.push_str("</repomd>\n");

    files.insert("repodata/repomd.xml.asc".into(), signer.sign_detached(repomd.as_bytes())?.into_bytes());
    files.insert("repodata/repomd.xml".into(), repomd.into_bytes());
    Ok(files)
}

/// Where dnf is told to download a package. Only the hash is read back.
fn location(package: &Package, meta: &RpmMeta) -> String {
    let name = format!("{}-{}-{}.{}.rpm", meta.name, meta.version, meta.release, meta.arch)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._+~-".contains(c) { c } else { '_' })
        .collect::<String>();
    format!("packages/{}/{name}", package.sha256)
}

fn write_dependencies(out: &mut String, name: &str, deps: &[Dependency]) -> std::fmt::Result {
    if deps.is_empty() {
        return Ok(());
    }
    writeln!(out, "    <rpm:{name}>")?;
    for dep in deps {
        write!(out, "      <rpm:entry name=\"{}\"", escape(&dep.name))?;
        if let Some(comparison) = dep.comparison().filter(|_| !dep.evr.is_empty()) {
            let (epoch, version, release) = split_evr(&dep.evr);
            write!(out, " flags=\"{comparison}\" epoch=\"{}\" ver=\"{}\"", escape(epoch.unwrap_or("0")), escape(version))?;
            if let Some(release) = release {
                write!(out, " rel=\"{}\"", escape(release))?;
            }
        }
        if name == "requires" && dep.pre() {
            write!(out, " pre=\"1\"")?;
        }
        writeln!(out, "/>")?;
    }
    writeln!(out, "    </rpm:{name}>")
}

fn primary_file(path: &str) -> bool {
    path.starts_with("/etc/") || path.contains("bin/") || path == "/usr/lib/sendmail"
}

fn file_type(file: &crate::inspect::rpm::File) -> &'static str {
    if file.dir {
        " type=\"dir\""
    } else if file.ghost {
        " type=\"ghost\""
    } else {
        ""
    }
}

/// Text for XML, with what XML 1.0 can't hold at all dropped.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_xml() {
        assert_eq!(escape("a<b & \"c\"\u{1}"), "a&lt;b &amp; &quot;c&quot;");
    }
}
