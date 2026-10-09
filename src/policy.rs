//! Which of an application's package files a repository serves.
//!
//! A NIP-82 application is one package: its repository serves the package
//! named after its `d` tag and nothing else, so adding it can't put anything
//! else on a system, under any name. Within that, the rules keep the package
//! from reaching other packages through its metadata, and keep each version
//! down to one file per architecture.

use std::collections::BTreeMap;

use crate::arch;
use crate::inspect::{Format, Meta};
use crate::version;

/// A package file one of the application's releases lists, inspected.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub release_version: String,
    pub asset_version: Option<String>,
    pub platforms: Vec<String>,
    pub sha256: String,
    pub meta: Meta,
}

/// Why a file was left out, for the log and the repository's status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub version: String,
    pub sha256: String,
    pub reason: String,
}

/// Of `candidates`, the files to serve, each with its architecture as its
/// format names it; and why the rest aren't.
pub fn choose(d: &str, candidates: Vec<Candidate>) -> (Vec<(Candidate, String)>, Vec<Rejection>) {
    let mut rejections = Vec::new();
    let mut groups: BTreeMap<(Format, String), Vec<(Candidate, String)>> = BTreeMap::new();
    for candidate in candidates {
        match check(d, &candidate) {
            Ok(arch) => groups.entry((candidate.meta.format(), candidate.release_version.clone())).or_default().push((candidate, arch)),
            Err(reason) => rejections.push(Rejection { version: candidate.release_version, sha256: candidate.sha256, reason }),
        }
    }

    let mut chosen = Vec::new();
    for ((format, _), files) in groups {
        let independent = independent_arch(format);
        let has_independent = files.iter().any(|(_, arch)| arch == independent);
        for (candidate, arch) in &files {
            let reason = if has_independent && files.len() > 1 {
                Some(format!(
                    "The release has an architecture-independent {} beside others. Publish either one {independent} file or one file per architecture.",
                    format.as_str()
                ))
            } else if files.iter().filter(|(_, other)| other == arch).count() > 1 {
                Some(format!("The release has more than one {} for {arch}, so none of them is served.", format.as_str()))
            } else {
                None
            };
            match reason {
                Some(reason) => {
                    rejections.push(Rejection { version: candidate.release_version.clone(), sha256: candidate.sha256.clone(), reason })
                }
                None => chosen.push((candidate.clone(), arch.clone())),
            }
        }
    }
    (chosen, rejections)
}

pub fn independent_arch(format: Format) -> &'static str {
    match format {
        Format::Deb => "all",
        Format::Rpm => "noarch",
    }
}

/// The file's architecture, if it's one this repository may serve.
fn check(d: &str, candidate: &Candidate) -> Result<String, String> {
    if candidate.asset_version.as_deref().is_some_and(|version| version != candidate.release_version) {
        return Err("The asset's version isn't its release's.".into());
    }
    let (name, file_version, file_arch) = match &candidate.meta {
        Meta::Deb(meta) => (meta.package(), version::deb_upstream(meta.version()).to_string(), meta.architecture()),
        Meta::Rpm(meta) => (meta.name.as_str(), meta.version.clone(), meta.arch.as_str()),
    };
    let format = candidate.meta.format();

    if name != d {
        return Err(format!(
            "The package is named {name:?}, but the application is {d:?}. A repository only serves the package named after its application."
        ));
    }

    let expected = match format {
        Format::Deb => version::deb(&candidate.release_version),
        Format::Rpm => version::rpm(&candidate.release_version),
    };
    if file_version != expected {
        return Err(format!(
            "The package's version is {file_version:?}, but its release is {:?}, which a package spells {expected:?}.",
            candidate.release_version
        ));
    }

    if file_arch != independent_arch(format) {
        let platforms: Vec<&str> = candidate
            .platforms
            .iter()
            .filter_map(|platform| match format {
                Format::Deb => arch::deb(platform),
                Format::Rpm => arch::rpm(platform),
            })
            .collect();
        if platforms != [file_arch] {
            return Err(format!(
                "The package is for {file_arch}, but its asset's platforms ({}) don't say so, alone.",
                candidate.platforms.join(", ")
            ));
        }
    }

    match &candidate.meta {
        Meta::Deb(meta) => {
            if meta.get("Replaces").is_some_and(|value| !value.is_empty()) {
                return Err("The package declares Replaces, which would let it take over other packages' files.".into());
            }
            for provided in meta.get("Provides").unwrap_or_default().split([',', '|']) {
                let provided = provided.split('(').next().unwrap_or_default().trim();
                let provided = provided.split(':').next().unwrap_or_default();
                if !provided.is_empty() && provided != d {
                    return Err(format!("The package provides {provided:?}, which would stand in for another package."));
                }
            }
        }
        Meta::Rpm(meta) => {
            if !meta.obsoletes.is_empty() {
                return Err("The package declares Obsoletes, which would let it replace other packages on upgrade.".into());
            }
            for provided in &meta.provides {
                // rpm adds `name(arch)` and `config(name)` itself.
                let own = provided.name == d
                    || provided.name == format!("config({d})")
                    || provided.name.strip_prefix(d).is_some_and(|rest| rest.starts_with('(') && rest.ends_with(')'));
                if !own {
                    return Err(format!("The package provides {:?}, which would stand in for another package.", provided.name));
                }
            }
        }
    }

    Ok(file_arch.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::deb::parse_control;

    fn deb(control: &str, version: &str, platforms: &[&str], sha: char) -> Candidate {
        Candidate {
            release_version: version.into(),
            asset_version: Some(version.into()),
            platforms: platforms.iter().map(|p| p.to_string()).collect(),
            sha256: sha.to_string().repeat(64),
            meta: Meta::Deb(parse_control(control).unwrap()),
        }
    }

    fn reasons(d: &str, candidates: Vec<Candidate>) -> (usize, Vec<String>) {
        let (chosen, rejected) = choose(d, candidates);
        (chosen.len(), rejected.into_iter().map(|r| r.reason).collect())
    }

    const AMD64: &str = "Package: npanel\nVersion: 0.6.0\nArchitecture: amd64\n";
    const ARM64: &str = "Package: npanel\nVersion: 0.6.0-1\nArchitecture: arm64\n";

    #[test]
    fn accepts_one_file_per_architecture() {
        let (chosen, rejected) =
            choose("npanel", vec![deb(AMD64, "0.6.0", &["linux-x86_64"], 'a'), deb(ARM64, "v0.6.0", &["linux-aarch64"], 'b')]);
        assert!(rejected.is_empty(), "{rejected:?}");
        let arches: Vec<_> = chosen.iter().map(|(_, arch)| arch.as_str()).collect();
        assert_eq!(arches, ["amd64", "arm64"]);
    }

    #[test]
    fn rejects_other_names() {
        let (n, why) =
            reasons("armada-stack", vec![deb("Package: armada\nVersion: 1\nArchitecture: amd64\n", "1", &["linux-x86_64"], 'a')]);
        assert_eq!(n, 0);
        assert!(why[0].contains("named \"armada\""));
    }

    #[test]
    fn rejects_wrong_versions_and_arches() {
        let (n, why) = reasons("npanel", vec![deb(AMD64, "0.6.1", &["linux-x86_64"], 'a')]);
        assert_eq!(n, 0);
        assert!(why[0].contains("version"));
        let (n, _) = reasons("npanel", vec![deb(AMD64, "0.6.0", &["linux-aarch64"], 'a')]);
        assert_eq!(n, 0);
        let (n, _) = reasons("npanel", vec![deb(AMD64, "0.6.0", &[], 'a')]);
        assert_eq!(n, 0);
        let pre = "Package: npanel\nVersion: 0.7.0~rc.1\nArchitecture: all\n";
        assert_eq!(reasons("npanel", vec![deb(pre, "0.7.0-rc.1", &[], 'a')]).0, 1);
    }

    #[test]
    fn rejects_reaching_other_packages() {
        let replaces = format!("{AMD64}Replaces: openssl\n");
        assert_eq!(reasons("npanel", vec![deb(&replaces, "0.6.0", &["linux-x86_64"], 'a')]).0, 0);
        let provides = format!("{AMD64}Provides: npanel (= 0.6.0), libc6\n");
        assert_eq!(reasons("npanel", vec![deb(&provides, "0.6.0", &["linux-x86_64"], 'a')]).0, 0);
        let own = format!("{AMD64}Provides: npanel (= 0.6.0)\nConflicts: other\n");
        assert_eq!(reasons("npanel", vec![deb(&own, "0.6.0", &["linux-x86_64"], 'a')]).0, 1);
    }

    #[test]
    fn rejects_ambiguous_releases() {
        let (n, why) = reasons("npanel", vec![deb(AMD64, "0.6.0", &["linux-x86_64"], 'a'), deb(AMD64, "0.6.0", &["linux-x86_64"], 'b')]);
        assert_eq!((n, why.len()), (0, 2));

        let all = "Package: npanel\nVersion: 0.6.0\nArchitecture: all\n";
        let (n, _) = reasons("npanel", vec![deb(all, "0.6.0", &[], 'a'), deb(ARM64, "0.6.0", &["linux-aarch64"], 'b')]);
        assert_eq!(n, 0);

        // Different releases don't collide.
        let next = "Package: npanel\nVersion: 0.7.0\nArchitecture: amd64\n";
        let (n, _) = reasons("npanel", vec![deb(AMD64, "0.6.0", &["linux-x86_64"], 'a'), deb(next, "0.7.0", &["linux-x86_64"], 'b')]);
        assert_eq!(n, 2);
    }

    #[test]
    fn checks_rpms() {
        let meta = crate::inspect::rpm::inspect(include_bytes!("../tests/fixtures/hello-1.2.0-rc.1.x86_64.rpm")).unwrap();
        let candidate = |meta: crate::inspect::RpmMeta| Candidate {
            release_version: "1.2.0-rc.1".into(),
            asset_version: None,
            platforms: vec!["linux-x86_64".into()],
            sha256: "a".repeat(64),
            meta: Meta::Rpm(Box::new(meta)),
        };
        assert_eq!(reasons("hello", vec![candidate(meta.clone())]), (1, vec![]));

        let mut obsoletes = meta.clone();
        obsoletes.obsoletes.push(crate::inspect::rpm::Dependency { name: "openssl".into(), flags: 0, evr: String::new() });
        assert_eq!(reasons("hello", vec![candidate(obsoletes)]).0, 0);
    }
}
