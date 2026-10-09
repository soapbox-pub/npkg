//! A NIP-82 version, as a package of it should spell its own.
//!
//! NIP-82 versions are SemVer, more or less: `v1.2.3`, `1.2.3-rc.1`. Both dpkg
//! and rpm sort `1.2.3-rc.1` wrong (as 1.2.3 with a release of `rc.1`, which
//! comes *after* 1.2.3), so packagers spell the pre-release with a tilde,
//! which sorts before everything: `1.2.3~rc.1`. nfpm does this on its own.

/// The upstream version a .deb of the NIP-82 `version` should have.
pub fn deb(version: &str) -> String {
    convert(version, false)
}

/// The `Version` an .rpm of the NIP-82 `version` should have. rpm allows no
/// `-` in a version, so one in the pre-release becomes `_`, as nfpm writes it.
pub fn rpm(version: &str) -> String {
    convert(version, true)
}

fn convert(version: &str, rpm: bool) -> String {
    let version = version.strip_prefix('v').unwrap_or(version);
    let (version, build) = match version.split_once('+') {
        Some((version, build)) => (version, Some(build)),
        None => (version, None),
    };
    let mut out = match version.split_once('-') {
        Some((base, pre)) => format!("{base}~{}", if rpm { pre.replace('-', "_") } else { pre.to_string() }),
        None => version.to_string(),
    };
    if let Some(build) = build {
        out.push('+');
        out.push_str(build);
    }
    out
}

/// A .deb's `Version` without its epoch and Debian revision: what upstream
/// called it.
pub fn deb_upstream(version: &str) -> &str {
    let version = match version.split_once(':') {
        Some((epoch, rest)) if epoch.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => version,
    };
    version.rsplit_once('-').map_or(version, |(upstream, _)| upstream)
}

/// Whether a package name is one both dpkg and rpm accept, and that needs no
/// escaping in a path or a file name.
pub fn valid_package_name(name: &str) -> bool {
    name.len() >= 2
        && name.len() <= 128
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_versions() {
        assert_eq!(deb("0.6.0"), "0.6.0");
        assert_eq!(deb("v0.6.0"), "0.6.0");
        assert_eq!(deb("0.3.0-rc.1"), "0.3.0~rc.1");
        assert_eq!(deb("1.0.0-alpha-2+abc"), "1.0.0~alpha-2+abc");
        assert_eq!(rpm("1.0.0-alpha-2"), "1.0.0~alpha_2");
    }

    #[test]
    fn strips_epochs_and_revisions() {
        assert_eq!(deb_upstream("0.6.0"), "0.6.0");
        assert_eq!(deb_upstream("0.6.0-1"), "0.6.0");
        assert_eq!(deb_upstream("2:0.6.0~rc.1-3ubuntu1"), "0.6.0~rc.1");
    }

    #[test]
    fn checks_package_names() {
        assert!(valid_package_name("npanel"));
        assert!(valid_package_name("pub.ditto.app"));
        assert!(valid_package_name("g++"));
        assert!(!valid_package_name("x"));
        assert!(!valid_package_name("Npanel"));
        assert!(!valid_package_name("my_app"));
        assert!(!valid_package_name("-x"));
        assert!(!valid_package_name("a/b"));
    }
}
