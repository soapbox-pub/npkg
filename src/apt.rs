//! An apt suite: `dists/<suite>/`, with one component, `main`.

use std::collections::HashMap;
use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::arch::DEB_ARCHES;
use crate::inspect::Meta;
use crate::repo::Package;
use crate::signing::Signer;

/// Fields the gateway writes itself, never copied from a control file.
const OWN_FIELDS: [&str; 7] = ["Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Description-md5"];

/// The files of one suite, by path below `dists/<suite>/`.
pub fn render(suite: &str, d: &str, description: &str, packages: &[&Package], signer: &Signer) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let mut files = HashMap::new();
    let mut sums = String::new();
    for arch in DEB_ARCHES {
        let mut index = String::new();
        for package in packages.iter().filter(|package| package.arch == arch || package.arch == "all") {
            let Meta::Deb(meta) = &package.meta else { continue };
            if !index.is_empty() {
                index.push('\n');
            }
            writeln!(index, "Package: {}", meta.package())?;
            for (key, value) in &meta.fields {
                if key.eq_ignore_ascii_case("Package") || value.is_empty() || OWN_FIELDS.iter().any(|own| own.eq_ignore_ascii_case(key)) {
                    continue;
                }
                writeln!(index, "{key}: {value}")?;
            }
            writeln!(index, "Filename: {}", pool_path(package, meta.version(), &package.arch))?;
            writeln!(index, "Size: {}", package.size)?;
            writeln!(index, "SHA256: {}", package.sha256)?;
        }

        let path = format!("main/binary-{arch}/Packages");
        let gz = gzip(index.as_bytes());
        writeln!(sums, " {} {} {path}", hex::encode(Sha256::digest(&index)), index.len())?;
        writeln!(sums, " {} {} {path}.gz", hex::encode(Sha256::digest(&gz)), gz.len())?;
        files.insert(format!("{path}.gz"), gz);
        files.insert(path, index.into_bytes());
    }

    // Dated by the newest release in it, not the build, so that a rebuild of
    // the same packages is the same file.
    let date = packages.iter().map(|package| package.created_at).max().unwrap_or(0);
    let release = format!(
        "Origin: npkg-gateway\nLabel: {d}\nSuite: {suite}\nCodename: {suite}\nDate: {}\nArchitectures: {}\nComponents: main\nDescription: {}\nSHA256:\n{sums}",
        rfc2822(date),
        DEB_ARCHES.join(" "),
        description.replace('\n', " "),
    );
    files.insert("InRelease".into(), signer.sign_cleartext(&release)?.into_bytes());
    files.insert("Release.gpg".into(), signer.sign_detached(release.as_bytes())?.into_bytes());
    files.insert("Release".into(), release.into_bytes());
    Ok(files)
}

/// Where apt is told to download a package. Only the hash is read back; the
/// name is for apt's cache and for people reading logs.
fn pool_path(package: &Package, version: &str, arch: &str) -> String {
    let name = format!("{}_{}_{arch}.deb", package.d, version)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._+~-".contains(c) { c } else { '_' })
        .collect::<String>();
    format!("pool/{}/{name}", package.sha256)
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

/// A Unix time as RFC 2822 has it, in UTC.
pub fn rfc2822(time: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = time.div_euclid(86_400);
    let seconds = time.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} UTC",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_dates() {
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 UTC");
        assert_eq!(rfc2822(1_791_497_344), "Thu, 08 Oct 2026 22:09:04 UTC");
        assert_eq!(rfc2822(951_782_400), "Tue, 29 Feb 2000 00:00:00 UTC");
    }
}
