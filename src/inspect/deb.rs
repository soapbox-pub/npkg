//! Reading a .deb's control file: an `ar` archive holding `control.tar`,
//! compressed or not, holding `./control`.

use std::io::{Cursor, Read};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// How much of a decompressed control archive is read. Control archives are
/// a few kilobytes; this only bounds a compression bomb.
const MAX_CONTROL_TAR: u64 = 16 << 20;

/// A control file's fields, in order. Values are kept as written, with their
/// continuation lines, so that they can be copied into `Packages` unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebMeta {
    pub fields: Vec<(String, String)>,
}

impl DebMeta {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn package(&self) -> &str {
        self.get("Package").unwrap_or_default()
    }

    pub fn version(&self) -> &str {
        self.get("Version").unwrap_or_default()
    }

    pub fn architecture(&self) -> &str {
        self.get("Architecture").unwrap_or_default()
    }
}

pub fn inspect(bytes: &[u8]) -> anyhow::Result<DebMeta> {
    let (name, member) =
        ar_members(bytes)?.into_iter().find(|(name, _)| name.starts_with("control.tar")).context("The .deb has no control archive.")?;

    let reader: Box<dyn Read + '_> = match name.as_str() {
        "control.tar" => Box::new(member),
        "control.tar.gz" => Box::new(flate2::read::GzDecoder::new(member)),
        "control.tar.xz" => {
            let mut out = Vec::new();
            lzma_rs::xz_decompress(&mut Cursor::new(member), &mut LimitedWriter(&mut out))
                .context("The .deb's control.tar.xz doesn't decompress.")?;
            Box::new(Cursor::new(out))
        }
        "control.tar.zst" => Box::new(
            ruzstd::decoding::StreamingDecoder::new(member)
                .map_err(|error| anyhow::anyhow!("The .deb's control.tar.zst doesn't decompress: {error}"))?,
        ),
        other => bail!("The .deb's control archive is {other}, a compression this gateway doesn't read."),
    };

    let mut archive = tar::Archive::new(reader.take(MAX_CONTROL_TAR));
    for entry in archive.entries().context("The .deb's control archive isn't a tar archive.")? {
        let mut entry = entry.context("The .deb's control archive is damaged.")?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if path.trim_start_matches("./") == "control" {
            let mut text = String::new();
            entry.read_to_string(&mut text).context("The .deb's control file isn't UTF-8.")?;
            return parse_control(&text);
        }
    }
    bail!("The .deb's control archive has no control file.")
}

/// The first paragraph of a deb822 file.
pub fn parse_control(text: &str) -> anyhow::Result<DebMeta> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        // A carriage return, say, could read as a line break to whatever
        // reads the Packages file the fields are copied into.
        if line.chars().any(|c| c.is_control() && c != '\t') {
            bail!("The control file has a control character in the line {line:?}.");
        }
        if line.trim().is_empty() {
            if fields.is_empty() {
                continue;
            }
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let (_, value) = fields.last_mut().context("The control file starts with a continuation line.")?;
            value.push('\n');
            value.push_str(line.trim_end());
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once(':').with_context(|| format!("The control file has a line that isn't a field: {line:?}"))?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_graphic() && b != b':') || key.starts_with('-') {
            bail!("The control file has a field with an invalid name: {key:?}");
        }
        if fields.iter().any(|(existing, _)| existing.eq_ignore_ascii_case(key)) {
            bail!("The control file has the field {key} twice.");
        }
        fields.push((key.to_string(), value.trim().to_string()));
    }
    let meta = DebMeta { fields };
    for required in ["Package", "Version", "Architecture"] {
        if meta.get(required).is_none_or(str::is_empty) {
            bail!("The control file has no {required} field.");
        }
    }
    Ok(meta)
}

/// The members of an `ar` archive, by name.
fn ar_members(bytes: &[u8]) -> anyhow::Result<Vec<(String, &[u8])>> {
    let mut rest = bytes.strip_prefix(b"!<arch>\n").context("The file isn't a .deb: it isn't an ar archive.")?;
    let mut members = Vec::new();
    while rest.len() >= 60 {
        let header = &rest[..60];
        if &header[58..60] != b"`\n" {
            bail!("The .deb's ar archive is damaged.");
        }
        let name = String::from_utf8_lossy(&header[..16]).trim_end().trim_end_matches('/').to_string();
        let size: usize = std::str::from_utf8(&header[48..58])
            .ok()
            .and_then(|size| size.trim().parse().ok())
            .context("The .deb's ar archive has a member of no size.")?;
        let data = rest.get(60..60 + size).context("The .deb is truncated.")?;
        members.push((name, data));
        let next = 60 + size + (size & 1);
        rest = rest.get(next..).unwrap_or_default();
    }
    Ok(members)
}

/// A writer that refuses to grow past [`MAX_CONTROL_TAR`].
struct LimitedWriter<'a>(&'a mut Vec<u8>);

impl std::io::Write for LimitedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.0.len() as u64 + buf.len() as u64 > MAX_CONTROL_TAR {
            return Err(std::io::Error::other("control archive too large"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A .deb with `control` as its control file and no data.
    pub fn build(control: &str, compression: &str) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(control.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "./control", control.as_bytes()).unwrap();
        let tar = tar.into_inner().unwrap();
        let (name, member) = match compression {
            "gz" => {
                use std::io::Write;
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&tar).unwrap();
                ("control.tar.gz", encoder.finish().unwrap())
            }
            "xz" => {
                let mut out = Vec::new();
                lzma_rs::xz_compress(&mut Cursor::new(&tar), &mut out).unwrap();
                ("control.tar.xz", out)
            }
            _ => ("control.tar", tar),
        };

        let mut deb = b"!<arch>\n".to_vec();
        for (name, data) in [("debian-binary", b"2.0\n".to_vec()), (name, member), ("data.tar", Vec::new())] {
            deb.extend(format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, 100644, data.len()).as_bytes());
            deb.extend(&data);
            if data.len() % 2 == 1 {
                deb.push(b'\n');
            }
        }
        deb
    }

    const CONTROL: &str = "Package: npanel\nVersion: 0.6.0\nArchitecture: amd64\nDescription: A thing\n It does things.\n .\n More.\n";

    #[test]
    fn reads_control_files() {
        for compression in ["gz", "xz", "none"] {
            let meta = inspect(&build(CONTROL, compression)).unwrap();
            assert_eq!(meta.package(), "npanel");
            assert_eq!(meta.version(), "0.6.0");
            assert_eq!(meta.architecture(), "amd64");
            assert_eq!(meta.get("description"), Some("A thing\n It does things.\n .\n More."));
        }
    }

    #[test]
    fn refuses_what_isnt_a_control_file() {
        assert!(inspect(b"not a deb").is_err());
        assert!(parse_control("Package: x\nVersion: 1\n").is_err());
        assert!(parse_control("Package: x\nPackage: y\nVersion: 1\nArchitecture: all\n").is_err());
        assert!(parse_control(" continuation\nPackage: x\n").is_err());
        assert!(parse_control("Package: x\njunk\n").is_err());
        assert!(parse_control("Package: x\nVersion: 1\rFilename: y\nArchitecture: all\n").is_err());
        assert!(parse_control("Package: x\r\nVersion: 1\r\nArchitecture: all\r\n").is_ok());
    }

    #[test]
    fn stops_at_the_first_paragraph() {
        let meta = parse_control("Package: x\nVersion: 1\nArchitecture: all\n\nFilename: evil\n").unwrap();
        assert_eq!(meta.get("Filename"), None);
    }
}
