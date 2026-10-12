//! What a package file says about itself, read from the file.

pub mod apk;
pub mod deb;
pub mod rpm;

use serde::{Deserialize, Serialize};

pub use apk::ApkMeta;
pub use deb::DebMeta;
pub use rpm::RpmMeta;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Format {
    Deb,
    Rpm,
    Apk,
}

impl Format {
    pub fn from_mime(mime: &str) -> Option<Format> {
        match mime {
            crate::nip82::DEB_MIME => Some(Format::Deb),
            crate::nip82::RPM_MIME => Some(Format::Rpm),
            crate::nip82::APK_MIME => Some(Format::Apk),
            _ => None,
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Format::Deb => crate::nip82::DEB_MIME,
            Format::Rpm => crate::nip82::RPM_MIME,
            Format::Apk => crate::nip82::APK_MIME,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Deb => "deb",
            Format::Rpm => "rpm",
            Format::Apk => "apk",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum Meta {
    Deb(DebMeta),
    Rpm(Box<RpmMeta>),
    Apk(Box<ApkMeta>),
}

impl Meta {
    pub fn format(&self) -> Format {
        match self {
            Meta::Deb(_) => Format::Deb,
            Meta::Rpm(_) => Format::Rpm,
            Meta::Apk(_) => Format::Apk,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Meta::Deb(meta) => meta.package(),
            Meta::Rpm(meta) => &meta.name,
            Meta::Apk(meta) => &meta.package,
        }
    }

    /// The version as the format's own tools compare it: a deb's `Version`,
    /// an rpm's `epoch:version-release`, an APK's versionCode.
    pub fn version(&self) -> String {
        match self {
            Meta::Deb(meta) => meta.version().to_string(),
            Meta::Rpm(meta) => format!("{}:{}-{}", meta.epoch, meta.version, meta.release),
            Meta::Apk(meta) => meta.version_code.to_string(),
        }
    }

    pub fn arch(&self) -> String {
        match self {
            Meta::Deb(meta) => meta.architecture().to_string(),
            Meta::Rpm(meta) => meta.arch.clone(),
            Meta::Apk(meta) => meta.arch(),
        }
    }
}

pub fn inspect(format: Format, bytes: &[u8]) -> anyhow::Result<Meta> {
    Ok(match format {
        Format::Deb => Meta::Deb(deb::inspect(bytes)?),
        Format::Rpm => Meta::Rpm(Box::new(rpm::inspect(bytes)?)),
        Format::Apk => Meta::Apk(Box::new(apk::inspect(bytes)?)),
    })
}
