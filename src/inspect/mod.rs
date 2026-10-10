//! What a package file says about itself, read from the file.

pub mod deb;
pub mod rpm;

use serde::{Deserialize, Serialize};

pub use deb::DebMeta;
pub use rpm::RpmMeta;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Format {
    Deb,
    Rpm,
}

impl Format {
    pub fn from_mime(mime: &str) -> Option<Format> {
        match mime {
            crate::nip82::DEB_MIME => Some(Format::Deb),
            crate::nip82::RPM_MIME => Some(Format::Rpm),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Deb => "deb",
            Format::Rpm => "rpm",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum Meta {
    Deb(DebMeta),
    Rpm(Box<RpmMeta>),
}

impl Meta {
    pub fn format(&self) -> Format {
        match self {
            Meta::Deb(_) => Format::Deb,
            Meta::Rpm(_) => Format::Rpm,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Meta::Deb(meta) => meta.package(),
            Meta::Rpm(meta) => &meta.name,
        }
    }

    /// The version as the format's own tools compare it: a deb's `Version`,
    /// an rpm's `epoch:version-release`.
    pub fn version(&self) -> String {
        match self {
            Meta::Deb(meta) => meta.version().to_string(),
            Meta::Rpm(meta) => format!("{}:{}-{}", meta.epoch, meta.version, meta.release),
        }
    }

    pub fn arch(&self) -> &str {
        match self {
            Meta::Deb(meta) => meta.architecture(),
            Meta::Rpm(meta) => &meta.arch,
        }
    }
}

pub fn inspect(format: Format, bytes: &[u8]) -> anyhow::Result<Meta> {
    Ok(match format {
        Format::Deb => Meta::Deb(deb::inspect(bytes)?),
        Format::Rpm => Meta::Rpm(Box::new(rpm::inspect(bytes)?)),
    })
}
