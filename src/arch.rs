//! NIP-82 platform identifiers (Appendix A), as Debian and rpm name the
//! architectures.

/// Debian architectures every apt suite lists, so that a host of any of them
/// reads the suite rather than warning that it doesn't support it.
pub const DEB_ARCHES: [&str; 4] = ["amd64", "arm64", "armhf", "riscv64"];

pub fn deb(platform: &str) -> Option<&'static str> {
    Some(match platform {
        "linux-x86_64" => "amd64",
        "linux-aarch64" => "arm64",
        "linux-armv7l" => "armhf",
        "linux-riscv64" => "riscv64",
        _ => return None,
    })
}

pub fn rpm(platform: &str) -> Option<&'static str> {
    Some(match platform {
        "linux-x86_64" => "x86_64",
        "linux-aarch64" => "aarch64",
        "linux-armv7l" => "armv7hl",
        "linux-riscv64" => "riscv64",
        _ => return None,
    })
}
