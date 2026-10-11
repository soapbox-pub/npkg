//! Requests that someone else points the gateway at: NIP-05 lookups, which
//! anyone can ask for by naming a domain, and package downloads, at the
//! URLs authors give and wherever those redirect. They only go to public
//! addresses, so that nobody can use the gateway to reach what's private
//! to the network it runs on.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// How many redirects a download follows.
const MAX_REDIRECTS: usize = 5;

/// Whether `ip` is reachable from the internet at large, rather than
/// loopback, private, link-local, or set aside for something else.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // Carrier-grade NAT, 100.64.0.0/10.
        || (a == 100 && b & 0xc0 == 64)
        // IETF protocol assignments, 192.0.0.0/24.
        || (a == 192 && b == 0 && c == 0)
        // Benchmarking, 198.18.0.0/15.
        || (a == 198 && b & 0xfe == 18)
        // Reserved, 240.0.0.0/4.
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = ip.segments();
    // NAT64 (64:ff9b::/96) reaches the IPv4 address it embeds.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [_, _, _, _, _, _, high, low] = segments;
        return is_public_v4(Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // IPv4-compatible, deprecated: ::/96.
        || segments[..6] == [0; 6]
        // Unique local, fc00::/7.
        || segments[0] & 0xfe00 == 0xfc00
        // Link-local and the old site-local, fe80::/10 and fec0::/10.
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xffc0 == 0xfec0
        // Documentation, 2001:db8::/32.
        || segments[..2] == [0x2001, 0xdb8])
}

/// Whether `url` is https, and not at an IP address that isn't public.
/// Host names are checked when they're resolved, by [`PublicResolver`].
pub fn is_public_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else { return false };
    url.scheme() == "https" && host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().ok().is_none_or(is_public)
}

/// Follows up to [`MAX_REDIRECTS`] redirects, each to a URL
/// [`is_public_url`] allows.
pub fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            attempt.error("it redirected too many times")
        } else if !is_public_url(attempt.url()) {
            let error = format!("it redirected to {}, which isn't a public https URL", attempt.url());
            attempt.error(error)
        } else {
            attempt.follow()
        }
    })
}

/// Resolves host names to their public addresses only, failing when they
/// have none. Hosts the operator configured, in `trusted`, resolve as
/// they would anywhere.
pub struct PublicResolver {
    trusted: HashSet<String>,
}

impl PublicResolver {
    pub fn new(trusted: impl IntoIterator<Item = String>) -> Arc<PublicResolver> {
        Arc::new(PublicResolver { trusted: trusted.into_iter().map(|host| host.to_ascii_lowercase()).collect() })
    }
}

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let trusted = self.trusted.contains(&host);
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let allowed: Vec<SocketAddr> = found.into_iter().filter(|addr| trusted || is_public(addr.ip())).collect();
            if allowed.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_public_addresses() {
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1", "64:ff9b::101:101"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "ff02::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }

    #[test]
    fn tells_public_urls() {
        let url = |url: &str| reqwest::Url::parse(url).unwrap();
        assert!(is_public_url(&url("https://blossom.example.com/abc")));
        assert!(is_public_url(&url("https://1.1.1.1/abc")));
        assert!(!is_public_url(&url("http://blossom.example.com/abc")));
        assert!(!is_public_url(&url("https://127.0.0.1/abc")));
        assert!(!is_public_url(&url("https://[::1]/abc")));
        assert!(!is_public_url(&url("https://169.254.169.254/latest/meta-data")));
    }

    #[tokio::test]
    async fn resolves_only_to_public_addresses() {
        let resolve = |resolver: Arc<PublicResolver>| async move {
            resolver.resolve("localhost".parse().unwrap()).await.map(|addrs| addrs.collect::<Vec<_>>())
        };
        assert!(resolve(PublicResolver::new([])).await.is_err());
        assert!(!resolve(PublicResolver::new(["localhost".to_string()])).await.unwrap().is_empty());
    }
}
