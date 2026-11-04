//! Find the IP address embedded in a hostname.
//!
//! Supported forms (shown for the zone `ipssl.cc`):
//!
//! | Name                         | Result        |
//! |------------------------------|---------------|
//! | `10-0-0-1.ipssl.cc`          | 10.0.0.1      |
//! | `app-10-0-0-1.ipssl.cc`      | 10.0.0.1      |
//! | `10-0-0-1-app.ipssl.cc`      | 10.0.0.1      |
//! | `app.10-0-0-1.ipssl.cc`      | 10.0.0.1      |
//! | `10.0.0.1.ipssl.cc`          | 10.0.0.1      |
//! | `app.10.0.0.1.ipssl.cc`      | 10.0.0.1      |
//! | `app-10.0.0.1.ipssl.cc`      | 10.0.0.1      |
//! | `0a000001.ipssl.cc`          | 10.0.0.1      |
//! | `2001-db8--1.ipssl.cc`       | 2001:db8::1   |
//! | `app.2001-db8--1.ipssl.cc`   | 2001:db8::1   |
//!
//! When a name holds more than one address, the one closest to the zone
//! (the rightmost) wins. Octets with leading zeros (`010`) are rejected so
//! nobody has to guess whether they are octal.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extracts an IP address from `labels`, the lowercase labels left of the
/// zone apex in normal order (`["app", "10-0-0-1"]` for
/// `app.10-0-0-1.ipssl.cc`).
pub fn extract_ip(labels: &[&str]) -> Option<IpAddr> {
    for end in (0..labels.len()).rev() {
        if end >= 3
            && let Some(ip) = dotted_v4(&labels[end - 3..=end])
        {
            return Some(IpAddr::V4(ip));
        }
        if let Some(ip) = single_label(labels[end]) {
            return Some(ip);
        }
    }
    None
}

/// `a.b.c.d` across four labels. The first label may carry a prefix
/// (`app-10.0.0.1`).
fn dotted_v4(parts: &[&str]) -> Option<Ipv4Addr> {
    let first = parts[0].rsplit('-').next()?;
    Some(Ipv4Addr::new(
        octet(first)?,
        octet(parts[1])?,
        octet(parts[2])?,
        octet(parts[3])?,
    ))
}

/// An address inside one label: IPv6 with dashes for colons (the whole
/// label), or IPv4 as four dash-separated octets or eight hex digits,
/// optionally surrounded by other dash-separated words.
fn single_label(label: &str) -> Option<IpAddr> {
    if label.contains('-')
        && let Ok(ip) = label.replace('-', ":").parse::<Ipv6Addr>()
    {
        return Some(IpAddr::V6(ip));
    }

    let tokens: Vec<&str> = label.split('-').collect();
    for end in (0..tokens.len()).rev() {
        if end >= 3 {
            let w = &tokens[end - 3..=end];
            if let (Some(a), Some(b), Some(c), Some(d)) =
                (octet(w[0]), octet(w[1]), octet(w[2]), octet(w[3]))
            {
                return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
            }
        }
        if let Some(ip) = hex_v4(tokens[end]) {
            return Some(IpAddr::V4(ip));
        }
    }
    None
}

/// A decimal octet, 0–255, without leading zeros.
fn octet(s: &str) -> Option<u8> {
    let valid = !s.is_empty()
        && s.len() <= 3
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if valid { s.parse().ok() } else { None }
}

/// Eight hex digits, e.g. `0a000001` for 10.0.0.1.
fn hex_v4(s: &str) -> Option<Ipv4Addr> {
    if s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(s, 16).ok().map(Ipv4Addr::from)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(name: &str) -> Option<IpAddr> {
        let labels: Vec<&str> = if name.is_empty() {
            vec![]
        } else {
            name.split('.').collect()
        };
        extract_ip(&labels)
    }

    fn v4(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn dashed_ipv4() {
        assert_eq!(ip("10-0-0-1"), v4("10.0.0.1"));
        assert_eq!(ip("192-168-1-254"), v4("192.168.1.254"));
        assert_eq!(ip("0-0-0-0"), v4("0.0.0.0"));
        assert_eq!(ip("255-255-255-255"), v4("255.255.255.255"));
    }

    #[test]
    fn dashed_ipv4_with_words() {
        assert_eq!(ip("app-10-0-0-1"), v4("10.0.0.1"));
        assert_eq!(ip("10-0-0-1-app"), v4("10.0.0.1"));
        assert_eq!(ip("my-app-10-0-0-1-v2"), v4("10.0.0.1"));
        assert_eq!(ip("app.10-0-0-1"), v4("10.0.0.1"));
        assert_eq!(ip("a.b.c.10-0-0-1"), v4("10.0.0.1"));
    }

    #[test]
    fn dotted_ipv4() {
        assert_eq!(ip("10.0.0.1"), v4("10.0.0.1"));
        assert_eq!(ip("app.10.0.0.1"), v4("10.0.0.1"));
        assert_eq!(ip("magic-127.0.0.1"), v4("127.0.0.1"));
    }

    #[test]
    fn hex_ipv4() {
        assert_eq!(ip("0a000001"), v4("10.0.0.1"));
        assert_eq!(ip("c0a80001"), v4("192.168.0.1"));
        assert_eq!(ip("app-c0a80001"), v4("192.168.0.1"));
        assert_eq!(ip("abc"), None);
        assert_eq!(ip("0a00000"), None);
        assert_eq!(ip("0a0000011"), None);
    }

    #[test]
    fn dashed_ipv6() {
        assert_eq!(ip("2001-db8--1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(ip("--1"), Some("::1".parse().unwrap()));
        assert_eq!(ip("fe80--1"), Some("fe80::1".parse().unwrap()));
        assert_eq!(
            ip("2001-db8-0-0-0-0-0-1"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(ip("app.2001-db8--1"), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rightmost_address_wins() {
        assert_eq!(ip("10-0-0-1.192-168-1-1"), v4("192.168.1.1"));
        assert_eq!(ip("1.2.3.4.5"), v4("2.3.4.5"));
        assert_eq!(ip("10.0.0.1.192-168-1-1"), v4("192.168.1.1"));
    }

    #[test]
    fn rejects_non_addresses() {
        assert_eq!(ip(""), None);
        assert_eq!(ip("www"), None);
        assert_eq!(ip("10-0-0"), None);
        assert_eq!(ip("10.0.0"), None);
        assert_eq!(ip("256-0-0-1"), None);
        assert_eq!(ip("1-2-3-1000"), None);
        assert_eq!(ip("xn--fiqs8s"), None);
        assert_eq!(ip("my-cool-app"), None);
    }

    #[test]
    fn rejects_leading_zeros() {
        assert_eq!(ip("010-0-0-1"), None);
        assert_eq!(ip("10.0.0.01"), None);
        assert_eq!(ip("00-0-0-0"), None);
    }
}
