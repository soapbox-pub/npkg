//! Just enough DER for X.509 certificates and PKCS#7 signatures: writing
//! the F-Droid repository's, and reading the signer out of an APK's v1
//! signature.

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
/// `[0]`, constructed: an explicit tag, or an implicit SET OF.
pub const CONTEXT_0: u8 = 0xa0;

/// A TLV: `tag`, the length of `content`, and `content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A constructed value, of its parts one after another.
pub fn constructed(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    constructed(SEQUENCE, parts)
}

/// A non-negative INTEGER from its big-endian bytes.
pub fn unsigned(bytes: &[u8]) -> Vec<u8> {
    let bytes = &bytes[bytes.iter().take_while(|&&b| b == 0).count().min(bytes.len().saturating_sub(1))..];
    let mut content = Vec::with_capacity(bytes.len() + 1);
    if bytes.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(bytes);
    tlv(INTEGER, &content)
}

/// An OBJECT IDENTIFIER.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    let mut base128 = |mut arc: u64| {
        let mut digits = vec![(arc & 0x7f) as u8];
        arc >>= 7;
        while arc > 0 {
            digits.push(0x80 | (arc & 0x7f) as u8);
            arc >>= 7;
        }
        content.extend(digits.iter().rev());
    };
    base128(arcs[0] * 40 + arcs[1]);
    arcs[2..].iter().for_each(|&arc| base128(arc));
    tlv(0x06, &content)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn utf8_string(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

/// A BIT STRING of whole bytes.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0][..], bytes].concat())
}

/// An X.509 Time: UTCTime through 2049, GeneralizedTime after, as RFC 5280
/// has it.
pub fn time(unix: i64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = civil(unix);
    if (1950..2050).contains(&year) {
        tlv(0x17, format!("{:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z", year % 100).as_bytes())
    } else {
        tlv(0x18, format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z").as_bytes())
    }
}

/// A Unix time as a UTC year, month, day, hour, minute and second.
fn civil(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    // Howard Hinnant's days-to-civil.
    let (days, secs) = (unix.div_euclid(86400), unix.rem_euclid(86400) as u32);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, secs / 3600, secs / 60 % 60, secs % 60)
}

/// One value read from the front of `input`: its tag, its content, the
/// whole TLV, and what follows it.
pub struct Read<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub whole: &'a [u8],
    pub rest: &'a [u8],
}

/// The value at the front of `input`, if it's well-formed DER with a
/// one-byte tag.
pub fn read(input: &[u8]) -> Option<Read<'_>> {
    let (&tag, after) = input.split_first()?;
    let (&first, after) = after.split_first()?;
    let (len, after) = if first < 0x80 {
        (first as usize, after)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || after.len() < count {
            return None;
        }
        (after[..count].iter().fold(0usize, |len, &b| len << 8 | b as usize), &after[count..])
    };
    let content = after.get(..len)?;
    let header = input.len() - after.len();
    Some(Read { tag, content, whole: &input[..header + len], rest: &after[len..] })
}

/// The value at the front of `input`, if it has tag `tag`.
pub fn expect(input: &[u8], tag: u8) -> Option<Read<'_>> {
    read(input).filter(|value| value.tag == tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_what_it_reads() {
        assert_eq!(oid(&[1, 2, 840, 113549, 1, 1, 11]), [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
        assert_eq!(unsigned(&[0x00, 0x00, 0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(unsigned(&[0x00]), [0x02, 0x01, 0x00]);
        let long = tlv(OCTET_STRING, &[7; 300]);
        assert_eq!(&long[..4], [0x04, 0x82, 0x01, 0x2c]);
        let outer = sequence(&[&long, &null()]);
        let value = expect(&outer, SEQUENCE).unwrap();
        assert!(value.rest.is_empty());
        let inner = read(value.content).unwrap();
        assert_eq!((inner.tag, inner.content.len(), inner.whole.len()), (OCTET_STRING, 300, 304));
        assert_eq!(inner.rest, null());
        assert!(read(&outer[..outer.len() - 1]).is_none());
    }

    #[test]
    fn writes_times_as_rfc_5280_does() {
        assert_eq!(time(0), tlv(0x17, b"700101000000Z"));
        assert_eq!(time(1_791_734_400), tlv(0x17, b"261011160000Z"));
        assert_eq!(time(253_402_300_799), tlv(0x18, b"99991231235959Z"));
    }
}
