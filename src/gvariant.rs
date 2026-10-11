//! GVariant, GLib's binary serialization: the subset OSTree's objects,
//! deltas and summaries are made of.
//!
//! Values are written in normal form, byte for byte what GLib writes, since
//! OSTree checksums and signs those bytes. Reading is strict: data GLib would
//! read as a default value is an error here, since it came from a file that
//! should have been written by GLib in the first place.
//!
//! Numbers are little-endian, as GLib writes them on every machine this runs
//! on. OSTree stores some fields big-endian inside them; callers swap those.

use std::borrow::Cow;
use std::fmt;

use anyhow::{Context, Result, anyhow, bail, ensure};

/// How deeply types and values may nest, variants included: GLib's own
/// limit. Reading is recursive, and a bundle is the author's to make, so
/// without one a few kilobytes of nesting would overflow the stack.
const MAX_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Bool,
    Byte,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    Double,
    Str,
    ObjectPath,
    Signature,
    Variant,
    Maybe(Box<Type>),
    Array(Box<Type>),
    Tuple(Vec<Type>),
    Entry(Box<Type>, Box<Type>),
}

impl Type {
    pub fn parse(signature: &str) -> Result<Type> {
        let (ty, rest) = Type::parse_one(signature.as_bytes(), 0).with_context(|| format!("{signature:?} isn't a GVariant type"))?;
        ensure!(rest.is_empty(), "{signature:?} is more than one GVariant type");
        Ok(ty)
    }

    fn parse_one(s: &[u8], depth: usize) -> Result<(Type, &[u8])> {
        ensure!(depth < MAX_DEPTH, "it nests more than {MAX_DEPTH} deep");
        let depth = depth + 1;
        let (&first, rest) = s.split_first().ok_or_else(|| anyhow!("it ends early"))?;
        Ok(match first {
            b'b' => (Type::Bool, rest),
            b'y' => (Type::Byte, rest),
            b'n' => (Type::I16, rest),
            b'q' => (Type::U16, rest),
            b'i' => (Type::I32, rest),
            b'u' => (Type::U32, rest),
            b'x' => (Type::I64, rest),
            b't' => (Type::U64, rest),
            b'd' => (Type::Double, rest),
            b's' => (Type::Str, rest),
            b'o' => (Type::ObjectPath, rest),
            b'g' => (Type::Signature, rest),
            b'v' => (Type::Variant, rest),
            b'm' => {
                let (inner, rest) = Type::parse_one(rest, depth)?;
                (Type::Maybe(Box::new(inner)), rest)
            }
            b'a' => {
                let (inner, rest) = Type::parse_one(rest, depth)?;
                (Type::Array(Box::new(inner)), rest)
            }
            b'(' => {
                let mut members = Vec::new();
                let mut rest = rest;
                loop {
                    if let Some(after) = rest.strip_prefix(b")") {
                        break (Type::Tuple(members), after);
                    }
                    let (member, after) = Type::parse_one(rest, depth)?;
                    members.push(member);
                    rest = after;
                }
            }
            b'{' => {
                let (key, rest) = Type::parse_one(rest, depth)?;
                ensure!(key.fixed_size().is_some() || key.is_string(), "a dictionary key must be a basic type");
                let (value, rest) = Type::parse_one(rest, depth)?;
                let rest = rest.strip_prefix(b"}").ok_or_else(|| anyhow!("a dictionary entry has more than two members"))?;
                (Type::Entry(Box::new(key), Box::new(value)), rest)
            }
            other => bail!("{:?} isn't a type", other as char),
        })
    }

    fn is_string(&self) -> bool {
        matches!(self, Type::Str | Type::ObjectPath | Type::Signature)
    }

    fn members(&self) -> Vec<&Type> {
        match self {
            Type::Tuple(members) => members.iter().collect(),
            Type::Entry(key, value) => vec![key, value],
            _ => Vec::new(),
        }
    }

    pub fn alignment(&self) -> usize {
        match self {
            Type::Bool | Type::Byte | Type::Str | Type::ObjectPath | Type::Signature => 1,
            Type::I16 | Type::U16 => 2,
            Type::I32 | Type::U32 => 4,
            Type::I64 | Type::U64 | Type::Double | Type::Variant => 8,
            Type::Maybe(inner) | Type::Array(inner) => inner.alignment(),
            Type::Tuple(_) | Type::Entry(..) => self.members().iter().map(|member| member.alignment()).max().unwrap_or(1),
        }
    }

    /// The size every value of the type has, if they all have the same one.
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            Type::Bool | Type::Byte => Some(1),
            Type::I16 | Type::U16 => Some(2),
            Type::I32 | Type::U32 => Some(4),
            Type::I64 | Type::U64 | Type::Double => Some(8),
            Type::Tuple(_) | Type::Entry(..) => {
                let members = self.members();
                if members.is_empty() {
                    return Some(1);
                }
                let mut size = 0;
                for member in members {
                    size = align(size, member.alignment()) + member.fixed_size()?;
                }
                Some(align(size, self.alignment()))
            }
            _ => None,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Bool => f.write_str("b"),
            Type::Byte => f.write_str("y"),
            Type::I16 => f.write_str("n"),
            Type::U16 => f.write_str("q"),
            Type::I32 => f.write_str("i"),
            Type::U32 => f.write_str("u"),
            Type::I64 => f.write_str("x"),
            Type::U64 => f.write_str("t"),
            Type::Double => f.write_str("d"),
            Type::Str => f.write_str("s"),
            Type::ObjectPath => f.write_str("o"),
            Type::Signature => f.write_str("g"),
            Type::Variant => f.write_str("v"),
            Type::Maybe(inner) => write!(f, "m{inner}"),
            Type::Array(inner) => write!(f, "a{inner}"),
            Type::Tuple(members) => {
                f.write_str("(")?;
                for member in members {
                    write!(f, "{member}")?;
                }
                f.write_str(")")
            }
            Type::Entry(key, value) => write!(f, "{{{key}{value}}}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value<'a> {
    Bool(bool),
    Byte(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Double(f64),
    Str(Cow<'a, str>),
    ObjectPath(Cow<'a, str>),
    Signature(Cow<'a, str>),
    Variant(Box<Value<'a>>),
    Maybe(Type, Option<Box<Value<'a>>>),
    /// `ay`, kept as bytes: some are hundreds of megabytes.
    Bytes(Cow<'a, [u8]>),
    /// Any other array, and the type of its elements.
    Array(Type, Vec<Value<'a>>),
    Tuple(Vec<Value<'a>>),
    Entry(Box<Value<'a>>, Box<Value<'a>>),
}

impl<'a> Value<'a> {
    pub fn str(s: impl Into<String>) -> Value<'static> {
        Value::Str(Cow::Owned(s.into()))
    }

    pub fn bytes(b: impl Into<Vec<u8>>) -> Value<'static> {
        Value::Bytes(Cow::Owned(b.into()))
    }

    pub fn variant(value: Value<'a>) -> Value<'a> {
        Value::Variant(Box::new(value))
    }

    /// An `a{sv}` with these entries, in this order.
    pub fn vardict(entries: Vec<(&str, Value<'a>)>) -> Value<'a> {
        let entries =
            entries.into_iter().map(|(key, value)| Value::Entry(Box::new(Value::str(key)), Box::new(Value::variant(value)))).collect();
        Value::Array(Type::Entry(Box::new(Type::Str), Box::new(Type::Variant)), entries)
    }

    pub fn ty(&self) -> Type {
        match self {
            Value::Bool(_) => Type::Bool,
            Value::Byte(_) => Type::Byte,
            Value::I16(_) => Type::I16,
            Value::U16(_) => Type::U16,
            Value::I32(_) => Type::I32,
            Value::U32(_) => Type::U32,
            Value::I64(_) => Type::I64,
            Value::U64(_) => Type::U64,
            Value::Double(_) => Type::Double,
            Value::Str(_) => Type::Str,
            Value::ObjectPath(_) => Type::ObjectPath,
            Value::Signature(_) => Type::Signature,
            Value::Variant(_) => Type::Variant,
            Value::Maybe(ty, _) => Type::Maybe(Box::new(ty.clone())),
            Value::Bytes(_) => Type::Array(Box::new(Type::Byte)),
            Value::Array(ty, _) => Type::Array(Box::new(ty.clone())),
            Value::Tuple(members) => Type::Tuple(members.iter().map(Value::ty).collect()),
            Value::Entry(key, value) => Type::Entry(Box::new(key.ty()), Box::new(value.ty())),
        }
    }

    /// The value serialized in normal form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Value::Bool(b) => out.push(*b as u8),
            Value::Byte(b) => out.push(*b),
            Value::I16(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::U16(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::I32(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::U32(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::I64(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::U64(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::Double(n) => out.extend_from_slice(&n.to_le_bytes()),
            Value::Str(s) | Value::ObjectPath(s) | Value::Signature(s) => {
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            Value::Variant(inner) => {
                inner.write(out);
                out.push(0);
                out.extend_from_slice(inner.ty().to_string().as_bytes());
            }
            Value::Maybe(ty, inner) => {
                if let Some(inner) = inner {
                    inner.write(out);
                    if ty.fixed_size().is_none() {
                        out.push(0);
                    }
                }
            }
            Value::Bytes(bytes) => out.extend_from_slice(bytes),
            Value::Array(ty, items) => {
                let start = out.len();
                let fixed = ty.fixed_size().is_some();
                let mut ends = Vec::new();
                for item in items {
                    pad(out, start, ty.alignment());
                    item.write(out);
                    ends.push(out.len() - start);
                }
                if !fixed {
                    write_offsets(out, start, &ends);
                }
            }
            Value::Tuple(_) | Value::Entry(..) => {
                let members: Vec<&Value> = match self {
                    Value::Tuple(members) => members.iter().collect(),
                    Value::Entry(key, value) => vec![key, value],
                    _ => unreachable!(),
                };
                let start = out.len();
                let ty = self.ty();
                if members.is_empty() {
                    out.push(0);
                    return;
                }
                let mut ends = Vec::new();
                for (i, member) in members.iter().enumerate() {
                    let member_ty = member.ty();
                    pad(out, start, member_ty.alignment());
                    member.write(out);
                    if member_ty.fixed_size().is_none() && i + 1 < members.len() {
                        ends.push(out.len() - start);
                    }
                }
                if ty.fixed_size().is_some() {
                    pad(out, start, ty.alignment());
                } else {
                    ends.reverse();
                    write_offsets(out, start, &ends);
                }
            }
        }
    }

    /// Read `data` as a value of type `ty`, borrowing strings and byte
    /// arrays from it.
    pub fn read(data: &'a [u8], ty: &Type) -> Result<Value<'a>> {
        Value::read_at(data, ty, 0)
    }

    /// [`Self::read`], inside `depth` containers.
    fn read_at(data: &'a [u8], ty: &Type, depth: usize) -> Result<Value<'a>> {
        ensure!(depth < MAX_DEPTH, "a value nests more than {MAX_DEPTH} deep");
        let depth = depth + 1;
        let scalar = |size: usize| -> Result<&'a [u8]> {
            ensure!(data.len() == size, "a {ty} is {size} bytes, not {}", data.len());
            Ok(data)
        };
        Ok(match ty {
            Type::Bool => match scalar(1)?[0] {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => bail!("a boolean is 0 or 1"),
            },
            Type::Byte => Value::Byte(scalar(1)?[0]),
            Type::I16 => Value::I16(i16::from_le_bytes(scalar(2)?.try_into()?)),
            Type::U16 => Value::U16(u16::from_le_bytes(scalar(2)?.try_into()?)),
            Type::I32 => Value::I32(i32::from_le_bytes(scalar(4)?.try_into()?)),
            Type::U32 => Value::U32(u32::from_le_bytes(scalar(4)?.try_into()?)),
            Type::I64 => Value::I64(i64::from_le_bytes(scalar(8)?.try_into()?)),
            Type::U64 => Value::U64(u64::from_le_bytes(scalar(8)?.try_into()?)),
            Type::Double => Value::Double(f64::from_le_bytes(scalar(8)?.try_into()?)),
            Type::Str | Type::ObjectPath | Type::Signature => {
                let (&last, text) = data.split_last().ok_or_else(|| anyhow!("a string is at least its terminating NUL"))?;
                ensure!(last == 0 && !text.contains(&0), "a string has one NUL, at its end");
                let text = Cow::Borrowed(std::str::from_utf8(text).context("a string isn't UTF-8")?);
                match ty {
                    Type::Str => Value::Str(text),
                    Type::ObjectPath => Value::ObjectPath(text),
                    _ => Value::Signature(text),
                }
            }
            Type::Variant => {
                let nul = data.iter().rposition(|&b| b == 0).ok_or_else(|| anyhow!("a variant has no type"))?;
                let inner_ty = Type::parse(std::str::from_utf8(&data[nul + 1..])?)?;
                Value::Variant(Box::new(Value::read_at(&data[..nul], &inner_ty, depth)?))
            }
            Type::Maybe(inner) => {
                if data.is_empty() {
                    Value::Maybe((**inner).clone(), None)
                } else {
                    let body = match inner.fixed_size() {
                        Some(_) => data,
                        None => {
                            let (&last, body) = data.split_last().unwrap_or((&1, data));
                            ensure!(last == 0, "a maybe's value is followed by a NUL");
                            body
                        }
                    };
                    Value::Maybe((**inner).clone(), Some(Box::new(Value::read_at(body, inner, depth)?)))
                }
            }
            Type::Array(inner) if **inner == Type::Byte => Value::Bytes(Cow::Borrowed(data)),
            Type::Array(inner) => {
                let mut items = Vec::new();
                match inner.fixed_size() {
                    Some(size) => {
                        ensure!(data.len().is_multiple_of(size), "an array of {inner} isn't a whole number of them");
                        for chunk in data.chunks(size) {
                            items.push(Value::read_at(chunk, inner, depth)?);
                        }
                    }
                    None if data.is_empty() => {}
                    None => {
                        let width = offset_width(data.len());
                        let last_end = read_offset(data, data.len() - width, width)?;
                        ensure!(last_end <= data.len() && (data.len() - last_end).is_multiple_of(width), "an array's offsets are wrong");
                        let count = (data.len() - last_end) / width;
                        let mut start = 0;
                        for i in 0..count {
                            let end = read_offset(data, last_end + i * width, width)?;
                            start = align(start, inner.alignment());
                            ensure!(start <= end && end <= last_end, "an array's offsets are wrong");
                            items.push(Value::read_at(&data[start..end], inner, depth)?);
                            start = end;
                        }
                    }
                }
                Value::Array((**inner).clone(), items)
            }
            Type::Tuple(_) | Type::Entry(..) => {
                let members = ty.members();
                if members.is_empty() {
                    ensure!(data == [0], "an empty tuple is one NUL");
                    return Ok(Value::Tuple(Vec::new()));
                }
                if let Some(size) = ty.fixed_size() {
                    ensure!(data.len() == size, "a {ty} is {size} bytes, not {}", data.len());
                }
                let width = offset_width(data.len());
                let mut offsets_used = 0;
                let mut start = 0;
                let mut values = Vec::new();
                for (i, member) in members.iter().enumerate() {
                    start = align(start, member.alignment());
                    let end = match member.fixed_size() {
                        Some(size) => start + size,
                        None if i + 1 == members.len() => {
                            data.len().checked_sub(offsets_used * width).ok_or_else(|| anyhow!("a tuple's offsets are wrong"))?
                        }
                        None => {
                            offsets_used += 1;
                            let at = data.len().checked_sub(offsets_used * width).ok_or_else(|| anyhow!("a tuple's offsets are wrong"))?;
                            read_offset(data, at, width)?
                        }
                    };
                    ensure!(start <= end && end <= data.len(), "a tuple's offsets are wrong");
                    values.push(Value::read_at(&data[start..end], member, depth)?);
                    start = end;
                }
                match ty {
                    Type::Entry(..) => {
                        let mut values = values.into_iter();
                        let (Some(key), Some(value)) = (values.next(), values.next()) else { unreachable!() };
                        Value::Entry(Box::new(key), Box::new(value))
                    }
                    _ => Value::Tuple(values),
                }
            }
        })
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::ObjectPath(s) | Value::Signature(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::U32(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_byte(&self) -> Option<u8> {
        match self {
            Value::Byte(n) => Some(*n),
            _ => None,
        }
    }

    /// The members of a tuple, or the items of an array.
    pub fn items(&self) -> &[Value<'a>] {
        match self {
            Value::Tuple(items) | Value::Array(_, items) => items,
            _ => &[],
        }
    }

    /// Member `i` of a tuple.
    pub fn get(&self, i: usize) -> Result<&Value<'a>> {
        match self {
            Value::Tuple(items) => items.get(i).ok_or_else(|| anyhow!("a tuple has no member {i}")),
            _ => bail!("a {} isn't a tuple", self.ty()),
        }
    }

    /// What a variant holds; anything else, as it is.
    pub fn unwrap_variant(&self) -> &Value<'a> {
        match self {
            Value::Variant(inner) => inner,
            other => other,
        }
    }

    /// The value for `key` in an `a{sv}` (or any dictionary keyed by
    /// strings), unwrapped from its variant.
    pub fn lookup(&self, key: &str) -> Option<&Value<'a>> {
        self.items().iter().find_map(|entry| match entry {
            Value::Entry(k, v) if k.as_str() == Some(key) => Some(v.unwrap_variant()),
            _ => None,
        })
    }
}

fn align(n: usize, alignment: usize) -> usize {
    n.div_ceil(alignment) * alignment
}

/// Pad `out` with NULs until `start` to its end is a multiple of `alignment`.
fn pad(out: &mut Vec<u8>, start: usize, alignment: usize) {
    let len = out.len() - start;
    out.resize(start + align(len, alignment), 0);
}

/// The width of the framing offsets in a container `size` bytes long.
fn offset_width(size: usize) -> usize {
    match size {
        0 => 0,
        1..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xffff_ffff => 4,
        _ => 8,
    }
}

/// Append framing offsets to the container that starts at `start`, as narrow
/// as the container, offsets included, allows.
fn write_offsets(out: &mut Vec<u8>, start: usize, ends: &[usize]) {
    let body = out.len() - start;
    let width = [1usize, 2, 4, 8].into_iter().find(|width| offset_width(body + ends.len() * width) <= *width).unwrap_or(8);
    if ends.is_empty() {
        return;
    }
    for end in ends {
        out.extend_from_slice(&end.to_le_bytes()[..width]);
    }
}

fn read_offset(data: &[u8], at: usize, width: usize) -> Result<usize> {
    let bytes = data.get(at..at + width).ok_or_else(|| anyhow!("an offset is out of bounds"))?;
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(bytes);
    usize::try_from(u64::from_le_bytes(buf)).map_err(|_| anyhow!("an offset is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read `hex` as `signature`, and write it back: the same bytes, every
    /// time. The hex is what GLib 2.86 wrote.
    fn round_trip(signature: &str, hex: &str) -> Value<'static> {
        let bytes = hex::decode(hex).unwrap();
        let ty = Type::parse(signature).unwrap();
        let value = Value::read(&bytes, &ty).unwrap();
        assert_eq!(value.ty().to_string(), signature);
        assert_eq!(hex::encode(value.to_bytes()), hex, "{signature}");
        // Detach it from `bytes`.
        Value::read(Box::leak(bytes.into_boxed_slice()), &ty).unwrap()
    }

    #[test]
    fn writes_what_glib_writes() {
        for (signature, hex) in [
            ("(uuuusa(ayay))", "0100000002000000a4810000000000000011"),
            ("(tuuuusa(ayay))", "05000000000000000000000000000000ffa100000000000074617267657400757365722e61007607091f"),
            ("a{sv}", "6100000000000000780000730200000062620000000000000700000000000000007403000000000063000000000000000102006179020d2336"),
            (
                "(a(say)a(sayay))",
                "6600aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02236400bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc22024424",
            ),
            ("(yay)", "7868656c6c6f"),
            ("()", "00"),
            ("(ty)", "01000000000000000200000000000000"),
            ("a(uuu)", "010000000200000003000000040000000500000006000000"),
            ("v", "6869000003000000030028737529"),
            ("a{sv}", ""),
            (
                "(a(s(taya{sv}))a{sv})",
                "6170702f780000006402000000000000111111111111111111111111111111111111111111111111111111111111111174730000000000000900000000000000007403132806460078612e636163686500000000000000006170702f78000000010000000000000002000000000000006d65746100061e00617b7328747473297d0076093c47",
            ),
            ("aay", "6162630000000305"),
            ("ms", "68690000"),
            ("mu", ""),
        ] {
            round_trip(signature, hex);
        }
    }

    #[test]
    fn widens_offsets_past_255_bytes() {
        let long = "x".repeat(300);
        let value = Value::Array(Type::Str, vec![Value::str(""), Value::str("abc"), Value::str(long.clone())]);
        let mut hex = String::from("0061626300");
        hex.push_str(&hex::encode(format!("{long}\0")));
        hex.push_str("010005003201");
        assert_eq!(hex::encode(value.to_bytes()), hex);
        assert_eq!(Value::read(&value.to_bytes(), &value.ty()).unwrap(), value);
    }

    #[test]
    fn reads_dictionaries() {
        let value = round_trip(
            "a{sv}",
            "6100000000000000780000730200000062620000000000000700000000000000007403000000000063000000000000000102006179020d2336",
        );
        assert_eq!(value.lookup("a").and_then(Value::as_str), Some("x"));
        assert_eq!(value.lookup("bb").and_then(Value::as_u64), Some(7));
        assert_eq!(value.lookup("c").and_then(Value::as_bytes), Some(&[1, 2][..]));
        assert!(value.lookup("d").is_none());
    }

    #[test]
    fn refuses_what_glib_would_not_have_written() {
        let ty = |s| Type::parse(s).unwrap();
        assert!(Value::read(b"ab", &ty("s")).is_err());
        assert!(Value::read(b"a\0b\0", &ty("s")).is_err());
        assert!(Value::read(&[1, 2, 3], &ty("u")).is_err());
        assert!(Value::read(&[2], &ty("b")).is_err());
        assert!(Value::read(&[0x61, 0, 0x09], &ty("as")).is_err());
        assert!(Value::read(&[0x61, 0, 0x05], &ty("(ss)")).is_err());
        assert!(Type::parse("a").is_err());
        assert!(Type::parse("(s").is_err());
        assert!(Type::parse("{vs}").is_err());
        assert!(Type::parse("ss").is_err());
    }

    #[test]
    fn refuses_deep_nesting() {
        assert!(Type::parse(&format!("{}y", "a".repeat(100_000))).is_err());
        assert!(Type::parse(&format!("{}y", "a".repeat(MAX_DEPTH - 1))).is_ok());
        // A variant holding a variant holding a variant, and so on.
        let mut nested = Value::Byte(1);
        for _ in 0..MAX_DEPTH - 1 {
            nested = Value::variant(nested);
        }
        assert!(Value::read(&nested.to_bytes(), &Type::Variant).is_ok());
        let mut data = vec![1u8];
        for _ in 0..100_000 {
            data.extend_from_slice(b"\0v");
        }
        data[2] = b'y';
        assert!(Value::read(&data, &Type::Variant).is_err());
    }
}
