//! Standard base64 (RFC 4648) encode and decode. The Rust standard library ships
//! no base64, and SCRAM carries the salt, proof, and signatures as base64, so
//! Conduit implements it here with zero dependencies.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard base64 with `=` padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode standard base64 (padding optional). Returns `None` on any invalid
/// character or malformed group so a hostile server cannot cause a panic.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let c0 = val(chunk[0])?;
        let c1 = val(chunk[1])?;
        let mut n = (c0 << 18) | (c1 << 12);
        let mut count = 1;
        if chunk.len() > 2 && chunk[2] != b'=' {
            n |= val(chunk[2])? << 6;
            count = 2;
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            n |= val(chunk[3])?;
            count = 3;
        }
        out.push((n >> 16) as u8);
        if count >= 2 {
            out.push((n >> 8) as u8);
        }
        if count >= 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn round_trips() {
        let cases: [&[u8]; 8] = [
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0x00, 0xff, 0x10],
        ];
        for s in cases {
            let e = encode(s);
            assert_eq!(decode(&e).unwrap(), s);
        }
    }

    #[test]
    fn decodes_known_salt() {
        // The RFC 7677 example salt.
        let raw = decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        assert_eq!(encode(&raw), "W22ZaJ0SNY7soEsUEjb6gQ==");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("!!!!").is_none());
        assert!(decode("A").is_none());
    }
}
