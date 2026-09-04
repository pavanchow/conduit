//! An in-process mock Postgres server. It speaks just enough of the v3 protocol
//! to script a full session over real TCP, which lets the whole driver be tested
//! without a database installed. The mock encodes backend messages by hand, so
//! it also cross-checks the driver's decoder against an independent encoder.

use crate::auth::md5_password;
use crate::base64;
use crate::sha256::{hmac_sha256, pbkdf2_hmac_sha256, sha256};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

/// A fixed salt so the MD5 handshake is deterministic in tests.
pub const MOCK_MD5_SALT: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

/// A fixed SCRAM salt and iteration count so the SCRAM handshake is
/// deterministic in tests.
const MOCK_SCRAM_SALT: [u8; 16] = [
    0x73, 0x61, 0x6c, 0x74, 0x66, 0x6f, 0x72, 0x73, 0x63, 0x72, 0x61, 0x6d, 0x74, 0x65, 0x73, 0x74,
];
const MOCK_SCRAM_ITERS: u32 = 4096;
const MOCK_SERVER_NONCE: &str = "3rfcNHYJY1ZVvWVs7j3l6dTR";

/// A cap the mock applies to any client-declared message length, mirroring the
/// driver's own ceiling so a hostile length cannot over-allocate.
const MOCK_MAX_MSG: usize = 64 * 1024 * 1024;

/// How the mock should behave.
#[derive(Clone, Default)]
pub struct MockConfig {
    /// When set, the mock demands MD5 auth and verifies the client's hash
    /// against this password.
    pub md5_password: Option<String>,
    /// When set, the mock demands SCRAM-SHA-256 auth and verifies the client's
    /// proof against this password.
    pub scram_password: Option<String>,
    /// When true, the SCRAM handshake sends a deliberately wrong server
    /// signature so the client's verification step can be exercised.
    pub scram_bad_server_signature: bool,
}

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

/// A running mock server. Accepts connections on a background thread until
/// dropped. `addr` is the bound loopback address (an ephemeral port).
pub struct MockServer {
    pub addr: SocketAddr,
}

impl MockServer {
    /// Bind `127.0.0.1:0` and start accepting connections.
    pub fn start(config: MockConfig) -> std::io::Result<MockServer> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let cfg = config.clone();
                thread::spawn(move || {
                    let _ = handle(stream, cfg);
                });
            }
        });
        Ok(MockServer { addr })
    }

    pub fn host(&self) -> String {
        self.addr.ip().to_string()
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

// ------------------------------------------------------------- backend encoder

/// Frame a backend message body with a type tag and a big-endian length.
fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = (body.len() + 4) as i32;
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(tag);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn put_cstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

fn auth_ok() -> Vec<u8> {
    framed(b'R', &0i32.to_be_bytes())
}

fn auth_md5(salt: &[u8; 4]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&5i32.to_be_bytes());
    body.extend_from_slice(salt);
    framed(b'R', &body)
}

fn auth_sasl(mechanism: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&10i32.to_be_bytes());
    put_cstr(&mut body, mechanism);
    body.push(0); // terminating empty mechanism name
    framed(b'R', &body)
}

fn auth_sasl_continue(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&11i32.to_be_bytes());
    body.extend_from_slice(data);
    framed(b'R', &body)
}

fn auth_sasl_final(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&12i32.to_be_bytes());
    body.extend_from_slice(data);
    framed(b'R', &body)
}

fn notification_response(pid: i32, channel: &str, payload: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&pid.to_be_bytes());
    put_cstr(&mut body, channel);
    put_cstr(&mut body, payload);
    framed(b'A', &body)
}

fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, name);
    put_cstr(&mut body, value);
    framed(b'S', &body)
}

fn backend_key_data(pid: i32, secret: i32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&pid.to_be_bytes());
    body.extend_from_slice(&secret.to_be_bytes());
    framed(b'K', &body)
}

fn ready_for_query(status: u8) -> Vec<u8> {
    framed(b'Z', &[status])
}

/// (name, type_oid) column descriptors.
fn row_description(fields: &[(&str, i32)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(fields.len() as i16).to_be_bytes());
    for (name, oid) in fields {
        put_cstr(&mut body, name);
        body.extend_from_slice(&0i32.to_be_bytes()); // table oid
        body.extend_from_slice(&0i16.to_be_bytes()); // column id
        body.extend_from_slice(&oid.to_be_bytes()); // type oid
        body.extend_from_slice(&(-1i16).to_be_bytes()); // type size (varlena)
        body.extend_from_slice(&(-1i32).to_be_bytes()); // type modifier
        body.extend_from_slice(&0i16.to_be_bytes()); // text format
    }
    framed(b'T', &body)
}

/// `None` for a NULL column, `Some(text)` otherwise.
fn data_row(cols: &[Option<&str>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(cols.len() as i16).to_be_bytes());
    for c in cols {
        match c {
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(s) => {
                body.extend_from_slice(&(s.len() as i32).to_be_bytes());
                body.extend_from_slice(s.as_bytes());
            }
        }
    }
    framed(b'D', &body)
}

fn command_complete(tag: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, tag);
    framed(b'C', &body)
}

fn error_response(code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    put_cstr(&mut body, "ERROR");
    body.push(b'C');
    put_cstr(&mut body, code);
    body.push(b'M');
    put_cstr(&mut body, message);
    body.push(0); // terminator
    framed(b'E', &body)
}

fn parse_complete() -> Vec<u8> {
    framed(b'1', &[])
}

fn bind_complete() -> Vec<u8> {
    framed(b'2', &[])
}

// ------------------------------------------------------------- frontend reader

/// Read exactly `n` bytes or fail.
fn read_exact(stream: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a message body given its declared length field. Rejects a length below
/// the 4-byte minimum (which would underflow `len - 4`) and any length past the
/// cap (which would over-allocate), turning a hostile length into an io error
/// instead of a panic.
fn read_body(stream: &mut TcpStream, len: i32) -> std::io::Result<Vec<u8>> {
    if len < 4 {
        return Err(invalid("message length is below the 4-byte minimum"));
    }
    let n = (len - 4) as usize;
    if n > MOCK_MAX_MSG {
        return Err(invalid("message length exceeds the mock cap"));
    }
    read_exact(stream, n)
}

fn be_i32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be_i16(b: &[u8]) -> i16 {
    i16::from_be_bytes([b[0], b[1]])
}

/// Read a big-endian i16 at `*i`, advancing it, or fail if the body is short.
fn take_i16(body: &[u8], i: &mut usize) -> std::io::Result<i16> {
    if *i + 2 > body.len() {
        return Err(invalid("truncated i16"));
    }
    let v = be_i16(&body[*i..]);
    *i += 2;
    Ok(v)
}

/// Read a big-endian i32 at `*i`, advancing it, or fail if the body is short.
fn take_i32(body: &[u8], i: &mut usize) -> std::io::Result<i32> {
    if *i + 4 > body.len() {
        return Err(invalid("truncated i32"));
    }
    let v = be_i32(&body[*i..]);
    *i += 4;
    Ok(v)
}

/// Read the untagged startup message and return its parameter pairs.
fn read_startup(stream: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let len = be_i32(&read_exact(stream, 4)?);
    let body = read_body(stream, len)?;
    // First 4 bytes are the protocol version; the rest are cstr pairs.
    let mut pairs = Vec::new();
    let mut i = 4;
    while i < body.len() {
        if body[i] == 0 {
            break;
        }
        let key = read_cstr(&body, &mut i);
        let val = read_cstr(&body, &mut i);
        pairs.push((key, val));
    }
    Ok(pairs)
}

fn read_cstr(body: &[u8], i: &mut usize) -> String {
    // Clamp so a cursor already past the end never panics on the slice.
    let start = (*i).min(body.len());
    let mut end = start;
    while end < body.len() && body[end] != 0 {
        end += 1;
    }
    let s = String::from_utf8_lossy(&body[start..end]).into_owned();
    // Consume the terminating nul when there is one.
    *i = if end < body.len() { end + 1 } else { end };
    s
}

/// A tagged frontend message: its tag byte and body (length field stripped).
struct FeMessage {
    tag: u8,
    body: Vec<u8>,
}

fn read_fe_message(stream: &mut TcpStream) -> std::io::Result<FeMessage> {
    let header = read_exact(stream, 5)?;
    let tag = header[0];
    let len = be_i32(&header[1..5]);
    let body = read_body(stream, len)?;
    Ok(FeMessage { tag, body })
}

/// Extract the text-format parameter values from a Bind message body. Every
/// slice is bounds-checked, so a hostile Bind yields an io error rather than a
/// panic.
fn parse_bind_params(body: &[u8]) -> std::io::Result<Vec<Option<String>>> {
    let mut i = 0;
    read_cstr(body, &mut i); // portal
    read_cstr(body, &mut i); // statement
    let n_fmt = take_i16(body, &mut i)?;
    if n_fmt < 0 {
        return Err(invalid("negative format-code count"));
    }
    let skip = (n_fmt as usize)
        .checked_mul(2)
        .ok_or_else(|| invalid("format-code count overflow"))?;
    if i + skip > body.len() {
        return Err(invalid("truncated format codes"));
    }
    i += skip;
    let n_params = take_i16(body, &mut i)?;
    if n_params < 0 {
        return Err(invalid("negative parameter count"));
    }
    let n_params = n_params as usize;
    let mut out = Vec::with_capacity(n_params);
    for _ in 0..n_params {
        let len = take_i32(body, &mut i)?;
        if len == -1 {
            out.push(None);
        } else if len < 0 {
            return Err(invalid("invalid bind parameter length"));
        } else {
            let l = len as usize;
            if i + l > body.len() {
                return Err(invalid("truncated bind parameter value"));
            }
            out.push(Some(String::from_utf8_lossy(&body[i..i + l]).into_owned()));
            i += l;
        }
    }
    Ok(out)
}

// ------------------------------------------------------------- session script

fn handle(mut stream: TcpStream, config: MockConfig) -> std::io::Result<()> {
    let params = read_startup(&mut stream)?;
    let user = params
        .iter()
        .find(|(k, _)| k == "user")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    if let Some(password) = &config.md5_password {
        stream.write_all(&auth_md5(&MOCK_MD5_SALT))?;
        let msg = read_fe_message(&mut stream)?; // PasswordMessage 'p'
        if msg.tag != b'p' {
            stream.write_all(&error_response("08P01", "expected password message"))?;
            return Ok(());
        }
        let mut i = 0;
        let received = read_cstr(&msg.body, &mut i);
        let expected = md5_password(&user, password, &MOCK_MD5_SALT);
        if received != expected {
            stream.write_all(&error_response("28P01", "password authentication failed"))?;
            return Ok(());
        }
    } else if let Some(password) = config.scram_password.clone() {
        if !scram_handshake(&mut stream, &password, config.scram_bad_server_signature)? {
            return Ok(());
        }
    }

    stream.write_all(&auth_ok())?;
    stream.write_all(&parameter_status("server_version", "16.0 (Conduit mock)"))?;
    stream.write_all(&parameter_status("client_encoding", "UTF8"))?;
    stream.write_all(&backend_key_data(4242, 987654321))?;
    stream.write_all(&ready_for_query(b'I'))?;

    loop {
        let msg = match read_fe_message(&mut stream) {
            Ok(m) => m,
            Err(_) => return Ok(()), // client hung up
        };
        match msg.tag {
            b'Q' => {
                let mut i = 0;
                let sql = read_cstr(&msg.body, &mut i);
                respond_simple(&mut stream, &sql)?;
            }
            b'P' => { /* Parse: acknowledged at Execute time */ }
            b'B' => {
                // Stash the bound params on the stream by responding lazily; we
                // just remember them until Execute. Simplest is to handle the
                // whole extended flow here since Bind carries the values.
                let bound = parse_bind_params(&msg.body)?;
                // Drain Describe/Execute/Sync that follow, then reply.
                finish_extended(&mut stream, bound)?;
            }
            b'X' => return Ok(()),
            b'S' => {
                stream.write_all(&ready_for_query(b'I'))?;
            }
            _ => {}
        }
    }
}

/// Perform the server side of a SCRAM-SHA-256 exchange against `password`.
/// Returns `Ok(true)` when the client proved knowledge of the password and the
/// session should continue, `Ok(false)` when authentication failed (an
/// ErrorResponse has already been written).
fn scram_handshake(
    stream: &mut TcpStream,
    password: &str,
    bad_server_signature: bool,
) -> std::io::Result<bool> {
    stream.write_all(&auth_sasl("SCRAM-SHA-256"))?;

    // SASLInitialResponse: [mechanism cstr][Int32 len][client-first bytes].
    let msg = read_fe_message(stream)?;
    if msg.tag != b'p' {
        stream.write_all(&error_response("08P01", "expected SASL initial response"))?;
        return Ok(false);
    }
    let mut i = 0;
    let _mechanism = read_cstr(&msg.body, &mut i);
    let dlen = take_i32(&msg.body, &mut i)?;
    if dlen < 0 || i + dlen as usize > msg.body.len() {
        return Err(invalid("bad SASL initial response length"));
    }
    let client_first = String::from_utf8_lossy(&msg.body[i..i + dlen as usize]).into_owned();
    let client_first_bare = client_first
        .strip_prefix("n,,")
        .ok_or_else(|| invalid("client-first missing gs2 header"))?
        .to_string();
    let client_nonce = attr(&client_first_bare, 'r')
        .ok_or_else(|| invalid("client-first missing nonce"))?;

    let combined_nonce = format!("{client_nonce}{MOCK_SERVER_NONCE}");
    let server_first = format!(
        "r={combined_nonce},s={},i={}",
        base64::encode(&MOCK_SCRAM_SALT),
        MOCK_SCRAM_ITERS
    );
    stream.write_all(&auth_sasl_continue(server_first.as_bytes()))?;

    // SASLResponse: raw client-final bytes "c=biws,r=<nonce>,p=<proof>".
    let msg = read_fe_message(stream)?;
    let client_final = String::from_utf8_lossy(&msg.body).into_owned();
    let proof_marker = client_final
        .rfind(",p=")
        .ok_or_else(|| invalid("client-final missing proof"))?;
    let without_proof = &client_final[..proof_marker];
    let proof_b64 = &client_final[proof_marker + 3..];

    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let salted = pbkdf2_hmac_sha256(password.as_bytes(), &MOCK_SCRAM_SALT, MOCK_SCRAM_ITERS);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut expected_proof = client_key;
    for j in 0..expected_proof.len() {
        expected_proof[j] ^= client_sig[j];
    }

    let received = base64::decode(proof_b64).unwrap_or_default();
    if received.as_slice() != expected_proof.as_slice() {
        stream.write_all(&error_response("28P01", "password authentication failed"))?;
        return Ok(false);
    }

    let server_key = hmac_sha256(&salted, b"Server Key");
    let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    let mut v = base64::encode(&server_sig);
    if bad_server_signature {
        // Flip the payload so verify_server_final rejects it.
        v = base64::encode(b"not the real server signature!!!");
    }
    let server_final = format!("v={v}");
    stream.write_all(&auth_sasl_final(server_final.as_bytes()))?;
    Ok(true)
}

/// Pull a single-letter SCRAM attribute value (`r`, `s`, `i`, ...) out of a
/// comma-separated attribute list.
fn attr(message: &str, key: char) -> Option<String> {
    for part in message.split(',') {
        let mut chars = part.chars();
        if chars.next() == Some(key) && chars.next() == Some('=') {
            return Some(part[2..].to_string());
        }
    }
    None
}

/// Canned result for the simple protocol. A query mentioning "boom" triggers an
/// ErrorResponse so the error path is exercisable. "multi" emits two result sets
/// before one ReadyForQuery, and "notify" prepends an asynchronous
/// NotificationResponse.
fn respond_simple(stream: &mut TcpStream, sql: &str) -> std::io::Result<()> {
    let lower = sql.to_lowercase();
    if lower.contains("boom") {
        stream.write_all(&error_response("42601", "syntax error at or near \"boom\""))?;
        stream.write_all(&ready_for_query(b'I'))?;
        return Ok(());
    }
    if lower.contains("multi") {
        // Two independent statements, each its own RowDescription and
        // CommandComplete, before a single ReadyForQuery.
        stream.write_all(&row_description(&[("n", 23)]))?;
        stream.write_all(&data_row(&[Some("1")]))?;
        stream.write_all(&command_complete("SELECT 1"))?;
        stream.write_all(&row_description(&[("n", 23)]))?;
        stream.write_all(&data_row(&[Some("2")]))?;
        stream.write_all(&data_row(&[Some("3")]))?;
        stream.write_all(&command_complete("SELECT 2"))?;
        stream.write_all(&ready_for_query(b'I'))?;
        return Ok(());
    }
    if lower.contains("notify") {
        stream.write_all(&notification_response(4242, "chan", "hello"))?;
    }
    write_sample_rows(stream)?;
    stream.write_all(&ready_for_query(b'I'))?;
    Ok(())
}

/// A representative typed result set: int, text, float, bool, and a NULL.
fn write_sample_rows(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&row_description(&[
        ("id", 23),      // int4
        ("name", 25),    // text
        ("score", 701),  // float8
        ("active", 16),  // bool
        ("note", 25),    // text (nullable)
    ]))?;
    stream.write_all(&data_row(&[
        Some("1"),
        Some("alice"),
        Some("3.5"),
        Some("t"),
        None,
    ]))?;
    stream.write_all(&data_row(&[
        Some("2"),
        Some("bob"),
        Some("-1.25"),
        Some("f"),
        Some("hi"),
    ]))?;
    stream.write_all(&command_complete("SELECT 2"))?;
    Ok(())
}

/// Read Describe/Execute/Sync after a Bind, then echo the bound params back as
/// a single text row so a caller can prove the parameters round-tripped.
fn finish_extended(stream: &mut TcpStream, bound: Vec<Option<String>>) -> std::io::Result<()> {
    // Consume messages until Sync.
    loop {
        let msg = read_fe_message(stream)?;
        if msg.tag == b'S' {
            break;
        }
    }

    stream.write_all(&parse_complete())?;
    stream.write_all(&bind_complete())?;

    let fields: Vec<(&str, i32)> = (0..bound.len())
        .map(|_| ("param", 25i32)) // echo as text
        .collect();
    stream.write_all(&row_description(&fields))?;

    let cols: Vec<Option<&str>> = bound.iter().map(|v| v.as_deref()).collect();
    stream.write_all(&data_row(&cols))?;
    stream.write_all(&command_complete("SELECT 1"))?;
    stream.write_all(&ready_for_query(b'I'))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bind_params_rejects_hostile_bodies_without_panicking() {
        // A truncated Bind (claims two params, carries none) must error, not
        // index out of bounds.
        let mut body = Vec::new();
        put_cstr(&mut body, ""); // portal
        put_cstr(&mut body, ""); // statement
        body.extend_from_slice(&0i16.to_be_bytes()); // zero format codes
        body.extend_from_slice(&2i16.to_be_bytes()); // claims two params
        assert!(parse_bind_params(&body).is_err());

        // A parameter claiming a huge positive length with no data behind it.
        let mut body = Vec::new();
        put_cstr(&mut body, "");
        put_cstr(&mut body, "");
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&0x7fff_ffffi32.to_be_bytes());
        assert!(parse_bind_params(&body).is_err());

        // An empty body: reading the first i16 already fails cleanly.
        assert!(parse_bind_params(&[]).is_err());
    }

    #[test]
    fn well_formed_bind_still_parses() {
        let mut body = Vec::new();
        put_cstr(&mut body, ""); // portal
        put_cstr(&mut body, ""); // statement
        body.extend_from_slice(&1i16.to_be_bytes()); // one format code
        body.extend_from_slice(&0i16.to_be_bytes()); // text
        body.extend_from_slice(&2i16.to_be_bytes()); // two params
        body.extend_from_slice(&2i32.to_be_bytes());
        body.extend_from_slice(b"42");
        body.extend_from_slice(&(-1i32).to_be_bytes()); // NULL
        let out = parse_bind_params(&body).unwrap();
        assert_eq!(out, vec![Some("42".to_string()), None]);
    }
}
