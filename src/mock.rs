//! An in-process mock Postgres server. It speaks just enough of the v3 protocol
//! to script a full session over real TCP, which lets the whole driver be tested
//! without a database installed. The mock encodes backend messages by hand, so
//! it also cross-checks the driver's decoder against an independent encoder.

use crate::auth::md5_password;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

/// A fixed salt so the MD5 handshake is deterministic in tests.
pub const MOCK_MD5_SALT: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

/// How the mock should behave.
#[derive(Clone, Default)]
pub struct MockConfig {
    /// When set, the mock demands MD5 auth and verifies the client's hash
    /// against this password.
    pub md5_password: Option<String>,
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

fn be_i32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be_i16(b: &[u8]) -> i16 {
    i16::from_be_bytes([b[0], b[1]])
}

/// Read the untagged startup message and return its parameter pairs.
fn read_startup(stream: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let len = be_i32(&read_exact(stream, 4)?);
    let body = read_exact(stream, (len - 4) as usize)?;
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
    let start = *i;
    while *i < body.len() && body[*i] != 0 {
        *i += 1;
    }
    let s = String::from_utf8_lossy(&body[start..*i]).into_owned();
    *i += 1;
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
    let body = read_exact(stream, (len - 4) as usize)?;
    Ok(FeMessage { tag, body })
}

/// Extract the text-format parameter values from a Bind message body.
fn parse_bind_params(body: &[u8]) -> Vec<Option<String>> {
    let mut i = 0;
    read_cstr(body, &mut i); // portal
    read_cstr(body, &mut i); // statement
    let n_fmt = be_i16(&body[i..]) as usize;
    i += 2 + n_fmt * 2;
    let n_params = be_i16(&body[i..]) as usize;
    i += 2;
    let mut out = Vec::with_capacity(n_params);
    for _ in 0..n_params {
        let len = be_i32(&body[i..]);
        i += 4;
        if len == -1 {
            out.push(None);
        } else {
            let l = len as usize;
            out.push(Some(String::from_utf8_lossy(&body[i..i + l]).into_owned()));
            i += l;
        }
    }
    out
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
                let bound = parse_bind_params(&msg.body);
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

/// Canned result for the simple protocol. A query mentioning "boom" triggers an
/// ErrorResponse so the error path is exercisable.
fn respond_simple(stream: &mut TcpStream, sql: &str) -> std::io::Result<()> {
    if sql.to_lowercase().contains("boom") {
        stream.write_all(&error_response("42601", "syntax error at or near \"boom\""))?;
        stream.write_all(&ready_for_query(b'I'))?;
        return Ok(());
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
