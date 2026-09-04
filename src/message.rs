//! The PostgreSQL v3 frontend/backend protocol codec. Pure functions over bytes,
//! no sockets. This is the heart of Conduit: every message encodes to and decodes
//! from the exact wire bytes.
//!
//! Framing (all integers big-endian):
//!   [1-byte type tag] [Int32 length] [body]
//! The length counts itself plus the body but NOT the type tag. The startup and
//! SSLRequest messages are the sole exception: they carry no type tag, just the
//! Int32 length followed by the body.
//!
//! Decoding is bounded: a malformed length or a short buffer yields a protocol
//! error or a request for more bytes, never a panic.

use crate::error::{Error, Result};

/// Text format code on the wire.
pub const FORMAT_TEXT: i16 = 0;
/// Binary format code on the wire (Conduit requests text everywhere).
pub const FORMAT_BINARY: i16 = 1;

/// Protocol version 3.0 encoded as the Int32 the server expects (0x00030000).
pub const PROTOCOL_VERSION: i32 = 196608;

// ------------------------------------------------------------------ encoding

/// Small helper for building message bodies with big-endian integers and
/// C strings, then framing them with a type tag and length.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn i16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// A null-terminated C string.
    fn cstr(&mut self, v: &str) {
        self.buf.extend_from_slice(v.as_bytes());
        self.buf.push(0);
    }

    /// Frame `body` as `[tag][Int32 len][body]`, len covering itself and body.
    fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
        let len = (body.len() + 4) as i32;
        let mut out = Vec::with_capacity(body.len() + 5);
        out.push(tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Frame `body` with no type tag (startup family): `[Int32 len][body]`.
    fn framed_untagged(body: &[u8]) -> Vec<u8> {
        let len = (body.len() + 4) as i32;
        let mut out = Vec::with_capacity(body.len() + 4);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(body);
        out
    }
}

/// A parameter value carried in a Bind message. Conduit always sends parameters
/// in the text format so that the value is data, never SQL, which makes
/// injection structurally impossible.
#[derive(Debug, Clone, PartialEq)]
pub enum BindValue {
    Null,
    Text(String),
}

/// Every message Conduit can send to the server.
#[derive(Debug, Clone, PartialEq)]
pub enum FrontendMessage {
    Startup {
        user: String,
        database: String,
        params: Vec<(String, String)>,
    },
    /// Cleartext or MD5 password; the string is whatever the auth layer computed.
    Password(String),
    Query(String),
    Parse {
        statement: String,
        query: String,
        param_types: Vec<i32>,
    },
    Bind {
        portal: String,
        statement: String,
        params: Vec<BindValue>,
    },
    /// Describe a 'S'tatement or 'P'ortal by name.
    Describe {
        kind: u8,
        name: String,
    },
    Execute {
        portal: String,
        max_rows: i32,
    },
    Sync,
    Terminate,
}

impl FrontendMessage {
    /// Serialize to the exact bytes that go on the wire.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            FrontendMessage::Startup {
                user,
                database,
                params,
            } => {
                let mut w = Writer::new();
                w.i32(PROTOCOL_VERSION);
                w.cstr("user");
                w.cstr(user);
                w.cstr("database");
                w.cstr(database);
                for (k, v) in params {
                    w.cstr(k);
                    w.cstr(v);
                }
                w.u8(0); // terminating empty key
                Writer::framed_untagged(&w.buf)
            }
            FrontendMessage::Password(s) => {
                let mut w = Writer::new();
                w.cstr(s);
                Writer::framed(b'p', &w.buf)
            }
            FrontendMessage::Query(sql) => {
                let mut w = Writer::new();
                w.cstr(sql);
                Writer::framed(b'Q', &w.buf)
            }
            FrontendMessage::Parse {
                statement,
                query,
                param_types,
            } => {
                let mut w = Writer::new();
                w.cstr(statement);
                w.cstr(query);
                w.i16(param_types.len() as i16);
                for oid in param_types {
                    w.i32(*oid);
                }
                Writer::framed(b'P', &w.buf)
            }
            FrontendMessage::Bind {
                portal,
                statement,
                params,
            } => {
                let mut w = Writer::new();
                w.cstr(portal);
                w.cstr(statement);
                // One format code, text, applied to every parameter.
                w.i16(1);
                w.i16(FORMAT_TEXT);
                w.i16(params.len() as i16);
                for p in params {
                    match p {
                        BindValue::Null => w.i32(-1),
                        BindValue::Text(s) => {
                            w.i32(s.len() as i32);
                            w.bytes(s.as_bytes());
                        }
                    }
                }
                // One result format code, text, applied to every column.
                w.i16(1);
                w.i16(FORMAT_TEXT);
                Writer::framed(b'B', &w.buf)
            }
            FrontendMessage::Describe { kind, name } => {
                let mut w = Writer::new();
                w.u8(*kind);
                w.cstr(name);
                Writer::framed(b'D', &w.buf)
            }
            FrontendMessage::Execute { portal, max_rows } => {
                let mut w = Writer::new();
                w.cstr(portal);
                w.i32(*max_rows);
                Writer::framed(b'E', &w.buf)
            }
            FrontendMessage::Sync => Writer::framed(b'S', &[]),
            FrontendMessage::Terminate => Writer::framed(b'X', &[]),
        }
    }

    /// Decode one frontend message from the front of `buf`. This mirrors
    /// [`FrontendMessage::encode`] so that `decode(encode(x)) == x`, which the
    /// golden tests rely on. A leading zero byte marks the untagged startup
    /// message (every tagged frontend message begins with a printable ASCII tag).
    pub fn decode(buf: &[u8]) -> Result<Option<(FrontendMessage, usize)>> {
        if buf.len() < 5 {
            return Ok(None);
        }
        if buf[0] == 0 {
            // Untagged startup family.
            let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if len < 8 {
                return Err(Error::Protocol(format!("startup length {len} too small")));
            }
            let total = len as usize;
            if buf.len() < total {
                return Ok(None);
            }
            let mut r = Reader::new(&buf[4..total]);
            let _version = r.i32()?;
            let mut user = String::new();
            let mut database = String::new();
            let mut params = Vec::new();
            loop {
                let key = r.cstr()?;
                if key.is_empty() {
                    break;
                }
                let value = r.cstr()?;
                match key.as_str() {
                    "user" => user = value,
                    "database" => database = value,
                    _ => params.push((key, value)),
                }
            }
            return Ok(Some((
                FrontendMessage::Startup {
                    user,
                    database,
                    params,
                },
                total,
            )));
        }

        let tag = buf[0];
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if len < 4 {
            return Err(Error::Protocol(format!("message length {len} too small")));
        }
        let total = 1 + len as usize;
        if buf.len() < total {
            return Ok(None);
        }
        let mut r = Reader::new(&buf[5..total]);
        let msg = match tag {
            b'p' => FrontendMessage::Password(r.cstr()?),
            b'Q' => FrontendMessage::Query(r.cstr()?),
            b'P' => {
                let statement = r.cstr()?;
                let query = r.cstr()?;
                let n = r.i16()?;
                let mut param_types = Vec::with_capacity(n.max(0) as usize);
                for _ in 0..n {
                    param_types.push(r.i32()?);
                }
                FrontendMessage::Parse {
                    statement,
                    query,
                    param_types,
                }
            }
            b'B' => {
                let portal = r.cstr()?;
                let statement = r.cstr()?;
                let n_fmt = r.i16()?;
                for _ in 0..n_fmt {
                    let _ = r.i16()?;
                }
                let n_params = r.i16()?;
                let mut params = Vec::with_capacity(n_params.max(0) as usize);
                for _ in 0..n_params {
                    let len = r.i32()?;
                    if len == -1 {
                        params.push(BindValue::Null);
                    } else if len < 0 {
                        return Err(Error::Protocol(format!("invalid bind length {len}")));
                    } else {
                        let bytes = r.bytes(len as usize)?;
                        params.push(BindValue::Text(
                            String::from_utf8_lossy(bytes).into_owned(),
                        ));
                    }
                }
                let n_res = r.i16()?;
                for _ in 0..n_res {
                    let _ = r.i16()?;
                }
                FrontendMessage::Bind {
                    portal,
                    statement,
                    params,
                }
            }
            b'D' => {
                let kind = r.u8()?;
                let name = r.cstr()?;
                FrontendMessage::Describe { kind, name }
            }
            b'E' => {
                let portal = r.cstr()?;
                let max_rows = r.i32()?;
                FrontendMessage::Execute { portal, max_rows }
            }
            b'S' => FrontendMessage::Sync,
            b'X' => FrontendMessage::Terminate,
            other => {
                return Err(Error::Protocol(format!(
                    "unknown frontend message tag {other:#x}"
                )))
            }
        };
        Ok(Some((msg, total)))
    }
}

// ------------------------------------------------------------------ decoding

/// Bounded cursor over a message body. Every read is length-checked and returns
/// a protocol error instead of panicking when the buffer runs short.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            return Err(Error::Protocol(format!(
                "message body truncated: need {n} bytes at offset {}, have {}",
                self.pos,
                self.buf.len() - self.pos
            )));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn i16(&mut self) -> Result<i16> {
        self.need(2)?;
        let v = i16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn i32(&mut self) -> Result<i32> {
        self.need(4)?;
        let v = i32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a null-terminated C string as UTF-8 (lossy for non-UTF-8 bytes).
    fn cstr(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return Err(Error::Protocol("unterminated C string".into()));
        }
        let s = String::from_utf8_lossy(&self.buf[start..self.pos]).into_owned();
        self.pos += 1; // consume the nul
        Ok(s)
    }
}

/// Result of an authentication request from the server.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthRequest {
    Ok,
    CleartextPassword,
    Md5Password { salt: [u8; 4] },
    /// Any auth method Conduit does not implement (SCRAM, GSS, etc.).
    Unsupported(i32),
}

/// One column description inside a RowDescription.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: i32,
    pub column_id: i16,
    pub type_oid: i32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: i16,
}

/// One field of an ErrorResponse or NoticeResponse: a type byte plus a value.
#[derive(Debug, Clone, PartialEq)]
pub struct NoticeField {
    pub code: u8,
    pub value: String,
}

/// Pull the SQLSTATE ('C') and message ('M') out of a notice/error field list.
pub fn error_code_and_message(fields: &[NoticeField]) -> (String, String) {
    let mut code = String::new();
    let mut message = String::new();
    for f in fields {
        match f.code {
            b'C' => code = f.value.clone(),
            b'M' => message = f.value.clone(),
            _ => {}
        }
    }
    (code, message)
}

/// Every message Conduit understands from the server.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendMessage {
    Authentication(AuthRequest),
    ParameterStatus { name: String, value: String },
    BackendKeyData { pid: i32, secret: i32 },
    ReadyForQuery { status: u8 },
    RowDescription(Vec<FieldDescription>),
    DataRow(Vec<Option<Vec<u8>>>),
    CommandComplete { tag: String },
    ErrorResponse(Vec<NoticeField>),
    NoticeResponse(Vec<NoticeField>),
    ParseComplete,
    BindComplete,
    NoData,
    EmptyQueryResponse,
    ParameterDescription(Vec<i32>),
    /// A message whose tag we do not model; skipped by length, never fatal.
    Unknown { tag: u8 },
}

impl BackendMessage {
    /// Try to decode one backend message from the front of `buf`.
    ///
    /// Returns `Ok(None)` when `buf` does not yet hold a full message (the caller
    /// should read more from the socket), or `Ok(Some((msg, consumed)))` with the
    /// number of bytes the message occupied. Malformed framing is a protocol error.
    pub fn decode(buf: &[u8]) -> Result<Option<(BackendMessage, usize)>> {
        if buf.len() < 5 {
            return Ok(None);
        }
        let tag = buf[0];
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if len < 4 {
            return Err(Error::Protocol(format!(
                "message length {len} is smaller than the 4-byte length field"
            )));
        }
        let total = 1 + len as usize; // tag byte plus the length-covered region
        if buf.len() < total {
            return Ok(None);
        }
        let body = &buf[5..total];
        let msg = BackendMessage::parse(tag, body)?;
        Ok(Some((msg, total)))
    }

    /// Parse a message body given its already-read type tag.
    pub fn parse(tag: u8, body: &[u8]) -> Result<BackendMessage> {
        let mut r = Reader::new(body);
        let msg = match tag {
            b'R' => {
                let code = r.i32()?;
                let auth = match code {
                    0 => AuthRequest::Ok,
                    3 => AuthRequest::CleartextPassword,
                    5 => {
                        let salt = r.bytes(4)?;
                        AuthRequest::Md5Password {
                            salt: [salt[0], salt[1], salt[2], salt[3]],
                        }
                    }
                    other => AuthRequest::Unsupported(other),
                };
                BackendMessage::Authentication(auth)
            }
            b'S' => {
                let name = r.cstr()?;
                let value = r.cstr()?;
                BackendMessage::ParameterStatus { name, value }
            }
            b'K' => {
                let pid = r.i32()?;
                let secret = r.i32()?;
                BackendMessage::BackendKeyData { pid, secret }
            }
            b'Z' => {
                let status = r.u8()?;
                BackendMessage::ReadyForQuery { status }
            }
            b'T' => {
                let n = r.i16()?;
                if n < 0 {
                    return Err(Error::Protocol("negative field count".into()));
                }
                let mut fields = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let name = r.cstr()?;
                    let table_oid = r.i32()?;
                    let column_id = r.i16()?;
                    let type_oid = r.i32()?;
                    let type_size = r.i16()?;
                    let type_modifier = r.i32()?;
                    let format = r.i16()?;
                    fields.push(FieldDescription {
                        name,
                        table_oid,
                        column_id,
                        type_oid,
                        type_size,
                        type_modifier,
                        format,
                    });
                }
                BackendMessage::RowDescription(fields)
            }
            b'D' => {
                let n = r.i16()?;
                if n < 0 {
                    return Err(Error::Protocol("negative column count".into()));
                }
                let mut cols = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let len = r.i32()?;
                    if len == -1 {
                        cols.push(None);
                    } else if len < 0 {
                        return Err(Error::Protocol(format!("invalid column length {len}")));
                    } else {
                        cols.push(Some(r.bytes(len as usize)?.to_vec()));
                    }
                }
                BackendMessage::DataRow(cols)
            }
            b'C' => {
                let tag = r.cstr()?;
                BackendMessage::CommandComplete { tag }
            }
            b'E' => BackendMessage::ErrorResponse(parse_notice_fields(&mut r)?),
            b'N' => BackendMessage::NoticeResponse(parse_notice_fields(&mut r)?),
            b'1' => BackendMessage::ParseComplete,
            b'2' => BackendMessage::BindComplete,
            b'n' => BackendMessage::NoData,
            b'I' => BackendMessage::EmptyQueryResponse,
            b't' => {
                let n = r.i16()?;
                if n < 0 {
                    return Err(Error::Protocol("negative parameter count".into()));
                }
                let mut oids = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    oids.push(r.i32()?);
                }
                BackendMessage::ParameterDescription(oids)
            }
            other => BackendMessage::Unknown { tag: other },
        };
        Ok(msg)
    }
}

fn parse_notice_fields(r: &mut Reader) -> Result<Vec<NoticeField>> {
    let mut fields = Vec::new();
    loop {
        let code = r.u8()?;
        if code == 0 {
            break;
        }
        let value = r.cstr()?;
        fields.push(NoticeField { code, value });
    }
    Ok(fields)
}
