//! The live connection: TCP transport, the startup handshake, and query
//! execution over both the simple and extended protocols.

use crate::auth::md5_password;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::message::{
    error_code_and_message, AuthRequest, BackendMessage, BindValue, FieldDescription,
    FrontendMessage,
};
use crate::row::Row;
use crate::scram::{ScramClient, MECHANISM};
use crate::types::ToSql;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

/// An open connection to a Postgres server.
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    // Unparsed bytes left over from the last socket read.
    read_buf: Vec<u8>,
    parameters: Vec<(String, String)>,
    backend_pid: i32,
    backend_secret: i32,
    // Ceiling on a server-declared message length, from the Config.
    max_message_len: usize,
}

impl Connection {
    /// Connect, run the startup handshake (including auth), and drain server
    /// parameters until the server reports it is ready for queries.
    pub fn connect(config: &Config) -> Result<Connection> {
        let stream = Connection::open_stream(config)?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(config.read_timeout)?;
        let mut conn = Connection {
            stream,
            read_buf: Vec::new(),
            parameters: Vec::new(),
            backend_pid: 0,
            backend_secret: 0,
            max_message_len: config.max_message_len,
        };
        conn.handshake(config)?;
        Ok(conn)
    }

    /// Open the TCP stream, honouring the configured connect timeout. With a
    /// timeout set, each resolved address is tried with `connect_timeout` so a
    /// silent host cannot block the caller indefinitely.
    fn open_stream(config: &Config) -> Result<TcpStream> {
        match config.connect_timeout {
            None => Ok(TcpStream::connect((config.host.as_str(), config.port))?),
            Some(timeout) => {
                let addrs = (config.host.as_str(), config.port).to_socket_addrs()?;
                let mut last_err = None;
                for addr in addrs {
                    match TcpStream::connect_timeout(&addr, timeout) {
                        Ok(stream) => return Ok(stream),
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(Error::Io(last_err.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no addresses resolved for host",
                    )
                })))
            }
        }
    }

    fn handshake(&mut self, config: &Config) -> Result<()> {
        self.send(&FrontendMessage::Startup {
            user: config.user.clone(),
            database: config.database.clone(),
            params: Vec::new(),
        })?;

        // SCRAM is a multi-round exchange, so its client state lives across loop
        // iterations.
        let mut scram: Option<ScramClient> = None;

        loop {
            match self.read_message()? {
                BackendMessage::Authentication(AuthRequest::Ok) => {}
                BackendMessage::Authentication(AuthRequest::CleartextPassword) => {
                    let pw = self.require_password(config)?;
                    self.send(&FrontendMessage::Password(pw))?;
                }
                BackendMessage::Authentication(AuthRequest::Md5Password { salt }) => {
                    let pw = self.require_password(config)?;
                    let hashed = md5_password(&config.user, &pw, &salt);
                    self.send(&FrontendMessage::Password(hashed))?;
                }
                BackendMessage::Authentication(AuthRequest::Sasl { mechanisms }) => {
                    if !mechanisms.iter().any(|m| m == MECHANISM) {
                        return Err(Error::Auth(format!(
                            "server offered SASL mechanisms {mechanisms:?}; Conduit implements {MECHANISM}"
                        )));
                    }
                    let pw = self.require_password(config)?;
                    let mut client = ScramClient::new(&pw);
                    let client_first = client.client_first();
                    self.send(&FrontendMessage::SaslInitialResponse {
                        mechanism: MECHANISM.to_string(),
                        data: client_first.into_bytes(),
                    })?;
                    scram = Some(client);
                }
                BackendMessage::Authentication(AuthRequest::SaslContinue { data }) => {
                    let client = scram.as_mut().ok_or_else(|| {
                        Error::Auth("server sent SASLContinue before SASL was started".into())
                    })?;
                    let client_final = client.client_final(&data)?;
                    self.send(&FrontendMessage::SaslResponse {
                        data: client_final.into_bytes(),
                    })?;
                }
                BackendMessage::Authentication(AuthRequest::SaslFinal { data }) => {
                    let client = scram.as_ref().ok_or_else(|| {
                        Error::Auth("server sent SASLFinal before SASL was started".into())
                    })?;
                    client.verify_server_final(&data)?;
                }
                BackendMessage::Authentication(AuthRequest::Unsupported(code)) => {
                    return Err(Error::Auth(format!(
                        "unsupported authentication method (code {code}); Conduit implements cleartext, MD5, and SCRAM-SHA-256"
                    )));
                }
                BackendMessage::ParameterStatus { name, value } => {
                    self.parameters.push((name, value));
                }
                BackendMessage::BackendKeyData { pid, secret } => {
                    self.backend_pid = pid;
                    self.backend_secret = secret;
                }
                BackendMessage::NoticeResponse(_)
                | BackendMessage::NotificationResponse { .. }
                | BackendMessage::Unknown { .. } => {}
                BackendMessage::ReadyForQuery { .. } => return Ok(()),
                BackendMessage::ErrorResponse(fields) => return Err(db_error(&fields)),
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected message during handshake: {other:?}"
                    )))
                }
            }
        }
    }

    fn require_password(&self, config: &Config) -> Result<String> {
        config
            .password
            .as_deref()
            .map(|p| p.to_string())
            .ok_or_else(|| {
                Error::Auth("server requested a password but none was configured".into())
            })
    }

    /// Run a single-statement simple query and collect its result rows.
    ///
    /// The simple protocol allows several statements separated by `;` in one
    /// message, and Postgres then returns one result set per statement. This
    /// method flattens whatever comes back into a single `Vec<Row>`, which is
    /// correct for a single statement but would merge the sets of a
    /// multi-statement query. Use [`Connection::simple_query_multi`] to keep the
    /// per-statement sets separate.
    pub fn simple_query(&mut self, sql: &str) -> Result<Vec<Row>> {
        Ok(self.simple_query_multi(sql)?.into_iter().flatten().collect())
    }

    /// Run a simple query that may contain several `;`-separated statements and
    /// return one result set per statement, in order. Each `CommandComplete`
    /// closes a set, so `SELECT 1; SELECT 2` yields two distinct sets rather than
    /// one merged list.
    pub fn simple_query_multi(&mut self, sql: &str) -> Result<Vec<Vec<Row>>> {
        self.send(&FrontendMessage::Query(sql.to_string()))?;
        self.collect_result_sets()
    }

    /// Run `sql` with the extended protocol, binding `params` as text-format
    /// values. Parameters travel as data, never as SQL text, so a value can
    /// never be reinterpreted as query syntax.
    pub fn query(&mut self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        let bind_values: Vec<BindValue> = params.iter().map(|p| p.to_sql()).collect();
        self.send(&FrontendMessage::Parse {
            statement: String::new(),
            query: sql.to_string(),
            param_types: Vec::new(),
        })?;
        self.send(&FrontendMessage::Bind {
            portal: String::new(),
            statement: String::new(),
            params: bind_values,
        })?;
        self.send(&FrontendMessage::Describe {
            kind: b'P',
            name: String::new(),
        })?;
        self.send(&FrontendMessage::Execute {
            portal: String::new(),
            max_rows: 0,
        })?;
        self.send(&FrontendMessage::Sync)?;
        Ok(self
            .collect_result_sets()?
            .into_iter()
            .flatten()
            .collect())
    }

    /// Read messages until ReadyForQuery, partitioning rows into one set per
    /// statement. Each `CommandComplete` (or `EmptyQueryResponse`) closes the
    /// current set, so multi-statement simple queries keep their sets separate.
    /// Any `ErrorResponse` is surfaced as `Error::Db` once the stream drains.
    fn collect_result_sets(&mut self) -> Result<Vec<Vec<Row>>> {
        let mut sets: Vec<Vec<Row>> = Vec::new();
        let mut columns: Option<Arc<Vec<FieldDescription>>> = None;
        let mut current: Vec<Row> = Vec::new();
        let mut pending_error: Option<Error> = None;

        loop {
            match self.read_message()? {
                BackendMessage::RowDescription(fields) => {
                    columns = Some(Arc::new(fields));
                }
                BackendMessage::DataRow(values) => {
                    let cols = columns.clone().ok_or_else(|| {
                        Error::Protocol("DataRow arrived before RowDescription".into())
                    })?;
                    current.push(Row::new(cols, values));
                }
                BackendMessage::CommandComplete { .. }
                | BackendMessage::EmptyQueryResponse => {
                    // A statement finished: close its result set.
                    sets.push(std::mem::take(&mut current));
                    columns = None;
                }
                BackendMessage::ParseComplete
                | BackendMessage::BindComplete
                | BackendMessage::NoData
                | BackendMessage::ParameterDescription(_)
                | BackendMessage::NoticeResponse(_)
                | BackendMessage::NotificationResponse { .. }
                | BackendMessage::Unknown { .. } => {}
                BackendMessage::ParameterStatus { name, value } => {
                    // A SET or similar can push a fresh parameter mid-stream.
                    self.parameters.push((name, value));
                }
                BackendMessage::ErrorResponse(fields) => {
                    pending_error = Some(db_error(&fields));
                }
                BackendMessage::ReadyForQuery { .. } => break,
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected message during query: {other:?}"
                    )))
                }
            }
        }

        // Defensive: a valid server always sends CommandComplete before
        // ReadyForQuery, but never drop rows if it did not.
        if !current.is_empty() {
            sets.push(current);
        }

        match pending_error {
            Some(e) => Err(e),
            None => Ok(sets),
        }
    }

    /// Send Terminate and close the socket. Best effort; ignores write errors.
    pub fn close(mut self) {
        let _ = self.send(&FrontendMessage::Terminate);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Server parameters reported during startup (server_version, etc.).
    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    pub fn backend_pid(&self) -> i32 {
        self.backend_pid
    }

    fn send(&mut self, msg: &FrontendMessage) -> Result<()> {
        let bytes = msg.encode();
        self.stream.write_all(&bytes)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Pull exactly one backend message, reading from the socket as needed and
    /// coping with messages split across reads.
    fn read_message(&mut self) -> Result<BackendMessage> {
        loop {
            if let Some((msg, consumed)) =
                BackendMessage::decode_with_cap(&self.read_buf, self.max_message_len)?
            {
                self.read_buf.drain(0..consumed);
                return Ok(msg);
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(Error::Protocol(
                    "server closed the connection unexpectedly".into(),
                ));
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }
}

fn db_error(fields: &[crate::message::NoticeField]) -> Error {
    let (code, message) = error_code_and_message(fields);
    Error::Db { code, message }
}
