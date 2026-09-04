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
use crate::types::ToSql;
use std::io::{Read, Write};
use std::net::TcpStream;
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
}

impl Connection {
    /// Connect, run the startup handshake (including auth), and drain server
    /// parameters until the server reports it is ready for queries.
    pub fn connect(config: &Config) -> Result<Connection> {
        let stream = TcpStream::connect((config.host.as_str(), config.port))?;
        stream.set_nodelay(true).ok();
        let mut conn = Connection {
            stream,
            read_buf: Vec::new(),
            parameters: Vec::new(),
            backend_pid: 0,
            backend_secret: 0,
        };
        conn.handshake(config)?;
        Ok(conn)
    }

    fn handshake(&mut self, config: &Config) -> Result<()> {
        self.send(&FrontendMessage::Startup {
            user: config.user.clone(),
            database: config.database.clone(),
            params: Vec::new(),
        })?;

        loop {
            match self.read_message()? {
                BackendMessage::Authentication(AuthRequest::Ok) => {}
                BackendMessage::Authentication(AuthRequest::CleartextPassword) => {
                    let pw = config.password.as_deref().ok_or_else(|| {
                        Error::Auth("server requested a password but none was configured".into())
                    })?;
                    self.send(&FrontendMessage::Password(pw.to_string()))?;
                }
                BackendMessage::Authentication(AuthRequest::Md5Password { salt }) => {
                    let pw = config.password.as_deref().ok_or_else(|| {
                        Error::Auth("server requested a password but none was configured".into())
                    })?;
                    let hashed = md5_password(&config.user, pw, &salt);
                    self.send(&FrontendMessage::Password(hashed))?;
                }
                BackendMessage::Authentication(AuthRequest::Unsupported(code)) => {
                    return Err(Error::Auth(format!(
                        "unsupported authentication method (code {code}); Conduit implements cleartext and MD5 only"
                    )));
                }
                BackendMessage::ParameterStatus { name, value } => {
                    self.parameters.push((name, value));
                }
                BackendMessage::BackendKeyData { pid, secret } => {
                    self.backend_pid = pid;
                    self.backend_secret = secret;
                }
                BackendMessage::NoticeResponse(_) => {}
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

    /// Run `sql` with the simple Query protocol and collect the result rows.
    pub fn simple_query(&mut self, sql: &str) -> Result<Vec<Row>> {
        self.send(&FrontendMessage::Query(sql.to_string()))?;
        self.collect_results()
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
        self.collect_results()
    }

    /// Read messages until ReadyForQuery, assembling rows and surfacing any
    /// ErrorResponse as `Error::Db`.
    fn collect_results(&mut self) -> Result<Vec<Row>> {
        let mut columns: Option<Arc<Vec<FieldDescription>>> = None;
        let mut rows: Vec<Row> = Vec::new();
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
                    rows.push(Row::new(cols, values));
                }
                BackendMessage::CommandComplete { .. }
                | BackendMessage::EmptyQueryResponse
                | BackendMessage::ParseComplete
                | BackendMessage::BindComplete
                | BackendMessage::NoData
                | BackendMessage::ParameterDescription(_)
                | BackendMessage::NoticeResponse(_) => {}
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

        match pending_error {
            Some(e) => Err(e),
            None => Ok(rows),
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
            if let Some((msg, consumed)) = BackendMessage::decode(&self.read_buf)? {
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
