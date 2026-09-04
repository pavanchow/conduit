//! Error type for the whole crate.

use std::fmt;

/// Anything that can go wrong talking to Postgres.
#[derive(Debug)]
pub enum Error {
    /// An I/O failure on the underlying socket.
    Io(std::io::Error),
    /// The bytes on the wire did not parse as a valid protocol message.
    Protocol(String),
    /// The server sent an ErrorResponse. `code` is the five-character SQLSTATE.
    Db { code: String, message: String },
    /// Authentication failed or an auth method we do not support was requested.
    Auth(String),
    /// A column could not be decoded into the requested Rust type.
    Decode(String),
    /// A column name or index that does not exist on the row.
    ColumnNotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Db { code, message } => write!(f, "db error [{code}]: {message}"),
            Error::Auth(m) => write!(f, "auth error: {m}"),
            Error::Decode(m) => write!(f, "decode error: {m}"),
            Error::ColumnNotFound(m) => write!(f, "column not found: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
