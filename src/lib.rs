//! Conduit is a from-scratch PostgreSQL driver. It speaks the real v3 wire
//! protocol over a plain TCP socket, from the startup handshake through typed
//! result rows, with zero external dependencies and hand-written MD5.
//!
//! The reading order that matches the design:
//!   - [`message`]: the protocol codec (encode frontend, decode backend).
//!   - [`md5`] and [`auth`]: hand-written MD5 and the Postgres password scheme.
//!   - [`types`] and [`row`]: OID-driven text decoding and typed row access.
//!   - [`connection`]: the socket, the handshake, and query execution.
//!   - [`mock`]: an in-process server that makes the whole stack testable with
//!     no database.
//!
//! ```no_run
//! use conduit::{Config, Connection};
//!
//! let cfg = Config::new().user("postgres").password("secret").database("app");
//! let mut conn = Connection::connect(&cfg)?;
//! for row in conn.query("SELECT id, name FROM users WHERE id = $1", &[&7i32])? {
//!     let id: i32 = row.get("id")?;
//!     let name: String = row.get("name")?;
//!     println!("{id} {name}");
//! }
//! # Ok::<(), conduit::Error>(())
//! ```

pub mod auth;
pub mod base64;
pub mod config;
pub mod connection;
pub mod error;
pub mod md5;
pub mod message;
pub mod mock;
pub mod row;
pub mod scram;
pub mod sha256;
pub mod types;

pub use config::Config;
pub use connection::Connection;
pub use error::{Error, Result};
pub use row::Row;
pub use types::{FromSql, ToSql};
