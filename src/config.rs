//! Connection configuration and a small parser for `postgres://` URLs.

use crate::error::{Error, Result};

/// Everything needed to open a connection.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: String,
}

impl Config {
    /// A config with sensible Postgres defaults; fill in what you need.
    pub fn new() -> Self {
        Config {
            host: "localhost".into(),
            port: 5432,
            user: "postgres".into(),
            password: None,
            database: "postgres".into(),
        }
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn database(mut self, database: impl Into<String>) -> Self {
        self.database = database.into();
        self
    }

    /// Parse a `postgres://user:password@host:port/database` URL.
    ///
    /// The scheme may be `postgres` or `postgresql`. User, password, port and
    /// database all fall back to the Postgres defaults when omitted. This is a
    /// deliberately small parser: no query parameters, no percent-decoding of
    /// exotic escapes beyond the common `%XX` case.
    pub fn from_url(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
            .ok_or_else(|| {
                Error::Protocol("url must start with postgres:// or postgresql://".into())
            })?;

        // Split credentials from the host section on the last '@' before any '/'.
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };

        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
            None => (None, authority),
        };

        let mut cfg = Config::new();

        if let Some(userinfo) = userinfo {
            match userinfo.split_once(':') {
                Some((u, p)) => {
                    if !u.is_empty() {
                        cfg.user = percent_decode(u);
                    }
                    cfg.password = Some(percent_decode(p));
                }
                None => {
                    if !userinfo.is_empty() {
                        cfg.user = percent_decode(userinfo);
                    }
                }
            }
        }

        if !hostport.is_empty() {
            match hostport.split_once(':') {
                Some((h, p)) => {
                    if !h.is_empty() {
                        cfg.host = h.to_string();
                    }
                    cfg.port = p
                        .parse()
                        .map_err(|_| Error::Protocol(format!("invalid port: {p}")))?;
                }
                None => cfg.host = hostport.to_string(),
            }
        }

        // Strip a query string if present, then take the database name.
        let db = path.split('?').next().unwrap_or("");
        if !db.is_empty() {
            cfg.database = percent_decode(db);
        }

        Ok(cfg)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}

/// Decode `%XX` escapes; leaves any malformed escape untouched.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_url() {
        let c = Config::from_url("postgres://alice:pw@db.example.com:6543/shop").unwrap();
        assert_eq!(c.user, "alice");
        assert_eq!(c.password.as_deref(), Some("pw"));
        assert_eq!(c.host, "db.example.com");
        assert_eq!(c.port, 6543);
        assert_eq!(c.database, "shop");
    }

    #[test]
    fn defaults_fill_in() {
        let c = Config::from_url("postgres://localhost/mydb").unwrap();
        assert_eq!(c.user, "postgres");
        assert_eq!(c.password, None);
        assert_eq!(c.port, 5432);
        assert_eq!(c.database, "mydb");
    }

    #[test]
    fn percent_decoded_password() {
        let c = Config::from_url("postgres://u:p%40ss@h/d").unwrap();
        assert_eq!(c.password.as_deref(), Some("p@ss"));
    }

    #[test]
    fn rejects_bad_scheme() {
        assert!(Config::from_url("mysql://x/y").is_err());
    }
}
