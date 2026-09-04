//! Type OIDs and the conversions between Postgres text-format bytes and Rust
//! values. Conduit reads and writes everything in the text format, so decoding
//! is "parse this ASCII" and encoding is "format this value as ASCII".

use crate::error::{Error, Result};
use crate::message::BindValue;

// The handful of built-in OIDs Conduit understands. Values are stable Postgres
// catalog OIDs (see pg_type).
pub const OID_BOOL: i32 = 16;
pub const OID_INT8: i32 = 20;
pub const OID_INT2: i32 = 21;
pub const OID_INT4: i32 = 23;
pub const OID_TEXT: i32 = 25;
pub const OID_FLOAT4: i32 = 700;
pub const OID_FLOAT8: i32 = 701;
pub const OID_BPCHAR: i32 = 1042;
pub const OID_VARCHAR: i32 = 1043;

/// Decode a text-format column value into a Rust type.
pub trait FromSql: Sized {
    /// `oid` is the column's Postgres type, `raw` its text-format bytes.
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self>;

    /// Called for a SQL NULL column. The default rejects it; wrap the type in
    /// `Option<T>` to accept NULL as `None`.
    fn from_sql_null() -> Result<Self> {
        Err(Error::Decode("unexpected NULL value in non-nullable column".into()))
    }
}

/// `None` for a SQL NULL, `Some(decoded)` otherwise.
impl<T: FromSql> FromSql for Option<T> {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        Ok(Some(T::from_sql(oid, raw)?))
    }

    fn from_sql_null() -> Result<Self> {
        Ok(None)
    }
}

fn as_str(raw: &[u8]) -> Result<&str> {
    std::str::from_utf8(raw).map_err(|_| Error::Decode("column value is not valid UTF-8".into()))
}

fn mismatch(oid: i32, want: &str) -> Error {
    Error::Decode(format!(
        "column type oid {oid} cannot be read as {want}"
    ))
}

impl FromSql for String {
    // The permissive default: any column comes back as its text rendering.
    fn from_sql(_oid: i32, raw: &[u8]) -> Result<Self> {
        Ok(as_str(raw)?.to_string())
    }
}

impl FromSql for bool {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        if oid != OID_BOOL {
            return Err(mismatch(oid, "bool"));
        }
        match raw {
            b"t" => Ok(true),
            b"f" => Ok(false),
            _ => Err(Error::Decode(format!(
                "invalid bool text {:?}",
                as_str(raw).unwrap_or("<non-utf8>")
            ))),
        }
    }
}

impl FromSql for i16 {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        if !matches!(oid, OID_INT2 | OID_INT4 | OID_INT8) {
            return Err(mismatch(oid, "i16"));
        }
        as_str(raw)?
            .parse()
            .map_err(|_| Error::Decode(format!("cannot parse {:?} as i16", as_str(raw))))
    }
}

impl FromSql for i32 {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        if !matches!(oid, OID_INT2 | OID_INT4 | OID_INT8) {
            return Err(mismatch(oid, "i32"));
        }
        as_str(raw)?
            .parse()
            .map_err(|_| Error::Decode(format!("cannot parse {:?} as i32", as_str(raw))))
    }
}

impl FromSql for i64 {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        if !matches!(oid, OID_INT2 | OID_INT4 | OID_INT8) {
            return Err(mismatch(oid, "i64"));
        }
        as_str(raw)?
            .parse()
            .map_err(|_| Error::Decode(format!("cannot parse {:?} as i64", as_str(raw))))
    }
}

impl FromSql for f32 {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        if !matches!(oid, OID_FLOAT4 | OID_FLOAT8 | OID_INT2 | OID_INT4 | OID_INT8) {
            return Err(mismatch(oid, "f32"));
        }
        as_str(raw)?
            .parse()
            .map_err(|_| Error::Decode(format!("cannot parse {:?} as f32", as_str(raw))))
    }
}

impl FromSql for f64 {
    fn from_sql(oid: i32, raw: &[u8]) -> Result<Self> {
        if !matches!(oid, OID_FLOAT4 | OID_FLOAT8 | OID_INT2 | OID_INT4 | OID_INT8) {
            return Err(mismatch(oid, "f64"));
        }
        as_str(raw)?
            .parse()
            .map_err(|_| Error::Decode(format!("cannot parse {:?} as f64", as_str(raw))))
    }
}

/// Encode a Rust value as a text-format bind parameter. Because the value goes
/// out as data in a Bind message and never as SQL text, parameters cannot be
/// interpreted as query syntax.
pub trait ToSql {
    fn to_sql(&self) -> BindValue;
}

impl ToSql for i16 {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.to_string())
    }
}

impl ToSql for i32 {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.to_string())
    }
}

impl ToSql for i64 {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.to_string())
    }
}

impl ToSql for f32 {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.to_string())
    }
}

impl ToSql for f64 {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.to_string())
    }
}

impl ToSql for bool {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(if *self { "t".into() } else { "f".into() })
    }
}

impl ToSql for str {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.to_string())
    }
}

impl ToSql for String {
    fn to_sql(&self) -> BindValue {
        BindValue::Text(self.clone())
    }
}

impl ToSql for &str {
    fn to_sql(&self) -> BindValue {
        BindValue::Text((*self).to_string())
    }
}

/// `None` binds a SQL NULL; `Some(v)` binds `v`.
impl<T: ToSql> ToSql for Option<T> {
    fn to_sql(&self) -> BindValue {
        match self {
            Some(v) => v.to_sql(),
            None => BindValue::Null,
        }
    }
}
