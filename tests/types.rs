//! Text-format type decoding: OID-driven conversion into Rust types, NULL as
//! Option, and clear errors on type mismatch.

use conduit::types::{
    FromSql, OID_BOOL, OID_FLOAT8, OID_INT2, OID_INT4, OID_INT8, OID_TEXT, OID_VARCHAR,
};

#[test]
fn integers_decode() {
    assert_eq!(i16::from_sql(OID_INT2, b"32000").unwrap(), 32000);
    assert_eq!(i32::from_sql(OID_INT4, b"2147483647").unwrap(), 2147483647);
    assert_eq!(
        i64::from_sql(OID_INT8, b"9223372036854775807").unwrap(),
        9223372036854775807
    );
    assert_eq!(i32::from_sql(OID_INT4, b"-5").unwrap(), -5);
}

#[test]
fn floats_decode() {
    assert_eq!(f64::from_sql(OID_FLOAT8, b"3.5").unwrap(), 3.5);
    assert_eq!(f64::from_sql(OID_FLOAT8, b"-1.25").unwrap(), -1.25);
    // An integer column can widen into a float.
    assert_eq!(f64::from_sql(OID_INT4, b"7").unwrap(), 7.0);
}

#[test]
fn bools_decode() {
    assert!(bool::from_sql(OID_BOOL, b"t").unwrap());
    assert!(!bool::from_sql(OID_BOOL, b"f").unwrap());
    assert!(bool::from_sql(OID_BOOL, b"x").is_err());
}

#[test]
fn text_decodes_and_is_the_default() {
    assert_eq!(String::from_sql(OID_TEXT, b"hello").unwrap(), "hello");
    assert_eq!(String::from_sql(OID_VARCHAR, b"world").unwrap(), "world");
    // Any oid renders as text under the permissive String default.
    assert_eq!(String::from_sql(OID_INT4, b"42").unwrap(), "42");
}

#[test]
fn type_mismatch_is_a_clear_error() {
    // Asking for an int from a text column must fail, not silently misparse.
    let err = i32::from_sql(OID_TEXT, b"42").unwrap_err();
    assert!(err.to_string().contains("cannot be read as i32"));

    let err = bool::from_sql(OID_INT4, b"1").unwrap_err();
    assert!(err.to_string().contains("cannot be read as bool"));
}

#[test]
fn null_requires_option() {
    // A non-nullable type rejects NULL...
    assert!(i32::from_sql_null().is_err());
    // ...while Option<T> accepts it as None.
    assert_eq!(<Option<i32> as FromSql>::from_sql_null().unwrap(), None);
    // And a present value comes through as Some.
    assert_eq!(
        <Option<i32> as FromSql>::from_sql(OID_INT4, b"9").unwrap(),
        Some(9)
    );
}
