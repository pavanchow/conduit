//! End-to-end: the real driver drives the in-process mock server over real TCP.
//! This proves the whole stack (handshake, MD5 auth, simple + extended queries,
//! typed row decoding, and ErrorResponse handling) without a database.

use conduit::mock::{MockConfig, MockServer};
use conduit::{Config, Connection, Error};

fn config_for(server: &MockServer) -> Config {
    Config::new()
        .host(server.host())
        .port(server.port())
        .user("conduit")
        .database("test")
}

#[test]
fn handshake_and_typed_select() {
    let server = MockServer::start(MockConfig::default()).unwrap();
    let mut conn = Connection::connect(&config_for(&server)).unwrap();

    // Startup drained the server parameters.
    assert!(conn
        .parameters()
        .iter()
        .any(|(k, _)| k == "server_version"));

    let rows = conn.simple_query("SELECT * FROM people").unwrap();
    assert_eq!(rows.len(), 2);

    // Row 0: id=1, name="alice", score=3.5, active=true, note=NULL.
    let r0 = &rows[0];
    assert_eq!(r0.get::<i32, _>("id").unwrap(), 1);
    assert_eq!(r0.get::<i64, _>("id").unwrap(), 1);
    assert_eq!(r0.get::<String, _>("name").unwrap(), "alice");
    assert_eq!(r0.get::<f64, _>("score").unwrap(), 3.5);
    assert!(r0.get::<bool, _>("active").unwrap());
    assert_eq!(r0.get::<Option<String>, _>("note").unwrap(), None);

    // Row 1: note is present.
    let r1 = &rows[1];
    assert_eq!(r1.get::<i32, _>("id").unwrap(), 2);
    assert!(!r1.get::<bool, _>("active").unwrap());
    assert_eq!(
        r1.get::<Option<String>, _>("note").unwrap(),
        Some("hi".to_string())
    );

    // Access by index works too.
    assert_eq!(r1.get::<String, _>(1).unwrap(), "bob");

    conn.close();
}

#[test]
fn md5_auth_succeeds_with_right_password() {
    let server = MockServer::start(MockConfig {
        md5_password: Some("hunter2".into()),
        ..Default::default()
    })
    .unwrap();
    let cfg = config_for(&server).password("hunter2");
    let mut conn = Connection::connect(&cfg).unwrap();
    let rows = conn.simple_query("SELECT * FROM people").unwrap();
    assert_eq!(rows.len(), 2);
    conn.close();
}

#[test]
fn md5_auth_fails_with_wrong_password() {
    let server = MockServer::start(MockConfig {
        md5_password: Some("hunter2".into()),
        ..Default::default()
    })
    .unwrap();
    let cfg = config_for(&server).password("wrong-password");
    let err = Connection::connect(&cfg).unwrap_err();
    match err {
        Error::Db { code, .. } => assert_eq!(code, "28P01"),
        other => panic!("expected auth failure, got {other:?}"),
    }
}

#[test]
fn parameterized_query_round_trips_params() {
    let server = MockServer::start(MockConfig::default()).unwrap();
    let mut conn = Connection::connect(&config_for(&server)).unwrap();

    let rows = conn
        .query(
            "SELECT $1, $2, $3",
            &[&42i32, &"hello", &Option::<String>::None],
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    // The mock echoes bound params back as text columns.
    assert_eq!(row.get::<String, _>(0).unwrap(), "42");
    assert_eq!(row.get::<String, _>(1).unwrap(), "hello");
    assert_eq!(row.get::<Option<String>, _>(2).unwrap(), None);

    conn.close();
}

#[test]
fn error_response_surfaces_as_db_error() {
    let server = MockServer::start(MockConfig::default()).unwrap();
    let mut conn = Connection::connect(&config_for(&server)).unwrap();

    let err = conn.simple_query("SELECT boom").unwrap_err();
    match err {
        Error::Db { code, message } => {
            assert_eq!(code, "42601");
            assert!(message.contains("boom"));
        }
        other => panic!("expected Error::Db, got {other:?}"),
    }

    // The connection is still usable after an error (server sent ReadyForQuery).
    let rows = conn.simple_query("SELECT * FROM people").unwrap();
    assert_eq!(rows.len(), 2);

    conn.close();
}

#[test]
fn scram_auth_succeeds_with_right_password() {
    let server = MockServer::start(MockConfig {
        scram_password: Some("pencil".into()),
        ..Default::default()
    })
    .unwrap();
    let cfg = config_for(&server).password("pencil");
    let mut conn = Connection::connect(&cfg).unwrap();
    let rows = conn.simple_query("SELECT * FROM people").unwrap();
    assert_eq!(rows.len(), 2);
    conn.close();
}

#[test]
fn scram_auth_fails_with_wrong_password() {
    let server = MockServer::start(MockConfig {
        scram_password: Some("pencil".into()),
        ..Default::default()
    })
    .unwrap();
    let cfg = config_for(&server).password("wrong");
    let err = Connection::connect(&cfg).unwrap_err();
    match err {
        // The mock rejects the proof with SQLSTATE 28P01.
        Error::Db { code, .. } => assert_eq!(code, "28P01"),
        Error::Auth(_) => {}
        other => panic!("expected auth failure, got {other:?}"),
    }
}

#[test]
fn scram_auth_fails_on_bad_server_signature() {
    let server = MockServer::start(MockConfig {
        scram_password: Some("pencil".into()),
        scram_bad_server_signature: true,
        ..Default::default()
    })
    .unwrap();
    let cfg = config_for(&server).password("pencil");
    let err = Connection::connect(&cfg).unwrap_err();
    match err {
        Error::Auth(m) => assert!(m.contains("signature")),
        other => panic!("expected Error::Auth on bad server signature, got {other:?}"),
    }
}

#[test]
fn notification_before_ready_does_not_break_query() {
    let server = MockServer::start(MockConfig::default()).unwrap();
    let mut conn = Connection::connect(&config_for(&server)).unwrap();
    // The mock prepends a NotificationResponse ('A') to this query's stream.
    let rows = conn.simple_query("SELECT notify").unwrap();
    assert_eq!(rows.len(), 2);
    conn.close();
}

#[test]
fn multi_statement_query_keeps_result_sets_separate() {
    let server = MockServer::start(MockConfig::default()).unwrap();
    let mut conn = Connection::connect(&config_for(&server)).unwrap();
    // The mock emits two result groups (1 row, then 2 rows) before ReadyForQuery.
    let sets = conn.simple_query_multi("SELECT multi").unwrap();
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].len(), 1);
    assert_eq!(sets[1].len(), 2);
    assert_eq!(sets[0][0].get::<i32, _>(0).unwrap(), 1);
    assert_eq!(sets[1][0].get::<i32, _>(0).unwrap(), 2);
    assert_eq!(sets[1][1].get::<i32, _>(0).unwrap(), 3);
    conn.close();
}

#[test]
fn hostile_startup_bytes_do_not_panic_the_server() {
    use std::io::Write;
    use std::net::TcpStream;

    let server = MockServer::start(MockConfig::default()).unwrap();

    // A startup frame with length 0 would underflow `len - 4` and try to
    // allocate ~usize::MAX bytes in the naive mock; it must be handled cleanly.
    let mut raw = TcpStream::connect(server.addr).unwrap();
    raw.write_all(&[0, 0, 0, 0]).unwrap();
    let _ = raw.write_all(&[0xde, 0xad, 0xbe, 0xef]);
    drop(raw);

    // The accept loop and other connection threads are unaffected: a fresh
    // normal connection still completes a query.
    let mut conn = Connection::connect(&config_for(&server)).unwrap();
    let rows = conn.simple_query("SELECT * FROM people").unwrap();
    assert_eq!(rows.len(), 2);
    conn.close();
}

/// Optional smoke test against a real Postgres. Skipped (returns early) unless
/// CONDUIT_PG_URL is set, e.g. postgres://user:pass@localhost:5432/db, so CI
/// stays green without a database.
#[test]
fn real_postgres_smoke() {
    let url = match std::env::var("CONDUIT_PG_URL") {
        Ok(u) => u,
        Err(_) => return, // no database configured; nothing to prove here
    };
    let cfg = Config::from_url(&url).unwrap();
    let mut conn = Connection::connect(&cfg).unwrap();

    let rows = conn.simple_query("SELECT 1 AS one, 'hi'::text AS greeting").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<i32, _>("one").unwrap(), 1);
    assert_eq!(rows[0].get::<String, _>("greeting").unwrap(), "hi");

    let rows = conn.query("SELECT $1::int + $2::int AS sum", &[&20i32, &22i32]).unwrap();
    assert_eq!(rows[0].get::<i32, _>("sum").unwrap(), 42);

    conn.close();
}
