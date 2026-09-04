# Conduit

A from-scratch PostgreSQL driver you can read end to end. Conduit speaks the real
v3 wire protocol over a plain TCP socket, from the startup handshake to typed
result rows, with no ORM, no libpq, no C bindings, and zero external
dependencies. Even the cryptography is written by hand: MD5, SHA-256,
HMAC-SHA-256, PBKDF2, and base64 all live in the tree so SCRAM-SHA-256 auth
needs nothing from outside.

Most people reach a database through a driver they never open. Conduit is the
opposite: the whole path is here in a few hundred lines of Rust, each protocol
message its own readable type, so you can trace a query from the bytes on the
wire up to `row.get::<i32>("id")`.

Conduit is the client side of the same story as
[Ledgerstone](https://github.com/pavanchow), Pavan's SQL engine. Ledgerstone
answers "how does a database run a query". Conduit answers "how does a program
talk to one".

## What it does

- Encodes every frontend message and decodes every backend message of the
  Postgres v3 protocol, each as its own type, with bounded parsing that returns
  a protocol error instead of panicking on a malformed length or a short buffer.
- Rejects a server-declared message length above a configurable cap (default
  64 MiB) before buffering a single body byte, so a hostile server cannot drive
  the client to OOM by announcing a multi-gigabyte frame. Connect and read
  timeouts (defaults 10s and 30s) keep a stalled or silent server from pinning
  the client.
- Authenticates with cleartext, MD5, or SCRAM-SHA-256, the default since
  PostgreSQL 14. The MD5 scheme
  (`"md5" + hex(md5(hex(md5(password + user)) + salt))`) is built on a
  hand-written RFC 1321 MD5. SCRAM runs the full RFC 5802 / RFC 7677 exchange
  (client-first, server-first, client-final, server-final) on hand-written
  SHA-256, HMAC-SHA-256, PBKDF2, and base64, and it verifies the server
  signature before trusting the connection.
- Runs queries two ways: the simple `Query` protocol, and the extended
  `Parse`/`Bind`/`Describe`/`Execute`/`Sync` protocol with text-format
  parameters, so a parameter is always data and never SQL.
- Keeps multi-statement result sets separate. A simple query may hold several
  `;`-separated statements, and `simple_query_multi` returns one result set per
  statement rather than merging them. `simple_query` flattens the result and is
  meant for a single statement.
- Tolerates asynchronous `NotificationResponse` and unknown message tags
  mid-stream, skipping them by length so a `NOTIFY` never breaks a query.
- Decodes text-format columns by their type OID into `i16`/`i32`/`i64`/`f32`/
  `f64`/`bool`/`String`, with `NULL` as `Option` and a clear error on type
  mismatch.
- Surfaces a server `ErrorResponse` as a structured `Error::Db { code, message }`.

## A taste

```rust
use conduit::{Config, Connection};

let cfg = Config::from_url("postgres://user:pass@localhost:5432/app")?;
let mut conn = Connection::connect(&cfg)?;

for row in conn.query("SELECT id, name FROM users WHERE id = $1", &[&7i32])? {
    let id: i32 = row.get("id")?;
    let name: String = row.get("name")?;
    println!("{id} {name}");
}
# Ok::<(), conduit::Error>(())
```

## Testable with no database

The hard part of a wire-protocol driver is proving it without standing up a
server. Conduit does it two ways:

1. **Golden byte vectors.** Every message is asserted against the exact bytes it
   must produce on the wire, and every backend message is decoded from a
   captured-style byte sequence (a full RowDescription, DataRow, CommandComplete,
   ReadyForQuery run, plus the auth messages and an ErrorResponse). Frontend
   messages round-trip: `decode(encode(x)) == x`.
2. **An in-process mock server.** A real `TcpListener` on `127.0.0.1:0` speaks
   enough of the protocol to script a session. The integration test runs the
   actual driver against it over real TCP and checks the whole stack: the
   handshake completes, MD5 and SCRAM-SHA-256 auth each succeed with the right
   password and fail cleanly with the wrong one (SCRAM also fails on a bad server
   signature), a `SELECT` returns typed rows including a `NULL`, a parameterized
   query round-trips its params, a multi-statement query keeps its result sets
   separate, and a bad query surfaces as `Error::Db` with the right SQLSTATE.

Because the mock encodes backend messages by hand while the driver decodes them
(and vice versa for frontend messages), the two halves cross-check each other.

## Try it

```
cargo test                                  # golden vectors + mock integration
cargo run -- demo                           # a scripted session, no database needed
cargo run -- query postgres://u:p@host/db "SELECT 1 AS one"
```

An optional real-Postgres smoke test runs only when `CONDUIT_PG_URL` is set, so
CI stays green without a database:

```
CONDUIT_PG_URL=postgres://user:pass@localhost:5432/db cargo test
```

## Non-goals

Conduit is a readable core, honest about its edges. It does not implement:

- **TLS.** Connections are plaintext TCP. There is no `SSLRequest` negotiation.
- **The binary result format.** Conduit requests text for every column and
  parameter. Text decoding is the readable path and sidesteps per-type binary
  layouts.
- **Connection pooling, prepared-statement caching, COPY, a full LISTEN/NOTIFY
  subscription API, pipelining, and async.** The API is synchronous and one
  query at a time. A `NotificationResponse` that arrives is tolerated and
  skipped, but there is no channel to deliver it to.

## Layout

```
src/message.rs     the protocol codec (encode frontend, decode backend)
src/md5.rs         hand-written RFC 1321 MD5
src/sha256.rs      hand-written SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256
src/base64.rs      hand-written RFC 4648 base64
src/scram.rs       the SCRAM-SHA-256 client exchange
src/auth.rs        the Postgres MD5 password scheme
src/types.rs       OID-driven text decoding, ToSql / FromSql
src/row.rs         typed row access by index or name
src/config.rs      connection config and postgres:// URL parsing
src/connection.rs  the socket, the handshake, query execution
src/mock.rs        the in-process test server
src/error.rs       the crate error type
src/main.rs        the conduit CLI (query, demo)
tests/             golden vectors, mock integration, type decoding
docs/index.html    a live protocol visualizer (the codec, ported to JS)
```

Author: Pavan Nallamothu (pavanchow). License: MIT.
