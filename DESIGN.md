# Conduit design

## The gap

A database driver is the one piece of the stack almost nobody reads. You import
it, call `.query()`, and the bytes on the wire stay invisible. Conduit exists to
make that path readable: a PostgreSQL driver that speaks the real v3 wire
protocol from the startup handshake to typed rows, with no ORM, no libpq, no C
bindings, and zero external dependencies. Every primitive authentication needs
is written by hand rather than pulled from a crate: MD5 for the legacy scheme,
and SHA-256, HMAC-SHA-256, PBKDF2, and base64 for SCRAM-SHA-256.

It is the client-side companion to Ledgerstone, a SQL engine. Ledgerstone shows
how a database answers a query. Conduit shows how a program asks one. Together
they cover both ends of the same conversation.

## Shape

The code is layered so each file answers one question.

- `message.rs` is the heart: pure functions over bytes, no sockets. Every
  frontend message knows how to encode itself and every backend message knows
  how to decode itself. Because it is pure, it is exhaustively testable with
  fixed byte vectors.
- `md5.rs`, `sha256.rs`, `base64.rs`, `scram.rs`, and `auth.rs` sit underneath:
  the RFC 1321 digest, the SHA-256 family (SHA-256, HMAC, PBKDF2), base64, the
  SCRAM-SHA-256 client state machine, and the Postgres MD5 password construction.
- `types.rs` and `row.rs` turn raw column bytes into Rust values by type OID.
- `connection.rs` is the only file that touches a socket. It owns the handshake
  and the read loop.
- `mock.rs` is a server that speaks the protocol back, so the whole stack can be
  driven without a database.

## The protocol codec

Postgres framing is uniform: a one-byte type tag, a four-byte big-endian length
that counts itself plus the body, then the body. The startup and SSLRequest
messages are the sole exception, carrying no tag. Conduit models this directly.

Encoding builds a body with a small `Writer` (big-endian integers, C strings),
then frames it. Decoding is the delicate half, because the bytes come from the
network and may be hostile or incomplete. Two rules keep it safe:

1. **Bounded reads.** A `Reader` cursor length-checks every read and returns a
   protocol error rather than indexing past the buffer. A truncated string, a
   short body, or a negative count are all errors, never panics.
2. **Decode returns "need more".** `BackendMessage::decode` returns `Ok(None)`
   when the buffer does not yet hold a complete message, so the connection layer
   knows to read more from the socket. This is what makes messages split across
   TCP reads just work.
3. **A length cap bounds memory.** A declared length above the cap (default
   64 MiB, configurable per connection) is a protocol error, rejected before any
   body byte is buffered. Without it a server could announce a two-gigabyte
   frame, drip a few bytes, and make the client grow its read buffer toward OOM
   while `decode` politely answered "need more". `decode_with_cap` takes the
   ceiling explicitly and `decode` applies the default.

Unknown message tags are not fatal. They decode to `Unknown { tag }` and are
skipped by their length, which is how a real client tolerates protocol
extensions. An asynchronous `NotificationResponse` is modelled explicitly and
likewise skipped in the query loops, so a `NOTIFY` mid-stream never breaks a
query.

The frontend side is symmetric: `FrontendMessage` has both `encode` and
`decode`, so `decode(encode(x)) == x` holds and the golden tests can prove the
encoder without a second implementation to disagree with.

## Authentication

Cleartext auth sends the password in a `PasswordMessage`. MD5 auth sends

```
"md5" + hex(md5( hex(md5(password + username)) + salt ))
```

The inner digest binds the password to the username; the outer digest binds that
to a per-session four-byte salt, so the same password never hashes the same way
twice. `md5.rs` implements the digest from the RFC 1321 pseudocode (the per-round
shift amounts, the sine-derived `K` table, the four nonlinear functions) and is
checked against the RFC's own known-answer vectors. `auth.rs` layers the Postgres
construction on top with its own known-answer test.

SCRAM-SHA-256, the default since PostgreSQL 14, runs the full challenge-response
exchange of RFC 5802 and RFC 7677 with channel binding disabled (the gs2 header
is the fixed `n,,`). The client sends `n,,n=,r=<clientnonce>`, parses the
server-first `r=<nonce>,s=<salt>,i=<iterations>`, derives

```
SaltedPassword  = PBKDF2(password, salt, iterations, 32)
ClientKey       = HMAC(SaltedPassword, "Client Key")
StoredKey       = SHA256(ClientKey)
ClientSignature = HMAC(StoredKey, AuthMessage)
ClientProof     = ClientKey XOR ClientSignature
```

and sends `c=biws,r=<nonce>,p=<base64 proof>`. It then verifies the server-final
`v=<base64 ServerSignature>`, where `ServerSignature = HMAC(HMAC(SaltedPassword,
"Server Key"), AuthMessage)`, before it trusts the connection. `sha256.rs`
provides SHA-256, HMAC-SHA-256, and PBKDF2, each checked against published
known-answer vectors (FIPS 180-4, RFC 4231, RFC 6070-style), and `scram.rs` is
cross-checked against the worked example in RFC 7677. The client nonce is built
from process-unique entropy since the standard library ships no RNG. What is
still left out is TLS, so channel binding stays off.

## The connection

`Connection::connect` opens a `TcpStream`, honouring a configurable connect
timeout so a silent host cannot block the caller, and sets a read timeout so a
stalled server cannot pin it. It then sends the startup message and runs a single
loop until the server reports `ReadyForQuery`. Inside that loop it answers any
authentication request, including the multi-round SCRAM exchange whose client
state lives across iterations, records the `ParameterStatus` values and
`BackendKeyData`, and ignores notices, notifications, and unknown tags. One loop,
every handshake shape.

Query execution shares a `collect_result_sets` reader that runs until
`ReadyForQuery`, assembling `RowDescription` into a shared column header and each
`DataRow` into a `Row`. Each `CommandComplete` closes a result set, so a simple
query carrying several `;`-separated statements keeps one set per statement
rather than merging them. `simple_query_multi` returns all sets, while
`simple_query` flattens them for the single-statement common case. An
`ErrorResponse` mid-stream is remembered and returned after the stream drains, so
the connection is left in a clean, reusable state even when a query fails.

The simple protocol is one `Query` message. The extended protocol sends
`Parse`, `Bind`, `Describe`, `Execute`, `Sync` in a batch. Conduit always binds
parameters in the **text format**: the value travels as a length-prefixed byte
string in the `Bind` message, never interpolated into SQL text. That is what
makes injection structurally impossible here, not a matter of escaping.

## Types

Postgres can return every column in text or binary; Conduit asks for text
everywhere. Decoding is then "parse this ASCII by its type OID". The `FromSql`
trait maps a `(oid, bytes)` pair to a Rust value: integer OIDs into `i16`/`i32`/
`i64`, float OIDs into `f32`/`f64`, `bool` from `t`/`f`, and `String` as a
permissive default that renders any column as its text form. Asking for a type
the OID cannot supply is a clear `Error::Decode`, not a silent misread.

`NULL` is handled one level up. A column is stored as `Option<Vec<u8>>`; a `NULL`
calls `FromSql::from_sql_null`, which errors for a plain type and returns `None`
for `Option<T>`. So `row.get::<Option<String>>("note")` is how you read a
nullable column, and `row.get::<String>("note")` on a `NULL` is an honest error.

## Proving it without a database

A wire-protocol driver is hard to test because the interesting behavior only
appears against a server. Conduit solves this at two levels.

**Golden vectors** pin the codec. Each message is asserted against exact bytes,
with the layout cited in comments, including a captured-style result sequence and
the auth and error messages. This is a unit test of the protocol itself: if a
byte moves, a test fails.

**The mock server** proves the stack. `mock.rs` binds a real `TcpListener` and
scripts a session: it answers the startup with `AuthenticationOk`, or demands
MD5 and verifies the client's hash, or drives a full SCRAM-SHA-256 exchange and
verifies the client's proof against a known password (and can send a deliberately
wrong server signature to exercise the client's verification step). It then sends
`ParameterStatus`, `BackendKeyData`, and `ReadyForQuery`, replies to a `Query`
with a typed result set, to a multi-statement query with two result sets, and to
a designated bad query with an `ErrorResponse`. The integration test runs the
real driver against it over real TCP. Crucially the mock encodes backend messages
by hand while the driver decodes them, so the encoder and decoder cross-check
each other rather than sharing code that could be wrong the same way twice. Its
frontend reader also bounds-checks every field, so hostile client bytes (a
zero-length startup, a truncated Bind) return an error instead of panicking the
connection thread.

An optional `CONDUIT_PG_URL` test runs the same queries against a real Postgres
when one is available, and is skipped otherwise so CI stays green.

## What is left out, and why

- **TLS.** Real and large. Leaving it out keeps the transport readable, and with
  no TLS there is no channel binding for SCRAM to negotiate.
- **The binary result format.** Text decoding is the legible path and avoids a
  per-type binary layout table. The format code is plumbed through, so binary is
  an extension point, not a rewrite.
- **Pooling, async, pipelining, COPY, and a LISTEN/NOTIFY subscription API.**
  Conduit is synchronous and one query at a time on purpose. A
  `NotificationResponse` is tolerated on the wire but not surfaced to a channel.
  The goal is a driver you can hold in your head, not a production client.

Author: Pavan Nallamothu (pavanchow).
