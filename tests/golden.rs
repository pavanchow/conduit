//! Golden byte vectors. Each message is asserted against the exact bytes it must
//! produce on the wire, and each backend message is decoded from a captured-style
//! byte sequence. Byte layouts are cited inline. All integers are big-endian.

use conduit::message::{
    error_code_and_message, AuthRequest, BackendMessage, BindValue, FieldDescription,
    FrontendMessage,
};

// -------------------------------------------------------------- frontend encode

#[test]
fn startup_message_bytes() {
    // [Int32 len][Int32 196608 version]["user"\0][value\0]["database"\0][value\0][\0]
    let msg = FrontendMessage::Startup {
        user: "conduit".into(),
        database: "postgres".into(),
        params: vec![],
    };
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x28, // length = 40
        0x00, 0x03, 0x00, 0x00, // protocol 3.0
        b'u', b's', b'e', b'r', 0x00, //
        b'c', b'o', b'n', b'd', b'u', b'i', b't', 0x00, //
        b'd', b'a', b't', b'a', b'b', b'a', b's', b'e', 0x00, //
        b'p', b'o', b's', b't', b'g', b'r', b'e', b's', 0x00, //
        0x00, // terminating empty key
    ];
    assert_eq!(msg.encode(), expected);
}

#[test]
fn query_message_bytes() {
    // 'Q' [Int32 len] [sql\0]
    let msg = FrontendMessage::Query("SELECT 1".into());
    let expected: &[u8] = &[
        b'Q', 0x00, 0x00, 0x00, 0x0D, // len = 13
        b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0x00,
    ];
    assert_eq!(msg.encode(), expected);
}

#[test]
fn password_message_bytes() {
    // 'p' [Int32 len] [password\0]
    let msg = FrontendMessage::Password("secret".into());
    let expected: &[u8] = &[
        b'p', 0x00, 0x00, 0x00, 0x0B, // len = 11
        b's', b'e', b'c', b'r', b'e', b't', 0x00,
    ];
    assert_eq!(msg.encode(), expected);
}

#[test]
fn sync_and_terminate_bytes() {
    assert_eq!(FrontendMessage::Sync.encode(), &[b'S', 0, 0, 0, 4]);
    assert_eq!(FrontendMessage::Terminate.encode(), &[b'X', 0, 0, 0, 4]);
}

#[test]
fn parse_message_bytes() {
    // 'P' [len] [statement\0] [query\0] [Int16 nparams=0]
    let msg = FrontendMessage::Parse {
        statement: String::new(),
        query: "SELECT $1".into(),
        param_types: vec![],
    };
    let expected: &[u8] = &[
        b'P', 0x00, 0x00, 0x00, 0x11, // len = 17
        0x00, // empty statement name
        b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'$', b'1', 0x00, //
        0x00, 0x00, // no parameter type oids
    ];
    assert_eq!(msg.encode(), expected);
}

#[test]
fn bind_message_bytes() {
    // 'B' [len] [portal\0] [stmt\0] [Int16 1][Int16 text][Int16 2 params]
    //     [Int32 2 "42"] [Int32 -1 (NULL)] [Int16 1][Int16 text result]
    let msg = FrontendMessage::Bind {
        portal: String::new(),
        statement: String::new(),
        params: vec![BindValue::Text("42".into()), BindValue::Null],
    };
    let expected: &[u8] = &[
        b'B', 0x00, 0x00, 0x00, 0x1A, // len = 26
        0x00, // portal
        0x00, // statement
        0x00, 0x01, // one parameter format code
        0x00, 0x00, // text
        0x00, 0x02, // two parameters
        0x00, 0x00, 0x00, 0x02, b'4', b'2', // param 0 = "42"
        0xFF, 0xFF, 0xFF, 0xFF, // param 1 = NULL
        0x00, 0x01, // one result format code
        0x00, 0x00, // text
    ];
    assert_eq!(msg.encode(), expected);
}

// -------------------------------------------------------------- frontend round-trip

#[test]
fn frontend_round_trip() {
    let messages = vec![
        FrontendMessage::Startup {
            user: "alice".into(),
            database: "shop".into(),
            params: vec![("application_name".into(), "conduit".into())],
        },
        FrontendMessage::Password("md5abcd".into()),
        FrontendMessage::Query("SELECT * FROM t".into()),
        FrontendMessage::Parse {
            statement: "s1".into(),
            query: "SELECT $1, $2".into(),
            param_types: vec![23, 25],
        },
        FrontendMessage::Bind {
            portal: "p1".into(),
            statement: "s1".into(),
            params: vec![
                BindValue::Text("hello".into()),
                BindValue::Null,
                BindValue::Text("".into()),
            ],
        },
        FrontendMessage::Describe {
            kind: b'P',
            name: "p1".into(),
        },
        FrontendMessage::Execute {
            portal: "p1".into(),
            max_rows: 100,
        },
        FrontendMessage::Sync,
        FrontendMessage::Terminate,
    ];
    for msg in messages {
        let bytes = msg.encode();
        let (decoded, consumed) = FrontendMessage::decode(&bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, msg);
    }
}

// -------------------------------------------------------------- backend decode

#[test]
fn authentication_messages_decode() {
    // 'R' [Int32 8] [Int32 code]
    let ok: &[u8] = &[b'R', 0, 0, 0, 8, 0, 0, 0, 0];
    let (m, n) = BackendMessage::decode(ok).unwrap().unwrap();
    assert_eq!(n, 9);
    assert_eq!(m, BackendMessage::Authentication(AuthRequest::Ok));

    let cleartext: &[u8] = &[b'R', 0, 0, 0, 8, 0, 0, 0, 3];
    assert_eq!(
        BackendMessage::decode(cleartext).unwrap().unwrap().0,
        BackendMessage::Authentication(AuthRequest::CleartextPassword)
    );

    // 'R' [Int32 12] [Int32 5] [salt 4 bytes]
    let md5: &[u8] = &[b'R', 0, 0, 0, 12, 0, 0, 0, 5, 0xDE, 0xAD, 0xBE, 0xEF];
    assert_eq!(
        BackendMessage::decode(md5).unwrap().unwrap().0,
        BackendMessage::Authentication(AuthRequest::Md5Password {
            salt: [0xDE, 0xAD, 0xBE, 0xEF]
        })
    );
}

#[test]
fn parameter_status_and_key_data_decode() {
    // 'S' [len] [name\0] [value\0]
    let ps: &[u8] = &[
        b'S', 0, 0, 0, 24, b's', b'e', b'r', b'v', b'e', b'r', b'_', b'v', b'e', b'r', b's', b'i',
        b'o', b'n', 0, b'1', b'6', b'.', b'0', 0,
    ];
    assert_eq!(
        BackendMessage::decode(ps).unwrap().unwrap().0,
        BackendMessage::ParameterStatus {
            name: "server_version".into(),
            value: "16.0".into()
        }
    );

    // 'K' [Int32 12] [Int32 pid] [Int32 secret]
    let kd: &[u8] = &[b'K', 0, 0, 0, 12, 0, 0, 0x10, 0x92, 0x3A, 0xDE, 0x68, 0xB1];
    assert_eq!(
        BackendMessage::decode(kd).unwrap().unwrap().0,
        BackendMessage::BackendKeyData {
            pid: 4242,
            secret: 987654321
        }
    );
}

/// The captured-style happy-path sequence: RowDescription, two DataRows (one
/// with a NULL), CommandComplete, ReadyForQuery. Decoded end to end.
#[test]
fn result_sequence_decode() {
    let mut stream: Vec<u8> = Vec::new();

    // 'T' RowDescription: 2 fields. id int4(23), name text(25).
    stream.extend_from_slice(&[
        b'T', 0, 0, 0, 50, //
        0, 2, // field count
        b'i', b'd', 0, // name
        0, 0, 0, 0, // table oid
        0, 0, // column id
        0, 0, 0, 23, // type oid int4
        0, 4, // type size
        0xFF, 0xFF, 0xFF, 0xFF, // type modifier -1
        0, 0, // text format
        b'n', b'a', b'm', b'e', 0, //
        0, 0, 0, 0, //
        0, 0, //
        0, 0, 0, 25, // type oid text
        0xFF, 0xFF, // varlena size -1
        0xFF, 0xFF, 0xFF, 0xFF, //
        0, 0, //
    ]);
    // 'D' DataRow: "1", "alice"
    stream.extend_from_slice(&[
        b'D', 0, 0, 0, 20, 0, 2, //
        0, 0, 0, 1, b'1', //
        0, 0, 0, 5, b'a', b'l', b'i', b'c', b'e',
    ]);
    // 'D' DataRow: "2", NULL
    stream.extend_from_slice(&[
        b'D', 0, 0, 0, 15, 0, 2, //
        0, 0, 0, 1, b'2', //
        0xFF, 0xFF, 0xFF, 0xFF,
    ]);
    // 'C' CommandComplete "SELECT 2"
    stream.extend_from_slice(&[
        b'C', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'2', 0,
    ]);
    // 'Z' ReadyForQuery 'I'
    stream.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);

    let mut off = 0;
    let mut decoded = Vec::new();
    while let Some((msg, n)) = BackendMessage::decode(&stream[off..]).unwrap() {
        off += n;
        decoded.push(msg);
    }
    assert_eq!(off, stream.len());
    assert_eq!(decoded.len(), 5);

    assert_eq!(
        decoded[0],
        BackendMessage::RowDescription(vec![
            FieldDescription {
                name: "id".into(),
                table_oid: 0,
                column_id: 0,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format: 0,
            },
            FieldDescription {
                name: "name".into(),
                table_oid: 0,
                column_id: 0,
                type_oid: 25,
                type_size: -1,
                type_modifier: -1,
                format: 0,
            },
        ])
    );
    assert_eq!(
        decoded[1],
        BackendMessage::DataRow(vec![Some(b"1".to_vec()), Some(b"alice".to_vec())])
    );
    assert_eq!(
        decoded[2],
        BackendMessage::DataRow(vec![Some(b"2".to_vec()), None])
    );
    assert_eq!(
        decoded[3],
        BackendMessage::CommandComplete {
            tag: "SELECT 2".into()
        }
    );
    assert_eq!(decoded[4], BackendMessage::ReadyForQuery { status: b'I' });
}

#[test]
fn error_response_decode() {
    // 'E' [len] then ('S'|'C'|'M' ...) field bytes, terminated by \0.
    let mut body: Vec<u8> = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"ERROR\0");
    body.push(b'C');
    body.extend_from_slice(b"42601\0");
    body.push(b'M');
    body.extend_from_slice(b"syntax error\0");
    body.push(0);

    let mut bytes = vec![b'E'];
    bytes.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    bytes.extend_from_slice(&body);

    let (m, _) = BackendMessage::decode(&bytes).unwrap().unwrap();
    match m {
        BackendMessage::ErrorResponse(fields) => {
            let (code, message) = error_code_and_message(&fields);
            assert_eq!(code, "42601");
            assert_eq!(message, "syntax error");
        }
        other => panic!("expected ErrorResponse, got {other:?}"),
    }
}

#[test]
fn short_buffer_asks_for_more() {
    // A truncated header yields None (need more bytes), never a panic.
    assert!(BackendMessage::decode(&[b'R', 0, 0]).unwrap().is_none());
    // A full header but missing body also yields None.
    assert!(BackendMessage::decode(&[b'R', 0, 0, 0, 12, 0, 0])
        .unwrap()
        .is_none());
}

#[test]
fn malformed_length_is_an_error() {
    // Length smaller than the 4-byte length field itself is a protocol error.
    assert!(BackendMessage::decode(&[b'R', 0, 0, 0, 3, 0, 0, 0, 0]).is_err());
}

#[test]
fn unknown_message_is_skipped_by_length() {
    // Tag 'W' is not modelled; it must decode as Unknown and consume its length.
    let bytes: &[u8] = &[b'W', 0, 0, 0, 6, 0xAA, 0xBB];
    let (m, n) = BackendMessage::decode(bytes).unwrap().unwrap();
    assert_eq!(n, 7);
    assert_eq!(m, BackendMessage::Unknown { tag: b'W' });
}
