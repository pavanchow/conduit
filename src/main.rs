//! The `conduit` CLI: run a query against a real Postgres, or a `demo` session
//! against the built-in mock server so it works with no database installed.

use conduit::mock::{MockConfig, MockServer};
use conduit::{Config, Connection, Row};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("query") => cmd_query(&args),
        Some("demo") => cmd_demo(),
        Some("help") | Some("-h") | Some("--help") | None => {
            usage();
            0
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            usage();
            2
        }
    };
    exit(code);
}

fn usage() {
    eprintln!(
        "conduit - a from-scratch PostgreSQL wire-protocol driver\n\
         \n\
         USAGE:\n\
         \x20 conduit query <postgres-url> \"<sql>\"   run a query against a real server\n\
         \x20 conduit demo                          run a scripted session against the built-in mock\n\
         \n\
         EXAMPLE:\n\
         \x20 conduit query postgres://user:pass@localhost:5432/mydb \"SELECT 1 AS one\""
    );
}

fn cmd_query(args: &[String]) -> i32 {
    let (url, sql) = match (args.get(2), args.get(3)) {
        (Some(u), Some(s)) => (u, s),
        _ => {
            eprintln!("usage: conduit query <postgres-url> \"<sql>\"");
            return 2;
        }
    };
    let config = match Config::from_url(url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bad url: {e}");
            return 2;
        }
    };
    match run(&config, sql) {
        Ok(rows) => {
            print_table(&rows);
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(config: &Config, sql: &str) -> conduit::Result<Vec<Row>> {
    let mut conn = Connection::connect(config)?;
    let rows = conn.simple_query(sql)?;
    conn.close();
    Ok(rows)
}

fn cmd_demo() -> i32 {
    // Spin up the in-process mock so this works with no database installed.
    let server = match MockServer::start(MockConfig::default()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not start mock server: {e}");
            return 1;
        }
    };
    let config = Config::new()
        .host(server.host())
        .port(server.port())
        .user("demo")
        .database("demo");

    let mut conn = match Connection::connect(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return 1;
        }
    };

    println!("connected to the built-in mock server at {}", server.addr);
    println!("server parameters: {:?}\n", conn.parameters());

    println!("simple_query(\"SELECT * FROM people\"):");
    match conn.simple_query("SELECT * FROM people") {
        Ok(rows) => print_table(&rows),
        Err(e) => {
            eprintln!("query failed: {e}");
            return 1;
        }
    }

    println!("\nquery(\"SELECT $1, $2\", &[&42, &\"hello\"]) (parameters round-trip):");
    match conn.query("SELECT $1, $2", &[&42i32, &"hello"]) {
        Ok(rows) => print_table(&rows),
        Err(e) => {
            eprintln!("query failed: {e}");
            return 1;
        }
    }

    println!("\nsimple_query with a bad query surfaces the server error:");
    match conn.simple_query("SELECT boom") {
        Ok(_) => println!("(unexpected success)"),
        Err(e) => println!("caught -> {e}"),
    }

    conn.close();
    0
}

/// Print rows as a simple aligned text table.
fn print_table(rows: &[Row]) {
    if rows.is_empty() {
        println!("(0 rows)");
        return;
    }
    let headers: Vec<String> = rows[0]
        .columns()
        .iter()
        .map(|c| c.name.clone())
        .collect();
    let ncols = headers.len();

    let cell = |row: &Row, i: usize| -> String {
        match row.get_bytes(i) {
            Ok(Some(b)) => String::from_utf8_lossy(b).into_owned(),
            Ok(None) => "NULL".to_string(),
            Err(_) => String::new(),
        }
    };

    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, w) in widths.iter_mut().enumerate() {
            *w = (*w).max(cell(row, i).len());
        }
    }

    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", join_padded(&headers, &widths));
    println!("{}", sep.join("-+-"));
    for row in rows {
        let cells: Vec<String> = (0..ncols).map(|i| cell(row, i)).collect();
        println!("{}", join_padded(&cells, &widths));
    }
    println!("({} row{})", rows.len(), if rows.len() == 1 { "" } else { "s" });
}

fn join_padded(cells: &[String], widths: &[usize]) -> String {
    cells
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
        .collect::<Vec<_>>()
        .join(" | ")
}
