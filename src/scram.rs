//! SCRAM-SHA-256 (RFC 5802 / RFC 7677), the default Postgres authentication
//! method since PostgreSQL 14. Channel binding is not used, so the gs2 header is
//! the fixed "n,,". Everything is built on the hand-written [`crate::sha256`] and
//! [`crate::base64`] modules, keeping Conduit dependency-free.

use crate::base64;
use crate::error::{Error, Result};
use crate::sha256::{hmac_sha256, pbkdf2_hmac_sha256, sha256};

/// The one mechanism Conduit speaks.
pub const MECHANISM: &str = "SCRAM-SHA-256";

/// A client-side SCRAM exchange. Created with the user's password, it produces
/// the client-first message, consumes the server-first message to produce the
/// client-final message, and finally verifies the server's signature.
pub struct ScramClient {
    password: String,
    client_nonce: String,
    // The SCRAM `n=` name. Empty for Postgres, which takes the user from the
    // startup packet; non-empty only for the RFC 7677 cross-check.
    name: String,
    // Filled in once the client-first message is built.
    client_first_bare: String,
    // Filled in once the server-first message is processed.
    server_signature: Option<[u8; 32]>,
}

impl ScramClient {
    /// A fresh exchange with a randomly generated client nonce.
    pub fn new(password: &str) -> Self {
        ScramClient::with_nonce(password, generate_nonce())
    }

    /// A fresh exchange with a caller-supplied nonce and an empty SCRAM name
    /// (the Postgres form).
    pub fn with_nonce(password: &str, client_nonce: String) -> Self {
        ScramClient::with_nonce_and_name(password, client_nonce, String::new())
    }

    /// A fresh exchange with a caller-supplied nonce and SCRAM `n=` name. The
    /// RFC 7677 cross-check test uses this to reproduce its published vector,
    /// which carries `n=user`.
    pub fn with_nonce_and_name(password: &str, client_nonce: String, name: String) -> Self {
        ScramClient {
            password: password.to_string(),
            client_nonce,
            name,
            client_first_bare: String::new(),
            server_signature: None,
        }
    }

    /// The client-first message: gs2 header "n,," then `n=<name>,r=<clientnonce>`.
    /// The name is empty for Postgres, which takes the user from the startup
    /// packet.
    pub fn client_first(&mut self) -> String {
        self.client_first_bare = format!("n={},r={}", self.name, self.client_nonce);
        format!("n,,{}", self.client_first_bare)
    }

    /// Consume the server-first message and produce the client-final message
    /// (`c=biws,r=<nonce>,p=<proof>`). Also stashes the expected server
    /// signature for the final verification step.
    pub fn client_final(&mut self, server_first: &[u8]) -> Result<String> {
        let server_first = std::str::from_utf8(server_first)
            .map_err(|_| Error::Auth("server-first message was not UTF-8".into()))?;

        let mut nonce = None;
        let mut salt_b64 = None;
        let mut iterations = None;
        for attr in server_first.split(',') {
            let (k, v) = attr.split_at(1);
            let v = v.strip_prefix('=').unwrap_or(v);
            match k {
                "r" => nonce = Some(v.to_string()),
                "s" => salt_b64 = Some(v.to_string()),
                "i" => iterations = Some(v.to_string()),
                _ => {}
            }
        }

        let nonce = nonce.ok_or_else(|| Error::Auth("server-first missing nonce".into()))?;
        let salt_b64 = salt_b64.ok_or_else(|| Error::Auth("server-first missing salt".into()))?;
        let iterations: u32 = iterations
            .ok_or_else(|| Error::Auth("server-first missing iteration count".into()))?
            .parse()
            .map_err(|_| Error::Auth("server-first iteration count was not a number".into()))?;

        if !nonce.starts_with(&self.client_nonce) {
            return Err(Error::Auth(
                "server nonce does not extend the client nonce".into(),
            ));
        }
        let salt = base64::decode(&salt_b64)
            .ok_or_else(|| Error::Auth("server salt was not valid base64".into()))?;

        // client-final-without-proof: channel binding "n,," is base64 "biws".
        let client_final_bare = format!("c=biws,r={nonce}");
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_bare
        );

        let salted_password = pbkdf2_hmac_sha256(self.password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key = sha256(&client_key);
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut client_proof = client_key;
        for i in 0..client_proof.len() {
            client_proof[i] ^= client_signature[i];
        }

        let server_key = hmac_sha256(&salted_password, b"Server Key");
        self.server_signature = Some(hmac_sha256(&server_key, auth_message.as_bytes()));

        Ok(format!(
            "{client_final_bare},p={}",
            base64::encode(&client_proof)
        ))
    }

    /// Verify the server-final message `v=<base64 ServerSignature>`. A mismatch
    /// means the server did not prove knowledge of the password and the whole
    /// exchange must be rejected.
    pub fn verify_server_final(&self, server_final: &[u8]) -> Result<()> {
        let server_final = std::str::from_utf8(server_final)
            .map_err(|_| Error::Auth("server-final message was not UTF-8".into()))?;
        let mut sig_b64 = None;
        for attr in server_final.split(',') {
            if let Some(v) = attr.strip_prefix("v=") {
                sig_b64 = Some(v.to_string());
            } else if let Some(e) = attr.strip_prefix("e=") {
                return Err(Error::Auth(format!("server rejected SCRAM exchange: {e}")));
            }
        }
        let sig_b64 = sig_b64.ok_or_else(|| Error::Auth("server-final missing signature".into()))?;
        let got = base64::decode(&sig_b64)
            .ok_or_else(|| Error::Auth("server signature was not valid base64".into()))?;
        let expected = self
            .server_signature
            .ok_or_else(|| Error::Auth("server-final arrived before client-final".into()))?;
        if got.as_slice() != expected.as_slice() {
            return Err(Error::Auth("server signature verification failed".into()));
        }
        Ok(())
    }
}

/// Build a printable nonce with no comma. Std has no RNG, so mix a few
/// process-unique sources through SHA-256 and base64 the result. Uniqueness,
/// not cryptographic unpredictability against a local attacker, is what SCRAM
/// requires of the client nonce.
fn generate_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tid = std::thread::current().id();
    let stack_marker = 0u8;
    let addr = &stack_marker as *const u8 as usize;

    let mut seed = Vec::new();
    seed.extend_from_slice(&now.to_le_bytes());
    seed.extend_from_slice(format!("{tid:?}").as_bytes());
    seed.extend_from_slice(&addr.to_le_bytes());
    // Two rounds so 24 base64 chars of entropy are available.
    let a = sha256(&seed);
    seed.extend_from_slice(&a);
    let b = sha256(&seed);
    let mut raw = Vec::with_capacity(24);
    raw.extend_from_slice(&a[..12]);
    raw.extend_from_slice(&b[..12]);
    // base64 of 24 bytes is 32 chars, all in the printable, comma-free alphabet.
    base64::encode(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 section 3 worked example. user "user", password "pencil",
    /// client nonce "rOprNGfwEbeRWgbNEkqO", server-first as published.
    #[test]
    fn rfc7677_example() {
        let mut scram = ScramClient::with_nonce_and_name(
            "pencil",
            "rOprNGfwEbeRWgbNEkqO".into(),
            "user".into(),
        );
        let client_first = scram.client_first();
        assert_eq!(client_first, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");

        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let client_final = scram.client_final(server_first.as_bytes()).unwrap();
        assert_eq!(
            client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );

        let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        scram.verify_server_final(server_final.as_bytes()).unwrap();
    }

    #[test]
    fn rejects_bad_server_signature() {
        let mut scram = ScramClient::with_nonce("pencil", "rOprNGfwEbeRWgbNEkqO".into());
        let _ = scram.client_first();
        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let _ = scram.client_final(server_first.as_bytes()).unwrap();
        let bad = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(scram.verify_server_final(bad.as_bytes()).is_err());
    }

    #[test]
    fn generated_nonce_is_printable_and_comma_free() {
        let n = generate_nonce();
        assert!(!n.is_empty());
        assert!(!n.contains(','));
        assert!(n.chars().all(|c| c.is_ascii_graphic()));
    }
}
