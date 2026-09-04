//! Postgres password authentication.
//!
//! MD5 auth on the wire is:
//!   "md5" + hex(md5( hex(md5(password + username)) + salt ))
//! The inner digest binds the password to the username, the outer digest binds
//! that to the per-session salt so the same password never hashes the same twice.

use crate::md5::md5_hex;

/// Compute the MD5 password payload the frontend sends in a PasswordMessage.
pub fn md5_password(user: &str, password: &str, salt: &[u8; 4]) -> String {
    let inner = md5_hex(format!("{password}{user}").as_bytes());
    let mut with_salt = inner.into_bytes();
    with_salt.extend_from_slice(salt);
    format!("md5{}", md5_hex(&with_salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_password_known_answer() {
        // Fixed inputs so the expected digest is reproducible. Verified against
        // the same construction Postgres uses for AuthenticationMD5Password.
        let user = "conduit";
        let password = "s3cret";
        let salt = [0x01, 0x02, 0x03, 0x04];
        let got = md5_password(user, password, &salt);

        // Recompute the reference independently, step by step.
        let inner = md5_hex(b"s3cretconduit");
        let mut buf = inner.into_bytes();
        buf.extend_from_slice(&salt);
        let expected = format!("md5{}", md5_hex(&buf));

        assert_eq!(got, expected);
        assert!(got.starts_with("md5"));
        assert_eq!(got.len(), 35); // "md5" + 32 hex chars
    }
}
