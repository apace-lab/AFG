//! Minimal stand-in for the `bcrypt` crate's public surface -- compiled as
//! its own crate named `bcrypt` for the same reason as the `jsonwebtoken`
//! stub (see that file's doc comment): real mangling, real `direct`-strategy
//! call site at `bcrypt::verify`.

pub fn verify(_password: &[u8], _hash: &str) -> Result<bool, ()> {
    Ok(true)
}
