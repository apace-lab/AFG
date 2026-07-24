//! Minimal stand-in for the `jsonwebtoken` crate's public surface -- just
//! enough to compile as its own crate (named `jsonwebtoken`, so real Rust
//! mangling gives call sites the path `jsonwebtoken::decode`, matching
//! `datasets/ac_functions.json`) and produce a real `direct`-strategy call
//! site for `find_ac_points_llvm`. Not the real crate -- see
//! `src/AC_FINDER.md#regenerating-examplesac_demo_llvmll` for how this is
//! compiled.

#[derive(Default)]
pub struct Claims;

pub struct DecodingKey;

pub struct Validation;

#[derive(Debug)]
pub struct Error;

pub fn decode<T: Default>(
    _token: &str,
    _key: &DecodingKey,
    _validation: &Validation,
) -> Result<T, Error> {
    Ok(T::default())
}
