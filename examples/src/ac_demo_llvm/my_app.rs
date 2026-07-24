//! The "application" half of the LLVM-IR demo -- calls into the three stub
//! crates (`jsonwebtoken`, `bcrypt`, `casbin`) plus one unrelated call that
//! must NOT be reported. Compiled for real with `rustc --emit=llvm-ir`
//! against the other three files in this directory to produce
//! `examples/ac_demo_llvm.ll`; see
//! `src/AC_FINDER.md#regenerating-examplesac_demo_llvmll` for the exact
//! commands.

use casbin::CoreApi;

pub fn verify_token(token: &str) -> bool {
    let key = jsonwebtoken::DecodingKey;
    let validation = jsonwebtoken::Validation;
    jsonwebtoken::decode::<jsonwebtoken::Claims>(token, &key, &validation).is_ok()
}

pub fn check_password(password: &[u8], hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

pub fn check_permission(enforcer: &casbin::Enforcer, sub: &str, obj: &str, act: &str) -> bool {
    enforcer.enforce(sub, obj, act)
}

/// Unrelated call -- demangles fine, matches no catalogue entry, must not
/// appear in `find_ac_points_llvm`'s output.
pub fn greet(name: &str) -> String {
    format!("hello, {name}")
}
