//! Minimal stand-in for the `casbin` crate's public surface -- compiled as
//! its own crate named `casbin`, just enough to exercise a *real* trait-impl
//! call site (`<Enforcer as CoreApi>::enforce`), the LLVM-IR analogue of
//! `ac_finder`/`ac_finder_rs_src`'s `angle-bracket`/`method` match
//! strategies. See `src/AC_FINDER.md#regenerating-examplesac_demo_llvmll`.

pub trait CoreApi {
    fn enforce(&self, sub: &str, obj: &str, act: &str) -> bool;
}

pub struct Enforcer;

impl CoreApi for Enforcer {
    fn enforce(&self, _sub: &str, _obj: &str, _act: &str) -> bool {
        true
    }
}
