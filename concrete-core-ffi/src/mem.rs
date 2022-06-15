//! Module providing constants for proper memory alignment across the FFI boundary.

#[no_mangle]
pub static U8_ALIGNMENT: usize = std::mem::align_of::<u8>();
#[no_mangle]
pub static U32_ALIGNMENT: usize = std::mem::align_of::<u32>();
#[no_mangle]
pub static U64_ALIGNMENT: usize = std::mem::align_of::<u64>();

// Rust references and pointers are aligned like C pointers for sized types, so no need to add
// alignment infos for pointer types
// See https://rust-lang.github.io/unsafe-code-guidelines/layout/pointers.html#notes
