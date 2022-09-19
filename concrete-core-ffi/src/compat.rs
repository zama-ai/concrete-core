use crate::{RustSlice, RustVec};
use std::os::raw::c_int;

pub type Buffer = RustVec<u8>;
pub type BufferView = RustSlice<u8>;

#[no_mangle]
pub unsafe extern "C" fn destroy_buffer(buffer: *mut Buffer) -> c_int {
    crate::destroy_rust_vec_u8(buffer)
}

#[no_mangle]
pub unsafe extern "C" fn destroy_buffer_unchecked(buffer: *mut Buffer) -> c_int {
    crate::destroy_rust_vec_u8_unchecked(buffer)
}
