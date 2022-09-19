use crate::{catch_panic, get_mut_checked};
use paste::paste;
use std::os::raw::c_int;

pub type RustVecU8 = RustVec<u8>;
pub type RustVecU32 = RustVec<u32>;
pub type RustVecU64 = RustVec<u64>;
pub type RustSliceU8 = RustSlice<u8>;
pub type RustSliceU32 = RustSlice<u32>;
pub type RustSliceU64 = RustSlice<u64>;
pub type RustMutSliceU8 = RustMutSlice<u8>;
pub type RustMutSliceU32 = RustMutSlice<u32>;
pub type RustMutSliceU64 = RustMutSlice<u64>;

#[repr(C)]
pub struct RustVec<T> {
    pub pointer: *mut T,
    pub length: usize,
}

impl<T> From<RustVec<T>> for Vec<T> {
    fn from(bf: RustVec<T>) -> Vec<T> {
        unsafe { Vec::from_raw_parts(bf.pointer, bf.length, bf.length) }
    }
}

impl<T> From<Vec<T>> for RustVec<T> {
    fn from(a: Vec<T>) -> Self {
        let a = a.leak();

        Self {
            pointer: a.as_mut_ptr(),
            length: a.len(),
        }
    }
}

#[repr(C)]
pub struct RustSlice<T> {
    pub pointer: *const T,
    pub length: usize,
}

impl<T> From<RustSlice<T>> for &[T] {
    fn from(bf: RustSlice<T>) -> &'static [T] {
        unsafe { std::slice::from_raw_parts(bf.pointer, bf.length) }
    }
}

impl<T> From<&[T]> for RustSlice<T> {
    fn from(a: &[T]) -> Self {
        Self {
            pointer: a.as_ptr(),
            length: a.len(),
        }
    }
}

#[repr(C)]
pub struct RustMutSlice<T> {
    pub pointer: *mut T,
    pub length: usize,
}

impl<T> From<RustMutSlice<T>> for &mut [T] {
    fn from(bf: RustMutSlice<T>) -> &'static mut [T] {
        unsafe { std::slice::from_raw_parts_mut(bf.pointer, bf.length) }
    }
}

impl<T> From<&mut [T]> for RustMutSlice<T> {
    fn from(a: &mut [T]) -> Self {
        Self {
            pointer: a.as_mut_ptr(),
            length: a.len(),
        }
    }
}

macro_rules! gen_destroys {
    ($($typ:ty),*) => {
        $(
            paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<destroy_rust_vec_ $typ>](buffer: *mut RustVec<$typ>) -> c_int {
                    catch_panic(|| {
                        let buffer = get_mut_checked(buffer).unwrap();
                        let pointer = get_mut_checked(buffer.pointer).unwrap();
                        let length = buffer.length;
                        Vec::from_raw_parts(pointer, length, length);
                        buffer.length = 0;
                        buffer.pointer = std::ptr::null_mut();
                    })
                }
                #[no_mangle]
                pub unsafe extern "C" fn [<destroy_rust_vec_ $typ _unchecked>](buffer: *mut RustVec<$typ>) -> c_int {
                    catch_panic(|| {
                        let buffer = &mut (*buffer);
                        let pointer = &mut (*buffer.pointer);
                        let length = buffer.length;
                        Vec::from_raw_parts(pointer, length, length);
                        buffer.length = 0;
                        buffer.pointer = std::ptr::null_mut();
                    })
                }
            }
        )*
    };
}

gen_destroys!(u8, u32, u64);
