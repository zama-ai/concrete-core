//! Module providing utilities to the `C` FFI for structures implementing the
//! `LweSecretKeyEntity` trait.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Fill result with a clone of the input `LweSecretKey32`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn clone_lwe_secret_key_u32(
    lwe_secret_key: *const LweSecretKey32,
    result: *mut *mut LweSecretKey32,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let lwe_secret_key = get_ref_checked(lwe_secret_key).unwrap();

        let heap_allocated_lwe_secret_key_clone = Box::new(lwe_secret_key.clone());

        *result = Box::into_raw(heap_allocated_lwe_secret_key_clone);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`clone_lwe_secret_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn clone_lwe_secret_key_unchecked_u32(
    lwe_secret_key: *const LweSecretKey32,
    result: *mut *mut LweSecretKey32,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let lwe_secret_key = &(*lwe_secret_key);

        let heap_allocated_lwe_secret_key_clone = Box::new(lwe_secret_key.clone());

        *result = Box::into_raw(heap_allocated_lwe_secret_key_clone);
    })
}
