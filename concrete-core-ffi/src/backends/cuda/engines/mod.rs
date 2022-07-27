//! Module providing utilities and entry points to the `C` FFI for the `cuda` backend `CudaEngine`
//! and its various implementations.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Create a new `CudaEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn new_cuda_engine(result: *mut *mut CudaEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_cuda_engine = Box::new(CudaEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_cuda_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`new_cuda_engine`]
#[no_mangle]
pub unsafe extern "C" fn new_cuda_engine_unchecked(result: *mut *mut CudaEngine) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_cuda_engine = Box::new(CudaEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_cuda_engine);
    })
}

/// Destroy an `CudaEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_cuda_engine(engine: *mut CudaEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`destroy_cuda_engine`]
#[no_mangle]
pub unsafe extern "C" fn destroy_cuda_engine_unchecked(engine: *mut CudaEngine) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(engine);
    })
}

pub mod destruction;
pub mod glwe_ciphertext_conversion;
pub mod lwe_bootstrap_key_conversion;
pub mod lwe_ciphertext_conversion;
pub mod lwe_keyswitch_key_conversion;

pub use destruction::*;
pub use glwe_ciphertext_conversion::*;
pub use lwe_bootstrap_key_conversion::*;
pub use lwe_ciphertext_conversion::*;
pub use lwe_keyswitch_key_conversion::*;
