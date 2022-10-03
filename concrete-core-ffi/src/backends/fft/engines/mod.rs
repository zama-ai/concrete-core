//! Module providing utilities and entry points to the `C` FFI for the `fft` backend `FftEngine`
//! and its various implementations.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Create a new `FftEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_fft_engine = Box::new(FftEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_fft_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`new_fft_engine`]
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine_unchecked(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_fft_engine = Box::new(FftEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_fft_engine);
    })
}

/// Destroy an `FftEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_engine(engine: *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`destroy_fft_engine`]
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_engine_unchecked(engine: *mut FftEngine) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// Create a new `FftSerializationEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "backend_fft_serialization")]
pub unsafe extern "C" fn new_fft_serialization_engine(
    result: *mut *mut FftSerializationEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_fft_serialization_engine =
            Box::new(FftSerializationEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_fft_serialization_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`new_fft_serialization_engine`]
#[no_mangle]
#[cfg(feature = "backend_fft_serialization")]
pub unsafe extern "C" fn new_fft_serialization_engine_unchecked(
    result: *mut *mut FftSerializationEngine,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_fft_serialization_engine =
            Box::new(FftSerializationEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_fft_serialization_engine);
    })
}

/// Destroy an `FftSerializationEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "backend_fft_serialization")]
pub unsafe extern "C" fn destroy_fft_serialization_engine(
    engine: *mut FftSerializationEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_fft_serialization_engine`]
#[no_mangle]
#[cfg(feature = "backend_fft_serialization")]
pub unsafe extern "C" fn destroy_fft_serialization_engine_unchecked(
    engine: *mut FftSerializationEngine,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

pub mod destroy;
#[cfg(feature = "backend_fft_serialization")]
pub mod entity_deserialization;
#[cfg(feature = "backend_fft_serialization")]
pub mod entity_serialization;
pub mod lwe_bootstrap_key_conversion;
pub mod lwe_ciphertext_discarding_bit_extraction;
pub mod lwe_ciphertext_discarding_bootstrap;
pub mod lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing;

pub use destroy::*;
#[cfg(feature = "backend_fft_serialization")]
pub use entity_deserialization::*;
#[cfg(feature = "backend_fft_serialization")]
pub use entity_serialization::*;
pub use lwe_bootstrap_key_conversion::*;
pub use lwe_ciphertext_discarding_bit_extraction::*;
pub use lwe_ciphertext_discarding_bootstrap::*;
pub use lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing::*;
