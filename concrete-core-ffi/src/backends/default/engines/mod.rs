//! Module providing utilities and entry points to the `C` FFI for the `default` backend
//! `DefaultEngine` and its various implementations.

use crate::seeders::SeederBuilder;
use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Create a new `DefaultEngine`.
///
/// Requires a [`SeederBuilder`] to seed the random generators of the engine.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn new_default_engine(
    seeder_builder: *mut SeederBuilder,
    result: *mut *mut DefaultEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let seeder = get_mut_checked(seeder_builder)
            .unwrap()
            .create_seeder()
            .unwrap();
        let heap_allocated_default_engine = Box::new(DefaultEngine::new(seeder).unwrap());
        *result = Box::into_raw(heap_allocated_default_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`new_default_engine`]
#[no_mangle]
pub unsafe extern "C" fn new_default_engine_unchecked(
    seeder_builder: *mut SeederBuilder,
    result: *mut *mut DefaultEngine,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let seeder = (*seeder_builder).create_seeder().unwrap();
        let heap_allocated_default_engine = Box::new(DefaultEngine::new(seeder).unwrap());
        *result = Box::into_raw(heap_allocated_default_engine);
    })
}

/// Destroy a `DefaultEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_default_engine(engine: *mut DefaultEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`destroy_default_engine`]
#[no_mangle]
pub unsafe extern "C" fn destroy_default_engine_unchecked(engine: *mut DefaultEngine) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(engine);
    })
}

/// Create a new `DefaultParallelEngine`.
///
/// Requires a [`SeederBuilder`] to seed the random generators of the engine.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "parallel")]
pub unsafe extern "C" fn new_default_parallel_engine(
    seeder_builder: *mut SeederBuilder,
    result: *mut *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let seeder = get_mut_checked(seeder_builder)
            .unwrap()
            .create_seeder()
            .unwrap();
        let heap_allocated_default_engine = Box::new(DefaultParallelEngine::new(seeder).unwrap());
        *result = Box::into_raw(heap_allocated_default_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`new_default_parallel_engine`]
#[no_mangle]
#[cfg(feature = "parallel")]
pub unsafe extern "C" fn new_default_parallel_engine_unchecked(
    seeder_builder: *mut SeederBuilder,
    result: *mut *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let seeder = (*seeder_builder).create_seeder().unwrap();
        let heap_allocated_default_engine = Box::new(DefaultParallelEngine::new(seeder).unwrap());
        *result = Box::into_raw(heap_allocated_default_engine);
    })
}

/// Destroy a `DefaultParallelEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "parallel")]
pub unsafe extern "C" fn destroy_default_parallel_engine(
    engine: *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_default_parallel_engine`]
#[no_mangle]
#[cfg(feature = "parallel")]
pub unsafe extern "C" fn destroy_default_parallel_engine_unchecked(
    engine: *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box, so that the memory is dropped at the end of the scope
        Box::from_raw(engine);
    })
}

pub mod destruction;
pub mod glwe_ciphertext_creation;
pub mod glwe_ciphertext_discarding_trivial_encryption;
pub mod lwe_bootstrap_key_creation;
pub mod lwe_ciphertext_cleartext_discarding_multiplication;
pub mod lwe_ciphertext_creation;
pub mod lwe_ciphertext_decryption;
pub mod lwe_ciphertext_discarding_addition;
pub mod lwe_ciphertext_discarding_encryption;
pub mod lwe_ciphertext_discarding_keyswitch;
pub mod lwe_ciphertext_discarding_opposite;
pub mod lwe_ciphertext_plaintext_discarding_addition;
pub mod lwe_glwe_secret_key_transformation;
pub mod lwe_keyswitch_key_creation;
pub mod lwe_secret_key_creation;

pub use destruction::*;
pub use glwe_ciphertext_creation::*;
pub use glwe_ciphertext_discarding_trivial_encryption::*;
pub use lwe_bootstrap_key_creation::*;
pub use lwe_ciphertext_cleartext_discarding_multiplication::*;
pub use lwe_ciphertext_creation::*;
pub use lwe_ciphertext_decryption::*;
pub use lwe_ciphertext_discarding_addition::*;
pub use lwe_ciphertext_discarding_encryption::*;
pub use lwe_ciphertext_discarding_keyswitch::*;
pub use lwe_ciphertext_discarding_opposite::*;
pub use lwe_ciphertext_plaintext_discarding_addition::*;
pub use lwe_glwe_secret_key_transformation::*;
pub use lwe_keyswitch_key_creation::*;
pub use lwe_secret_key_creation::*;
