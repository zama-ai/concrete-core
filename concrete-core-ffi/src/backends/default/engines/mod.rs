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

        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of [`destroy_default_engine`]
#[no_mangle]
pub unsafe extern "C" fn destroy_default_engine_unchecked(engine: *mut DefaultEngine) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// Create a new `DefaultParallelEngine`.
///
/// Requires a [`SeederBuilder`] to seed the random generators of the engine.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "backend_default_parallel")]
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
        let heap_allocated_default_parallel_engine =
            Box::new(DefaultParallelEngine::new(seeder).unwrap());
        *result = Box::into_raw(heap_allocated_default_parallel_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`new_default_parallel_engine`]
#[no_mangle]
#[cfg(feature = "backend_default_parallel")]
pub unsafe extern "C" fn new_default_parallel_engine_unchecked(
    seeder_builder: *mut SeederBuilder,
    result: *mut *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let seeder = (*seeder_builder).create_seeder().unwrap();
        let heap_allocated_default_parallel_engine =
            Box::new(DefaultParallelEngine::new(seeder).unwrap());
        *result = Box::into_raw(heap_allocated_default_parallel_engine);
    })
}

/// Destroy a `DefaultParallelEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "backend_default_parallel")]
pub unsafe extern "C" fn destroy_default_parallel_engine(
    engine: *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_default_parallel_engine`]
#[no_mangle]
#[cfg(feature = "backend_default_parallel")]
pub unsafe extern "C" fn destroy_default_parallel_engine_unchecked(
    engine: *mut DefaultParallelEngine,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// Create a new `DefaultSerializationEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "backend_default_serialization")]
pub unsafe extern "C" fn new_default_serialization_engine(
    result: *mut *mut DefaultSerializationEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_default_serialization_engine =
            Box::new(DefaultSerializationEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_default_serialization_engine);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`new_default_serialization_engine`]
#[no_mangle]
#[cfg(feature = "backend_default_serialization")]
pub unsafe extern "C" fn new_default_serialization_engine_unchecked(
    result: *mut *mut DefaultSerializationEngine,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_default_serialization_engine =
            Box::new(DefaultSerializationEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_default_serialization_engine);
    })
}

/// Destroy a `DefaultSerializationEngine`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "backend_default_serialization")]
pub unsafe extern "C" fn destroy_default_serialization_engine(
    engine: *mut DefaultSerializationEngine,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_default_serialization_engine`]
#[no_mangle]
#[cfg(feature = "backend_default_serialization")]
pub unsafe extern "C" fn destroy_default_serialization_engine_unchecked(
    engine: *mut DefaultSerializationEngine,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}

pub mod destroy;
#[cfg(feature = "backend_default_serialization")]
pub mod entity_deserialization;
#[cfg(feature = "backend_default_serialization")]
pub mod entity_serialization;
pub mod glwe_ciphertext_creation;
pub mod glwe_ciphertext_discarding_trivial_encryption;
pub mod glwe_lwe_secret_key_transformation;
pub mod glwe_secret_key_generation;
pub mod lwe_bootstrap_key_creation;
pub mod lwe_bootstrap_key_discarding_conversion;
pub mod lwe_bootstrap_key_generation;
pub mod lwe_ciphertext_cleartext_discarding_multiplication;
pub mod lwe_ciphertext_creation;
pub mod lwe_ciphertext_decryption;
pub mod lwe_ciphertext_discarding_addition;
pub mod lwe_ciphertext_discarding_encryption;
pub mod lwe_ciphertext_discarding_keyswitch;
pub mod lwe_ciphertext_discarding_opposite;
pub mod lwe_ciphertext_plaintext_discarding_addition;
pub mod lwe_ciphertext_vector_creation;
pub mod lwe_ciphertext_vector_decryption;
pub mod lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_generation;
pub mod lwe_glwe_secret_key_transformation;
pub mod lwe_keyswitch_key_creation;
pub mod lwe_keyswitch_key_discarding_conversion;
pub mod lwe_keyswitch_key_generation;
pub mod lwe_secret_key_generation;
pub mod lwe_seeded_bootstrap_key_generation;
pub mod lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_transformation;
pub mod lwe_seeded_keyswitch_key_generation;
pub mod lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_transformation;
pub mod lwe_ciphertext_vector_discarding_encryption;

pub use destroy::*;
#[cfg(feature = "backend_default_serialization")]
pub use entity_deserialization::*;
#[cfg(feature = "backend_default_serialization")]
pub use entity_serialization::*;
pub use glwe_ciphertext_creation::*;
pub use glwe_ciphertext_discarding_trivial_encryption::*;
pub use glwe_lwe_secret_key_transformation::*;
pub use glwe_secret_key_generation::*;
pub use lwe_bootstrap_key_creation::*;
pub use lwe_bootstrap_key_discarding_conversion::*;
pub use lwe_bootstrap_key_generation::*;
pub use lwe_ciphertext_cleartext_discarding_multiplication::*;
pub use lwe_ciphertext_creation::*;
pub use lwe_ciphertext_decryption::*;
pub use lwe_ciphertext_discarding_addition::*;
pub use lwe_ciphertext_discarding_encryption::*;
pub use lwe_ciphertext_discarding_keyswitch::*;
pub use lwe_ciphertext_discarding_opposite::*;
pub use lwe_ciphertext_plaintext_discarding_addition::*;
pub use lwe_ciphertext_vector_creation::*;
pub use lwe_ciphertext_vector_decryption::*;
pub use lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_generation::*;
pub use lwe_glwe_secret_key_transformation::*;
pub use lwe_keyswitch_key_creation::*;
pub use lwe_keyswitch_key_discarding_conversion::*;
pub use lwe_keyswitch_key_generation::*;
pub use lwe_secret_key_generation::*;
pub use lwe_seeded_bootstrap_key_generation::*;
pub use lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_transformation::*;
pub use lwe_seeded_keyswitch_key_generation::*;
pub use lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_transformation::*;
pub use lwe_ciphertext_vector_discarding_encryption::*;
