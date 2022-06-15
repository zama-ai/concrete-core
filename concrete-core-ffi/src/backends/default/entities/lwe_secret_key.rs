//! Module providing utilities to the `C` FFI for structures implementing the
//! `LweSecretKeyEntity` trait.

use crate::buffer::{Buffer, BufferView};
use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Fill result with a clone of the input `LweSecretKey64`.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn clone_lwe_secret_key_u64(
    lwe_secret_key: *const LweSecretKey64,
    result: *mut *mut LweSecretKey64,
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
/// [`clone_lwe_secret_key_u64`]
#[no_mangle]
pub unsafe extern "C" fn clone_lwe_secret_key_unchecked_u64(
    lwe_secret_key: *const LweSecretKey64,
    result: *mut *mut LweSecretKey64,
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

/// Serialize an `LweSecretKey64` to a byte (u8) [`Buffer`].
///
/// Fills the result with a [`Buffer`] struct pointing to the serialized key.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn serialize_lwe_secret_key_u64(
    secret_key: *const LweSecretKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let secret_key = get_ref_checked(secret_key).unwrap();

        let buffer: Buffer = bincode::serialize(secret_key).unwrap().into();
        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`serialize_lwe_secret_key_u64`]
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn serialize_lwe_secret_key_unchecked_u64(
    secret_key: *const LweSecretKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let secret_key = &(*secret_key);

        let buffer: Buffer = bincode::serialize(secret_key).unwrap().into();
        *result = buffer;
    })
}

/// Deserialize a byte (u8) [`BufferView`] to an `LweSecretKey64`.
///
/// Fills the result with a `LweSecretKey64` using the provided [`BufferView`] as source.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn deserialize_lwe_secret_key_u64(
    buffer: BufferView,
    result: *mut *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        *result = match bincode::deserialize(buffer.into()) {
            Ok(sk) => {
                let heap_allocated_sk = Box::new(sk);
                Box::into_raw(heap_allocated_sk)
            }
            _ => std::ptr::null_mut(),
        };
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`deserialize_lwe_secret_key_u64`]
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn deserialize_lwe_secret_key_unchecked_u64(
    buffer: BufferView,
    result: *mut *mut LweSecretKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        *result = match bincode::deserialize(buffer.into()) {
            Ok(sk) => {
                let heap_allocated_sk = Box::new(sk);
                Box::into_raw(heap_allocated_sk)
            }
            _ => std::ptr::null_mut(),
        };
    })
}
