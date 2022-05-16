//! Module providing utilities to the `C` FFI for structures implementing the
//! `LweKeyswitchKeyEntity` trait.

use crate::buffer::{Buffer, BufferView};
use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Serialize an `LweKeyswitchKey64` to a byte (u8) [`Buffer`].
///
/// Fills the result with a [`Buffer`] struct pointing to the serialized key.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn serialize_lwe_keyswitching_key_u64(
    keyswitching_key: *const LweKeyswitchKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let keyswitching_key = get_ref_checked(keyswitching_key).unwrap();

        let buffer: Buffer = bincode::serialize(keyswitching_key).unwrap().into();
        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`serialize_lwe_keyswitching_key_u64`]
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn serialize_lwe_keyswitching_key_unchecked_u64(
    keyswitching_key: *const LweKeyswitchKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let keyswitching_key = &(*keyswitching_key);

        let buffer: Buffer = bincode::serialize(keyswitching_key).unwrap().into();
        *result = buffer;
    })
}

/// Deserialize a byte (u8) [`BufferView`] to an `LweKeyswitchKey64`.
///
/// Fills the result with a `LweKeyswitchKey64` using the provided [`BufferView`] as source.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn deserialize_lwe_keyswitching_key_u64(
    buffer: BufferView,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        *result = match bincode::deserialize(buffer.into()) {
            Ok(ksk) => {
                let heap_allocated_ksk = Box::new(ksk);
                Box::into_raw(heap_allocated_ksk)
            }
            _ => std::ptr::null_mut(),
        };
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`deserialize_lwe_keyswitching_key_u64`]
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn deserialize_lwe_keyswitching_key_unchecked_u64(
    buffer: BufferView,
    result: *mut *mut LweKeyswitchKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        *result = match bincode::deserialize(buffer.into()) {
            Ok(ksk) => {
                let heap_allocated_ksk = Box::new(ksk);
                Box::into_raw(heap_allocated_ksk)
            }
            _ => std::ptr::null_mut(),
        };
    })
}
