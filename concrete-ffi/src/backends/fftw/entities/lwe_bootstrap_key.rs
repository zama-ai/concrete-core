//! Module providing utilities to the `C` FFI for structures implementing the
//! `LweBootstrapKeyEntity` trait.

use crate::buffer::{Buffer, BufferView};
use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Serialize an `FftwFourierLweBootstrapKey64` to a byte (u8) [`Buffer`].
///
/// Fills the result with a [`Buffer`] struct pointing to the serialized key.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn serialize_fftw_fourier_lwe_bootstrap_key_u64(
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let pbsk = get_ref_checked(bootstrap_key).unwrap();

        let buffer: Buffer = bincode::serialize(pbsk).unwrap().into();
        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`serialize_fftw_fourier_lwe_bootstrap_key_u64`]
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn serialize_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
    bootstrap_key: *const FftwFourierLweBootstrapKey64,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let pbsk = &(*bootstrap_key);

        let buffer: Buffer = bincode::serialize(pbsk).unwrap().into();
        *result = buffer;
    })
}

/// Deserialize a byte (u8) [`BufferView`] to an `FftwFourierLweBootstrapKey64`.
///
/// Fills the result with a `FftwFourierLweBootstrapKey64` using the provided [`BufferView`] as
/// source.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn deserialize_fftw_fourier_lwe_bootstrap_key_u64(
    buffer: BufferView,
    result: *mut *mut FftwFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        *result = match bincode::deserialize(buffer.into()) {
            Ok(bsk) => {
                let heap_allocated_bsk = Box::new(bsk);
                Box::into_raw(heap_allocated_bsk)
            }
            _ => std::ptr::null_mut(),
        };
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`deserialize_fftw_fourier_lwe_bootstrap_key_u64`]
#[no_mangle]
#[cfg(feature = "serde_serialize")]
pub unsafe extern "C" fn deserialize_fftw_fourier_lwe_bootstrap_key_unchecked_u64(
    buffer: BufferView,
    result: *mut *mut FftwFourierLweBootstrapKey64,
) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        *result = match bincode::deserialize(buffer.into()) {
            Ok(bsk) => {
                let heap_allocated_bsk = Box::new(bsk);
                Box::into_raw(heap_allocated_bsk)
            }
            _ => std::ptr::null_mut(),
        };
    })
}
