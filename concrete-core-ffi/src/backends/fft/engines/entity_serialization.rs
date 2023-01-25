use crate::buffer::Buffer;
use crate::utils::{
    catch_panic, check_ptr_is_non_null_and_aligned, engine_error_as_readable_string,
    get_mut_checked, get_ref_checked,
};
use concrete_core::prelude::{
    EntitySerializationEngine, FftFourierLweBootstrapKey32, FftSerializationEngine,
};
use std::os::raw::c_int;

/// Serializes a `FftFourierLweBootstrapKey32`.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_u32(
    engine: *mut FftSerializationEngine,
    bootstrap_key: *const FftFourierLweBootstrapKey32,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let engine = get_mut_checked(engine).unwrap();
        let bootstrap_key = get_ref_checked(bootstrap_key).unwrap();

        let buffer: Buffer = engine
            .serialize(bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap()
            .into();

        *result = buffer;
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_u32`]
#[no_mangle]
pub unsafe extern "C" fn fft_serialization_engine_serialize_fft_fourier_lwe_bootstrap_key_unchecked_u32(
    engine: *mut FftSerializationEngine,
    bootstrap_key: *const FftFourierLweBootstrapKey32,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);
        let bootstrap_key = &(*bootstrap_key);

        let buffer: Buffer = engine.serialize_unchecked(bootstrap_key).into();

        *result = buffer;
    })
}
