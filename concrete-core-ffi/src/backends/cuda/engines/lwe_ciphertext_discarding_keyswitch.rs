//! Module providing entry points to the `CudaEngine` implementations of various
//! `LweCiphertextDiscardingKeyswitchEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Keyswitch a `CudaLweCiphertext64`. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_discard_keyswitch_lwe_ciphertext_u64(
    engine: *mut CudaEngine,
    d_keyswitch_key: *const CudaLweKeyswitchKey64,
    d_output: *mut CudaLweCiphertext64,
    d_input: *const CudaLweCiphertext64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let d_keyswitch_key = get_ref_checked(d_keyswitch_key).unwrap();

        let d_output = get_mut_checked(d_output).unwrap();
        let d_input = get_ref_checked(d_input).unwrap();

        engine
            .discard_keyswitch_lwe_ciphertext(d_output, d_input, d_keyswitch_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_discard_keyswitch_lwe_ciphertext_u64`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_discard_keyswitch_lwe_ciphertext_unchecked_u64(
    engine: *mut CudaEngine,
    d_keyswitch_key: *const CudaLweKeyswitchKey64,
    d_output: *mut CudaLweCiphertext64,
    d_input: *const CudaLweCiphertext64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let d_keyswitch_key = &(*d_keyswitch_key);

        let d_output = &mut (*d_output);
        let d_input = &(*d_input);

        engine.discard_keyswitch_lwe_ciphertext_unchecked(d_output, d_input, d_keyswitch_key);
    })
}

/// Raw pointer variant of [`cuda_engine_discard_keyswitch_lwe_ciphertext_u64`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_discard_keyswitch_lwe_ciphertext_u64_raw_ptr_buffers(
    cuda_engine: *mut CudaEngine,
    d_keyswitch_key: *const CudaLweKeyswitchKey64,
    output: *mut u64,
    input: *const u64,
) -> c_int {
    catch_panic(|| {
        let cuda_engine = get_mut_checked(cuda_engine).unwrap();

        let d_keyswitch_key = get_ref_checked(d_keyswitch_key).unwrap();

        let lwe_input_size = d_keyswitch_key.input_lwe_dimension().to_lwe_size().0;
        let lwe_output_size = d_keyswitch_key.output_lwe_dimension().to_lwe_size().0;

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_output_size);
        let mut h_output = cuda_engine.create_lwe_ciphertext_unchecked(output_as_slice);

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, lwe_input_size);
        let h_input = cuda_engine
            .create_lwe_ciphertext(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let d_input = cuda_engine.convert_lwe_ciphertext(h_input);
        let d_output = cuda_engine.convert_lwe_ciphertext(h_output); // Only used to create the obj

        cuda_engine
            .discard_keyswitch_lwe_ciphertext(&mut d_output, &d_input, d_keyswitch_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let h_output = cuda_engine.convert_lwe_ciphertext(d_output);
        output_as_slice.clone_from_slice(h_output);

        cuda_engine.destroy(d_input);
        cuda_engine.destroy(d_output);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_discard_keyswitch_lwe_ciphertext_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_discard_keyswitch_lwe_ciphertext_unchecked_u64_raw_ptr_buffers(
    cuda_engine: *mut CudaEngine,
    d_keyswitch_key: *const CudaLweKeyswitchKey64,
    output: *mut u64,
    input: *const u64,
) -> c_int {
    catch_panic(|| {
        let cuda_engine = &mut (*cuda_engine);

        let d_keyswitch_key = &(*d_keyswitch_key);

        let lwe_input_size = d_keyswitch_key.input_lwe_dimension().to_lwe_size().0;
        let lwe_output_size = d_keyswitch_key.output_lwe_dimension().to_lwe_size().0;

        let output_as_slice = std::slice::from_raw_parts_mut(output, lwe_output_size);
        let mut h_output = cuda_engine.create_lwe_ciphertext_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, lwe_input_size);
        let h_input = cuda_engine.create_lwe_ciphertext_unchecked(input_as_slice);

        let d_input = cuda_engine.convert_lwe_ciphertext(h_input);
        let d_output = cuda_engine.convert_lwe_ciphertext(h_output); // Only used to create the obj

        cuda_engine.discard_keyswitch_lwe_ciphertext_unchecked(&mut d_output, &d_input, d_keyswitch_key);

        let h_output = cuda_engine.convert_lwe_ciphertext(d_output);
        output_as_slice.clone_from_slice(h_output);

        cuda_engine.destroy(d_input);
        cuda_engine.destroy(d_output);
    })
}
