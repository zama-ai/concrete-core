//! Module providing entry points to the `CudaEngine` implementations of various
//! `LweCiphertextDiscardingBootstrapEngine` traits.

use crate::utils::*;
use concrete_core::prelude::*;
use std::os::raw::c_int;

/// Bootstrap an LWE ciphertext using CUDA. View buffer variant.
///
/// Refer to `concrete-core` implementation for detailed documentation.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers(
    engine: *mut CudaEngine,
    d_bootstrap_key: *const CudaFourierLweBootstrapKey64,
    d_output: *mut CudaLweCiphertext64,
    d_input: *const CudaLweCiphertext64,
    d_accumulator: *const CudaGlweCiphertext64,
) -> c_int {
    catch_panic(|| {
        let engine = get_mut_checked(engine).unwrap();

        let d_bootstrap_key = get_ref_checked(d_bootstrap_key).unwrap();

        let d_output = get_mut_checked(d_output).unwrap();
        let d_input = get_ref_checked(d_input).unwrap();

        let d_accumulator = get_ref_checked(d_accumulator).unwrap();

        engine
            .discard_bootstrap_lwe_ciphertext(d_output, d_input, d_accumulator, d_bootstrap_key)
            .or_else(engine_error_as_readable_string)
            .unwrap();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u64_view_buffers(
    engine: *mut CudaEngine,
    d_bootstrap_key: *const CudaFourierLweBootstrapKey64,
    d_output: *mut CudaLweCiphertext64,
    d_input: *const CudaLweCiphertext64,
    d_accumulator: *const CudaGlweCiphertext64,
) -> c_int {
    catch_panic(|| {
        let engine = &mut (*engine);

        let d_bootstrap_key = &(*d_bootstrap_key);

        let d_output = &mut (*d_output);
        let d_input = &(*d_input);

        let d_accumulator = &(*d_accumulator);

        engine.discard_bootstrap_lwe_ciphertext_unchecked(
            d_output,
            d_input,
            d_accumulator,
            d_bootstrap_key,
        );
    })
}

/// Raw pointer buffer variant of
/// [`cuda_engine_lwe_ciphertext_discarding_bootstrap_u64_view_buffers`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_lwe_ciphertext_discarding_bootstrap_u64_raw_ptr_buffers(
    cuda_engine: *mut CudaEngine,
    default_engine: *mut DefaultEngine,
    d_bootstrap_key: *const CudaFourierLweBootstrapKey64,
    output: *mut u64,
    input: *const u64,
    accumulator: *const u64,
) -> c_int {
    catch_panic(|| {
        let cuda_engine = get_mut_checked(cuda_engine).unwrap();
        let default_engine = get_mut_checked(default_engine).unwrap();

        let d_bootstrap_key = get_ref_checked(d_bootstrap_key).unwrap();

        let input_lwe_size = d_bootstrap_key.input_lwe_dimension().to_lwe_size().0;
        let ouput_lwe_size = d_bootstrap_key.output_lwe_dimension().to_lwe_size().0;

        let polynomial_size = d_bootstrap_key.polynomial_size();
        let glwe_size = d_bootstrap_key.glwe_dimension().to_glwe_size();

        let output = get_mut_checked(output).unwrap();
        let output_as_slice = std::slice::from_raw_parts_mut(output, ouput_lwe_size);
        let mut h_output = default_engine
            .create_lwe_ciphertext(output_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let input = get_ref_checked(input).unwrap();
        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let h_input = default_engine
            .create_lwe_ciphertext(input_as_slice)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let accumulator = get_ref_checked(accumulator).unwrap();
        let accumulator_as_slice =
            std::slice::from_raw_parts(accumulator, polynomial_size.0 * glwe_size.0);
        let h_accumulator = default_engine
            .create_glwe_ciphertext(accumulator_as_slice, polynomial_size)
            .or_else(engine_error_as_readable_string)
            .unwrap();

        let d_input = cuda_engine.convert_lwe_ciphertext(h_input);
        let d_output = cuda_engine.convert_lwe_ciphertext(h_output);
        let d_accumulator = cuda_engine.convert_glwe_ciphertext(h_accumulator);

        cuda_engine.discard_bootstrap_lwe_ciphertext_unchecked(
            d_output,
            d_input,
            d_accumulator,
            d_bootstrap_key,
        );

        cuda_engine.destroy(d_input);
        cuda_engine.destroy(d_output);
        cuda_engine.destroy(d_accumulator);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`cuda_engine_lwe_ciphertext_discarding_bootstrap_u64_raw_ptr_buffers`]
#[no_mangle]
pub unsafe extern "C" fn cuda_engine_lwe_ciphertext_discarding_bootstrap_unchecked_u64_raw_ptr_buffers(
    cuda_engine: *mut CudaEngine,
    default_engine: *mut DefaultEngine,
    d_bootstrap_key: *const CudaFourierLweBootstrapKey64,
    output: *mut u64,
    input: *const u64,
    accumulator: *const u64,
) -> c_int {
    catch_panic(|| {
        let cuda_engine = &mut (*cuda_engine);
        let default_engine = &mut (*default_engine);

        let d_bootstrap_key = get_ref_checked(d_bootstrap_key).unwrap();

        let input_lwe_size = d_bootstrap_key.input_lwe_dimension().to_lwe_size().0;
        let ouput_lwe_size = d_bootstrap_key.output_lwe_dimension().to_lwe_size().0;

        let polynomial_size = d_bootstrap_key.polynomial_size();
        let glwe_size = d_bootstrap_key.glwe_dimension().to_glwe_size();

        let output_as_slice = std::slice::from_raw_parts_mut(output, ouput_lwe_size);
        let mut h_output = default_engine.create_lwe_ciphertext_unchecked(output_as_slice);

        let input_as_slice = std::slice::from_raw_parts(input, input_lwe_size);
        let h_input = default_engine.create_lwe_ciphertext_unchecked(input_as_slice);

        let accumulator_as_slice =
            std::slice::from_raw_parts(accumulator, polynomial_size.0 * glwe_size.0);
        let h_accumulator =
            default_engine.create_glwe_ciphertext_unchecked(accumulator_as_slice, polynomial_size);

        let d_input = cuda_engine.convert_lwe_ciphertext(h_input);
        let d_output = cuda_engine.convert_lwe_ciphertext(h_output);
        let d_accumulator = cuda_engine.convert_glwe_ciphertext(h_accumulator);

        cuda_engine.discard_bootstrap_lwe_ciphertext_unchecked(
            d_output,
            d_input,
            d_accumulator,
            d_bootstrap_key,
        );

        cuda_engine.destroy(d_input);
        cuda_engine.destroy(d_output);
        cuda_engine.destroy(d_accumulator);
    })
}
