use concrete_core::backends::fft::private::c64;
use concrete_core::backends::fft::private::crypto::bootstrap::{
    bootstrap_scratch, fill_with_forward_fourier_scratch, FourierLweBootstrapKey,
};
use concrete_core::commons::crypto::bootstrap::StandardBootstrapKey;
use concrete_core::commons::crypto::glwe::GlweCiphertext;
use concrete_core::prelude::*;
use core::slice;
use dyn_stack::DynStack;

use crate::types::{Fft, Parallelism, ScratchStatus};

#[must_use]
#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_bootstrap_key_convert_u64_to_fourier_scratch(
    stack_size: *mut usize,
    stack_align: *mut usize,
    // bootstrap parameters
    decomposition_level_count: usize,
    glwe_dimension: usize,
    polynomial_size: usize,
    input_lwe_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
) -> ScratchStatus {
    unused!(
        decomposition_level_count,
        glwe_dimension,
        polynomial_size,
        input_lwe_dimension,
        parallelism,
    );

    if let Ok(scratch) = fill_with_forward_fourier_scratch(unsafe { (*fft).inner.as_view() }) {
        unsafe {
            *stack_size = scratch.size_bytes();
            *stack_align = scratch.align_bytes();
        }
        ScratchStatus::Valid
    } else {
        ScratchStatus::SizeOverflow
    }
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_bootstrap_key_convert_u64_to_fourier(
    // bootstrap key
    standard_bsk: *const u64,
    fourier_bsk: *mut f64,
    // bootstrap parameters
    decomposition_level_count: usize,
    decomposition_base_log: usize,
    glwe_dimension: usize,
    polynomial_size: usize,
    input_lwe_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
    stack: *mut u8,
    stack_size: usize,
) {
    unused!(parallelism);

    let glwe_size = GlweDimension(glwe_dimension).to_glwe_size();
    let standard_len = input_lwe_dimension
        * decomposition_level_count
        * glwe_size.0
        * glwe_size.0
        * polynomial_size;
    let fourier_len = standard_len / 2;

    let standard = StandardBootstrapKey::from_container(
        unsafe { slice::from_raw_parts(standard_bsk, standard_len) },
        glwe_size,
        PolynomialSize(polynomial_size),
        DecompositionLevelCount(decomposition_level_count),
        DecompositionBaseLog(decomposition_base_log),
    );

    let fourier = FourierLweBootstrapKey::new(
        unsafe { slice::from_raw_parts_mut(fourier_bsk as *mut c64, fourier_len) },
        LweDimension(input_lwe_dimension),
        PolynomialSize(polynomial_size),
        glwe_size,
        DecompositionBaseLog(decomposition_base_log),
        DecompositionLevelCount(decomposition_level_count),
    );

    fourier.fill_with_forward_fourier(
        standard,
        unsafe { (*fft).inner.as_view() },
        DynStack::new(unsafe { slice::from_raw_parts_mut(stack as _, stack_size) }),
    );
}

#[must_use]
#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_bootstrap_lwe_ciphertext_u64_scratch(
    stack_size: *mut usize,
    stack_align: *mut usize,
    // bootstrap parameters
    decomposition_level_count: usize,
    glwe_dimension: usize,
    polynomial_size: usize,
    input_lwe_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
) -> ScratchStatus {
    unused!(decomposition_level_count, input_lwe_dimension, parallelism,);
    let fft = unsafe { (*fft).inner.as_view() };
    if let Ok(scratch) = bootstrap_scratch::<u64>(
        GlweDimension(glwe_dimension).to_glwe_size(),
        PolynomialSize(polynomial_size),
        fft,
    ) {
        unsafe {
            *stack_size = scratch.size_bytes();
            *stack_align = scratch.align_bytes();
        }
        ScratchStatus::Valid
    } else {
        ScratchStatus::SizeOverflow
    }
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_bootstrap_lwe_ciphertext_u64(
    // ciphertexts
    ct_out: *mut u64,
    ct_in: *const u64,
    // accumulator
    accumulator: *const u64,
    // bootstrap key
    fourier_bsk: *const f64,
    // bootstrap parameters
    decomposition_level_count: usize,
    decomposition_base_log: usize,
    glwe_dimension: usize,
    polynomial_size: usize,
    input_lwe_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    fft: *const Fft,
    stack: *mut u8,
    stack_size: usize,
) {
    unused!(parallelism);

    let output_lwe_dimension = glwe_dimension * polynomial_size;

    let glwe_size = GlweDimension(glwe_dimension).to_glwe_size();
    let standard_len = input_lwe_dimension
        * decomposition_level_count
        * glwe_size.0
        * glwe_size.0
        * polynomial_size;
    let fourier_len = standard_len / 2;

    let fourier = FourierLweBootstrapKey::new(
        unsafe { slice::from_raw_parts(fourier_bsk as *const c64, fourier_len) },
        LweDimension(input_lwe_dimension),
        PolynomialSize(polynomial_size),
        glwe_size,
        DecompositionBaseLog(decomposition_base_log),
        DecompositionLevelCount(decomposition_level_count),
    );

    let lwe_in =
        unsafe { slice::from_raw_parts(ct_in, LweDimension(input_lwe_dimension).to_lwe_size().0) };
    let lwe_out = unsafe {
        slice::from_raw_parts_mut(ct_out, LweDimension(output_lwe_dimension).to_lwe_size().0)
    };

    let accumulator = GlweCiphertext::from_container(
        unsafe { slice::from_raw_parts(accumulator, polynomial_size * glwe_size.0) },
        PolynomialSize(polynomial_size),
    );
    fourier.bootstrap(
        lwe_out,
        lwe_in,
        accumulator,
        unsafe { (*fft).inner.as_view() },
        unsafe { DynStack::new(slice::from_raw_parts_mut(stack as _, stack_size)) },
    );
}
