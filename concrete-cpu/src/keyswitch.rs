use crate::types::{Parallelism, ScratchStatus};
use concrete_core::commons::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use concrete_core::prelude::*;
use core::slice;

#[must_use]
#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_keyswitch_lwe_ciphertext_u64_scratch(
    stack_size: *mut usize,
    stack_align: *mut usize,
    // keyswitch parameters
    decomposition_level_count: usize,
    decomposition_base_log: usize,
    input_dimension: usize,
    output_dimension: usize,
    // parallelism
    parallelism: Parallelism,
) -> ScratchStatus {
    unused!(
        decomposition_level_count,
        decomposition_base_log,
        input_dimension,
        output_dimension,
        parallelism,
    );
    unsafe {
        *stack_size = 0;
        *stack_align = 1;
    }
    ScratchStatus::Valid
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_keyswitch_lwe_ciphertext_u64(
    // ciphertexts
    ct_out: *mut u64,
    ct_in: *const u64,
    // keyswitch key
    keyswitch_key: *const u64,
    // keyswitch parameters
    decomposition_level_count: usize,
    decomposition_base_log: usize,
    input_dimension: usize,
    output_dimension: usize,
    // parallelism
    parallelism: Parallelism,
    // side resources
    stack: *mut u8,
    stack_size: usize,
) {
    unused!(parallelism, stack, stack_size);

    let output_lwe_size = LweDimension(output_dimension).to_lwe_size().0;
    let input_lwe_size = LweDimension(input_dimension).to_lwe_size().0;
    let mut ct_out = LweCiphertext::from_container(unsafe {
        slice::from_raw_parts_mut(ct_out, output_lwe_size)
    });
    let ct_in =
        LweCiphertext::from_container(unsafe { slice::from_raw_parts(ct_in, input_lwe_size) });

    let keyswitch_key = LweKeyswitchKey::from_container(
        unsafe {
            slice::from_raw_parts(
                keyswitch_key,
                decomposition_level_count * output_lwe_size * input_dimension,
            )
        },
        DecompositionBaseLog(decomposition_base_log),
        DecompositionLevelCount(decomposition_level_count),
        LweDimension(output_dimension),
    );

    keyswitch_key.keyswitch_ciphertext(&mut ct_out, &ct_in);
}
