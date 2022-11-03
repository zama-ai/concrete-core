#![allow(clippy::missing_safety_doc)]

const __ASSERT_USIZE_SAME_AS_SIZE_T: () = {
    let _: libc::size_t = 0_usize;
};

#[allow(unused_macros)]
macro_rules! unused {
    ($($id: ident),* $(,)?) => {
        {
            $(let _ = &$id;)*
        }
    };
}

mod bootstrap;
mod keyswitch;
mod linear_op;
mod types;
mod wop_pbs;

pub use bootstrap::*;
pub use keyswitch::*;
pub use linear_op::*;
pub use types::*;
pub use wop_pbs::*;

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_init_lwe_secret_key_u64(
    lwe_sk: *mut u64,
    lwe_dimension: usize,
    csprng: *mut Csprng,
) {
    unused!(lwe_sk, lwe_dimension, csprng);
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_init_lwe_bootstrap_key_u64(
    // bootstrap key
    lwe_bsk: *mut u64,
    // secret keys
    input_lwe_sk: *mut u64,
    output_glwe_sk: *mut u64,
    // secret key dimensions
    input_lwe_dimension: usize,
    output_poly_size: usize,
    output_glwe_dimension: usize,
    // bootstrap key parameters
    level: usize,
    base_log: usize,
    variance: f64,
    csprng: *mut Csprng,
) {
    unused!(
        lwe_bsk,
        input_lwe_sk,
        output_glwe_sk,
        input_lwe_dimension,
        output_poly_size,
        output_glwe_dimension,
        level,
        base_log,
        variance,
        csprng,
    );
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_init_lwe_keyswitch_key_u64(
    // keyswitch key
    lwe_ksk: *mut u64,
    // secret keys
    input_lwe_sk: *mut u64,
    output_lwe_sk: *mut u64,
    // secret key dimensions
    input_lwe_dimension: usize,
    output_lwe_dimension: usize,
    // keyswitch key parameters
    level: usize,
    base_log: usize,
    variance: f64,
    csprng: *mut Csprng,
) {
    unused!(
        lwe_ksk,
        input_lwe_sk,
        output_lwe_sk,
        input_lwe_dimension,
        output_lwe_dimension,
        level,
        base_log,
        variance,
        csprng,
    );
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_init_lwe_packing_keyswitch_key_u64(
    // packing keyswitch key
    lwe_pksk: *mut u64,
    // secret keys
    input_lwe_sk: *mut u64,
    output_glwe_sk: *mut u64,
    // secret key dimensions
    input_lwe_dimension: usize,
    output_poly_size: usize,
    output_glwe_dimension: usize,
    // circuit bootstrap parameters
    level: usize,
    base_log: usize,
    variance: f64,
    csprng: *mut Csprng,
) {
    unused!(
        lwe_pksk,
        input_lwe_sk,
        output_glwe_sk,
        input_lwe_dimension,
        output_poly_size,
        output_glwe_dimension,
        level,
        base_log,
        variance,
        csprng,
    );
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_encrypt_lwe_ciphertext_u64(
    // secret key
    lwe_sk: *const u64,
    // ciphertext
    lwe_out: *mut u64,
    // plaintext
    input: u64,
    // lwe size
    lwe_dimension: usize,
    // encryption parameters
    variance: f64,
    csprng: *mut Csprng,
) {
    unused!(lwe_sk, lwe_out, input, lwe_dimension, variance, csprng);
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn concrete_cpu_decrypt_lwe_ciphertext_u64(
    // secret key
    lwe_sk: *const u64,
    // ciphertext
    lwe_ct_in: *const u64,
    // lwe size
    lwe_dimension: usize,
    // plaintext
    plaintext: *mut u64,
) {
    unused!(lwe_sk, lwe_ct_in, lwe_dimension, plaintext);
    todo!()
}
