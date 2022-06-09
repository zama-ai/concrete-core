//! Module providing utilities to the `C` FFI for the x86-accelerated CSPRNG implementation

use crate::utils::{catch_panic, check_ptr_is_non_null_and_aligned};
use concrete_core::prelude::RandomGeneratorImplementation;
use std::os::raw::c_int;

/// Check if `AesniRandomGenerator` is available on x86 CPUs.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn aesni_random_generator_is_available(result: *mut bool) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        *result = RandomGeneratorImplementation::Aesni.is_available();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`aesni_random_generator_is_available`].
#[no_mangle]
pub unsafe extern "C" fn aesni_random_generator_is_available_unchecked(result: *mut bool) -> c_int {
    catch_panic(|| {
        *result = RandomGeneratorImplementation::Aesni.is_available();
    })
}
