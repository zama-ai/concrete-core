//! Module providing the `C` FFI for Apple's secure enclave based seeder.
//! <https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc>

use crate::seeders::{SeederBuilder, SeederFactory};
use crate::utils::*;
use concrete_core::prelude::{AppleSecureEnclaveSeeder, Seeder};
use std::os::raw::c_int;

struct AppleSecureEnclaveSeederFactory {}

impl SeederFactory for AppleSecureEnclaveSeederFactory {
    fn create_seeder(&mut self) -> Result<Box<dyn Seeder>, String> {
        Ok(Box::new(AppleSecureEnclaveSeeder {}))
    }
}

/// Check if `AppleSecureEnclaveSeeder` is available on macOS for versions 10.7+.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn apple_secure_enclave_seeder_is_available(result: *mut bool) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        *result = AppleSecureEnclaveSeeder::is_available();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`apple_secure_enclave_seeder_is_available`].
#[no_mangle]
pub unsafe extern "C" fn apple_secure_enclave_seeder_is_available_unchecked(
    result: *mut bool,
) -> c_int {
    catch_panic(|| {
        *result = AppleSecureEnclaveSeeder::is_available();
    })
}

/// Return a [`SeederBuilder`] which yields `AppleSecureEnclaveSeeder`s that can be passed to engine
/// creation functions that require it.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn get_apple_secure_enclave_seeder_builder(
    result: *mut *mut SeederBuilder,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let heap_allocated_seeder_builder = Box::new(SeederBuilder::new(Box::new(
            AppleSecureEnclaveSeederFactory {},
        )));
        *result = Box::into_raw(heap_allocated_seeder_builder);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`get_apple_secure_enclave_seeder_builder`].
#[no_mangle]
pub unsafe extern "C" fn get_apple_secure_enclave_seeder_builder_unchecked(
    result: *mut *mut SeederBuilder,
) -> c_int {
    catch_panic(|| {
        let heap_allocated_seeder_builder = Box::new(SeederBuilder::new(Box::new(
            AppleSecureEnclaveSeederFactory {},
        )));
        *result = Box::into_raw(heap_allocated_seeder_builder);
    })
}
