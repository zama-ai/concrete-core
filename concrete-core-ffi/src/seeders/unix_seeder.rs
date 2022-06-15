//! Module providing the `C` FFI for [Unix](https://en.wikipedia.org/wiki/Unix)-specific seeders.

use crate::seeders::{SeederBuilder, SeederFactory};
use crate::utils::*;
use concrete_core::prelude::{Seeder, UnixSeeder};
use std::os::raw::c_int;

struct UnixSeederFactory {
    secret: u128,
    allowed_to_create_seeder: bool,
}

impl UnixSeederFactory {
    pub fn new(secret: u128) -> Self {
        Self {
            secret,
            allowed_to_create_seeder: true,
        }
    }
}

impl SeederFactory for UnixSeederFactory {
    fn create_seeder(&mut self) -> Result<Box<dyn Seeder>, String> {
        if !self.allowed_to_create_seeder {
            return Err(
                "The current UnixSeederFactory already created a seeder with the stored secret \
                and will not create anymore for security reasons. If you need a new UnixSeeder \
                create another UnixSeederFactory with a different secret."
                    .to_owned(),
            );
        }
        self.allowed_to_create_seeder = false;
        Ok(Box::new(UnixSeeder::new(self.secret)))
    }
}

/// Check if `UnixSeeder` is available on x86 CPUs.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn unix_seeder_is_available(result: *mut bool) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        *result = UnixSeeder::is_available();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`unix_seeder_is_available`].
#[no_mangle]
pub unsafe extern "C" fn unix_seeder_is_available_unchecked(result: *mut bool) -> c_int {
    catch_panic(|| {
        *result = UnixSeeder::is_available();
    })
}

fn u128_from_two_u64(high_64: u64, low_64: u64) -> u128 {
    let high_bytes: u128 = high_64.into();
    let low_bytes: u128 = low_64.into();
    (high_bytes << 64) ^ low_bytes
}

/// ⚠ It is VERY dangerous to re-use a secret to seed a UnixSeeder. The returned [`SeederBuilder`]
/// instance is only callable once and will panic if called more than once.
///
/// This function requires a 128 bits seed that will be used as a secret to create a `UnixSeeder`
/// instance. Two 64 bits unsigned integers (`secret_high_64` and `secret_low_64`) are required to
/// create the 128 bits secret.
///
/// Return a [`SeederBuilder`] which will create only one `UnixSeeder`, that can be passed to engine
/// creation functions that require it. Using the [`SeederBuilder`] more than once will panic.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn get_unix_seeder_builder(
    secret_high_64: u64,
    secret_low_64: u64,
    result: *mut *mut SeederBuilder,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let secret = u128_from_two_u64(secret_high_64, secret_low_64);
        let heap_allocated_seeder_builder =
            Box::new(SeederBuilder::new(Box::new(UnixSeederFactory::new(secret))));
        *result = Box::into_raw(heap_allocated_seeder_builder);
    })
}

/// ⚠ It is VERY dangerous to re-use a secret to seed a UnixSeeder. The returned [`SeederBuilder`]
/// instance is only callable once and will panic if called more than once.
///
/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`get_unix_seeder_builder`].
#[no_mangle]
pub unsafe extern "C" fn get_unix_seeder_builder_unchecked(
    secret_high_64: u64,
    secret_low_64: u64,
    result: *mut *mut SeederBuilder,
) -> c_int {
    catch_panic(|| {
        let secret = u128_from_two_u64(secret_high_64, secret_low_64);
        let heap_allocated_seeder_builder =
            Box::new(SeederBuilder::new(Box::new(UnixSeederFactory::new(secret))));
        *result = Box::into_raw(heap_allocated_seeder_builder);
    })
}
