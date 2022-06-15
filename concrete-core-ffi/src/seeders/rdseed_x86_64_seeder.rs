//! Module providing the `C` FFI for the x86-specifc [rdseed](https://en.wikipedia.org/wiki/RDRAND)
//! based seeder.

use crate::seeders::{SeederBuilder, SeederFactory};
use crate::utils::*;
use concrete_core::prelude::{RdseedSeeder, Seeder};
use std::os::raw::c_int;

struct RdseedSeederFactory {}

impl SeederFactory for RdseedSeederFactory {
    fn create_seeder(&mut self) -> Result<Box<dyn Seeder>, String> {
        Ok(Box::new(RdseedSeeder {}))
    }
}

/// Check if `RdseedSeeder` is available on x86 CPUs.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn rdseed_seeder_is_available(result: *mut bool) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        *result = RdseedSeeder::is_available();
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`rdseed_seeder_is_available`].
#[no_mangle]
pub unsafe extern "C" fn rdseed_seeder_is_available_unchecked(result: *mut bool) -> c_int {
    catch_panic(|| {
        *result = RdseedSeeder::is_available();
    })
}

/// Return a [`SeederBuilder`] which yields `RdseedSeeder`s that can be passed to engine creation
/// functions that require it.
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn get_rdseed_seeder_builder(result: *mut *mut SeederBuilder) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
        let heap_allocated_seeder_builder =
            Box::new(SeederBuilder::new(Box::new(RdseedSeederFactory {})));
        *result = Box::into_raw(heap_allocated_seeder_builder);
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`get_rdseed_seeder_builder`].
#[no_mangle]
pub unsafe extern "C" fn get_rdseed_seeder_builder_unchecked(
    result: *mut *mut SeederBuilder,
) -> c_int {
    catch_panic(|| {
        let heap_allocated_seeder_builder =
            Box::new(SeederBuilder::new(Box::new(RdseedSeederFactory {})));
        *result = Box::into_raw(heap_allocated_seeder_builder);
    })
}
