//! Module providing the `C` FFI utilities to build seeders required for the creation of some
//! engines.

use crate::utils::*;
use concrete_core::prelude::Seeder;
use std::os::raw::c_int;

pub trait SeederFactory {
    fn create_seeder(&mut self) -> Result<Box<dyn Seeder>, String>;
}

/// Opaque structure that holds a [`SeederFactory`] able to build a `concrete-core` compatible
/// `Seeder`. A [`SeederBuilder`] is required by some engine creation functions.
pub struct SeederBuilder {
    factory: Box<dyn SeederFactory>,
}

impl SeederBuilder {
    pub fn new(factory: Box<dyn SeederFactory>) -> Self {
        Self { factory }
    }

    pub fn create_seeder(&mut self) -> Result<Box<dyn Seeder>, String> {
        self.factory.as_mut().create_seeder()
    }
}

/// Deallocate the passed [`SeederBuilder`].
///
/// This function is [checked](crate#safety-checked-and-unchecked-functions).
#[no_mangle]
pub unsafe extern "C" fn destroy_seeder_builder(seeder_builder: *mut SeederBuilder) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(seeder_builder).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(seeder_builder));
    })
}

/// [Unchecked](crate#safety-checked-and-unchecked-functions) version of
/// [`destroy_seeder_builder`].
#[no_mangle]
pub unsafe extern "C" fn destroy_seeder_builder_unchecked(
    seeder_builder: *mut SeederBuilder,
) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(seeder_builder));
    })
}
