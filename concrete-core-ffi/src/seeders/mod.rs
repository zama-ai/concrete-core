//! Module to manage `concrete-core` compatible seeders across the FFI boundary.

#[cfg(target_os = "macos")]
pub mod apple_secure_enclave_seeder;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub mod rdseed_x86_64_seeder;
pub mod seeder_builder;
#[cfg(feature = "seeder_unix")]
pub mod unix_seeder;

#[cfg(target_os = "macos")]
pub use apple_secure_enclave_seeder::*;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use rdseed_x86_64_seeder::*;
pub use seeder_builder::*;
#[cfg(feature = "seeder_unix")]
pub use unix_seeder::*;
