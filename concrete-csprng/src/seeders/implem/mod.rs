#[cfg(feature = "seeder_x86_64_rdseed")]
mod rdseed;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use rdseed::RdseedSeeder;

#[cfg(feature = "seeder_linux")]
mod linux;
#[cfg(feature = "seeder_linux")]
pub use linux::LinuxSeeder;
