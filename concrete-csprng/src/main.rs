//! This program uses the concrete csprng to generate an infinite stream of random bytes on
//! the program stdout. For testing purpose.
#[cfg(target_arch = "x86_64")]
use concrete_csprng::generators::AesniRandomGenerator as ActivatedRandomGenerator;
#[cfg(target_arch = "aarch64")]
use concrete_csprng::generators::ArmAesRandomGenerator as ActivatedRandomGenerator;
#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
use concrete_csprng::generators::SoftwareRandomGenerator as ActivatedRandomGenerator;

use concrete_csprng::generators::RandomGenerator;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use concrete_csprng::seeders::AppleSecureEnclaveSeeder as ActivatedSeeder;
#[cfg(target_arch = "x86_64")]
use concrete_csprng::seeders::RdseedSeeder as ActivatedSeeder;

use concrete_csprng::seeders::Seeder;

use std::io::prelude::*;
use std::io::stdout;

pub fn main() {
    let mut seeder = ActivatedSeeder;
    let mut generator = ActivatedRandomGenerator::new(seeder.seed());
    let mut stdout = stdout();
    let mut buffer = [0u8; 16];
    loop {
        buffer
            .iter_mut()
            .zip(&mut generator)
            .for_each(|(b, g)| *b = g);
        stdout.write_all(&buffer).unwrap();
    }
}
