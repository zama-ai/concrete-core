//! This program uses the concrete csprng to generate an infinite stream of random bytes on
//! the program stdout. It can also generate a fixed number of bytes by passing a value along the
//! optional argument `--bytes_total`, use the feature option `csprng_generate_bin_clap` to enable
//! CLI support. For testing purpose.
use clap::{Arg, Command};
use concrete_csprng::generators::{AesniRandomGenerator, RandomGenerator};
use concrete_csprng::seeders::{RdseedSeeder, Seeder};
use std::io::prelude::*;
use std::io::{stdout, Stdout};

fn write_bytes(buffer: &mut [u8], generator: &mut AesniRandomGenerator, stdout: &mut Stdout) {
    buffer.iter_mut().zip(generator).for_each(|(b, g)| *b = g);
    stdout.write_all(buffer).unwrap();
}

fn infinite_bytes_generation(
    buffer: &mut [u8],
    generator: &mut AesniRandomGenerator,
    stdout: &mut Stdout,
) {
    loop {
        write_bytes(buffer, generator, stdout);
    }
}

fn bytes_generation(
    bytes_total: usize,
    buffer: &mut [u8],
    generator: &mut AesniRandomGenerator,
    stdout: &mut Stdout,
) {
    let quotient = bytes_total / buffer.len();
    let remaining = bytes_total % buffer.len();

    if quotient > 0 {
        for _ in 0..quotient {
            write_bytes(buffer, generator, stdout);
        }
    }

    if remaining > 0 {
        write_bytes(&mut buffer[0..remaining], generator, stdout)
    }
}

pub fn main() {
    let matches = Command::new("Generate a stream of random numbers")
        .arg(
            Arg::new("bytes_total")
                .short('b')
                .long("bytes_total")
                .takes_value(true)
                .help("Total number of bytes that has to be generated"),
        )
        .get_matches();

    let mut seeder = RdseedSeeder;
    let mut generator = AesniRandomGenerator::new(seeder.seed());
    let mut stdout = stdout();
    let mut buffer = [0u8; 16];
    match matches.value_of("bytes_total") {
        Some(total) => {
            bytes_generation(
                total.parse::<usize>().unwrap(),
                &mut buffer,
                &mut generator,
                &mut stdout,
            );
        }
        None => {
            infinite_bytes_generation(&mut buffer, &mut generator, &mut stdout);
        }
    };
}
