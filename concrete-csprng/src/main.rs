//! This program uses the concrete csprng to generate an infinite stream of random bytes on
//! the program stdout. It can also generate a fixed number of bytes by passing a value along the
//! optional argument `--bytes_total`. For testing purpose.
use clap::{Arg, Command};
use concrete_csprng::generators::{AesniRandomGenerator, RandomGenerator};
use concrete_csprng::seeders::{RdseedSeeder, Seeder};
use std::io::prelude::*;
use std::io::{stdout, Stdout};

fn write_bytes(buffer: &mut [u8], generator: &mut AesniRandomGenerator, stdout: &mut Stdout) {
    buffer.iter_mut().zip(generator).for_each(|(b, g)| *b = g);
    stdout.write_all(buffer).unwrap();
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
            let total = total.parse::<usize>().unwrap();
            let quotient = total / buffer.len();
            let remaining = total % buffer.len();

            if quotient > 0 {
                for _ in 0..quotient {
                    write_bytes(&mut buffer, &mut generator, &mut stdout);
                }
            }

            if remaining > 0 {
                write_bytes(&mut buffer[0..remaining], &mut generator, &mut stdout)
            }
        }
        None => loop {
            write_bytes(&mut buffer, &mut generator, &mut stdout);
        },
    };
}
