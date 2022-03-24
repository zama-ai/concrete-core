use clap::Parser;
use concrete_commons::dispersion::{DispersionParameter, StandardDev, Variance};
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    AbstractEngine, CoreEngine, FourierGgswCiphertext64, GlweCiphertext64,
};
use concrete_core_fixture::fixture::{
    Fixture, GlweCiphertextGgswCiphertextExternalProductFixture,
    GlweCiphertextGgswCiphertextExternalProductParameters,
};
use concrete_core_fixture::generation::{Maker, Precision64};
use concrete_core_fixture::{Repetitions, SampleSize};
use indicatif::ProgressIterator;
use itertools::iproduct;
/// The number of time a test is repeated for a single set of parameter.
///
/// Number of different keys
pub const REPETITIONS: Repetitions = Repetitions(15);

pub const DEBUG: bool = false;

///// The size of the sample  per keys
pub const POT: usize = 40;

use concrete_npe;
use f64;
use std::fs::OpenOptions;
use std::io::Write;

fn variance_to_stddev(var: Variance) -> StandardDev {
    StandardDev::from_standard_dev(var.get_standard_dev())
}

fn write_to_file(
    params: &GlweCiphertextGgswCiphertextExternalProductParameters,
    input_stddev: StandardDev,
    output_stddev: StandardDev,
    pred_stddev: StandardDev,
    id: usize,
) {
    let data_to_save = format!(
        "{}, {}, {}, {}, {}, {}, {}\n",
        params.polynomial_size.0,
        params.glwe_dimension.0,
        params.decomposition_level_count.0,
        params.decomposition_base_log.0,
        input_stddev.get_variance(),
        output_stddev.get_variance(),
        pred_stddev.get_variance()
    );

    let _data_to_print = format!(
        "{}, {}, {}, {}, {}, {},{}\n",
        params.polynomial_size.0,
        params.glwe_dimension.0,
        params.decomposition_level_count.0,
        params.decomposition_base_log.0,
        input_stddev.get_log_standard_dev(),
        output_stddev.get_log_standard_dev(),
        pred_stddev.get_log_standard_dev(),
    );
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open(format!("{}.acquisition_external_product_k=1", id))
    {
        Err(why) => panic!("{}", why),
        Ok(file) => file,
    };
    file.write(data_to_save.as_bytes()).unwrap();
}

fn write_to_file_debug(
    params: &GlweCiphertextGgswCiphertextExternalProductParameters,
    errors: &[f64],
    rep: usize,
) {
    let filename = format!(
        "samples/{}.{}-{}-{}-{}.extprod.samples",
        rep,
        params.polynomial_size.0,
        params.glwe_dimension.0,
        params.decomposition_level_count.0,
        params.decomposition_base_log.0,
    );
    // let data_to_save = format!(
    //     "{}, {}, {}, {}, {}, {}, {}, ",
    //     params.polynomial_size.0,
    //     params.glwe_dimension.0,
    //     params.decomposition_level_count.0,
    //     params.decomposition_base_log.0,
    //     input_stddev.get_variance(),
    //     output_stddev.get_variance(),
    //     pred_stddev.get_variance(),
    // );
    // file.write(data_to_save.as_bytes()).unwrap();

    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
    {
        Err(why) => panic!("{}", why),
        Ok(file) => file,
    };

    if errors.len() > 0 {
        let errors: String = errors
            .iter()
            .map(|x| x.to_string()) // format!("{}", x))
            .collect::<Vec<String>>()
            .join(", ");
        file.write(errors.as_bytes()).unwrap();
    }
}
#[derive(Debug)]
struct NotABit(u64);

fn minimal_variance_for_security_64(k: GlweDimension, size: PolynomialSize) -> f64 {
    f64::max(
        f64::powf(
            2.,
            -2. * 0.026374888765705498 * k.0 as f64 * size.0 as f64 + 2. * 2.012143923330495,
        ),
        f64::powi(2., -(2 * 64 - 2 * 2)),
    )
}

fn mean(data: &[f64]) -> Option<f64> {
    // adapted from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    let sum = data.iter().sum::<f64>() as f64;
    let count = data.len();

    match count {
        positive if positive > 0 => Some(sum / count as f64),
        _ => None,
    }
}

fn std_deviation(data: &[f64]) -> Option<StandardDev> {
    // from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    // replacing the mean by 0. as we theoretically know it
    match (mean(data), data.len()) {
        (Some(_data_mean), count) if count > 0 => {
            let variance = data
                .iter()
                .map(|value| {
                    let diff = 0. - (*value as f64);

                    diff * diff
                })
                .sum::<f64>()
                / count as f64;

            Some(StandardDev::from_modular_standard_dev::<u64>(
                variance.sqrt(),
            ))
        }
        _ => None,
    }
}

fn compute_error(errs: &mut [f64], output: Vec<u64>, input: Vec<u64>, bit: u64) {
    match bit {
        1 => {
            for (out, (inp, err)) in output.iter().zip(input.iter().zip(errs.iter_mut())) {
                *err = (out.wrapping_sub(*inp)) as i64 as f64;
            }
        }
        0 => {
            for (out, err) in output.iter().zip(errs.iter_mut()) {
                *err = *out as i64 as f64;
            }
        }
        _ => panic!("Not a bit: {:?}", NotABit(bit)),
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Total number of thread
    #[clap(long, short)]
    tot: usize,
    /// Current Thread ID
    #[clap(long, short)]
    id: usize,
}

fn main() {
    let args = Args::parse();
    let tot = args.tot;
    let id = args.id;
    // let n_threads = args.n_threads;
    // Fixture Init
    let mut maker = Maker::default();
    let mut engine = CoreEngine::new().unwrap();
    type Precision = Precision64;

    // Parameter Grid
    let polynomial_sizes = vec![
        1usize << 8,
        1 << 9,
        1 << 10,
        1 << 11,
        1 << 12,
        1 << 13,
        1 << 14,
    ];
    let max_polynomial_size = 1 << 14;
    let glwe_dimensions = vec![1usize];

    let mut base_logs = vec![1usize; 64];
    for b in 1..65 {
        base_logs[b - 1] = b;
    }
    let mut levels = vec![1; 64];
    for level in 1..65 {
        levels[level - 1] = level;
    }

    // let mut base_logs = vec![10usize; 1];
    // let mut levels = vec![4; 1];

    // Xperiment

    let hypercube = iproduct!(base_logs, glwe_dimensions, levels, polynomial_sizes);

    // for size in polynomial_sizes.iter() {
    //     for l in levels.iter() {
    //         for b in base_logs.iter() {
    //             if l * b <= 53 {
    //                 for k in glwe_dimensions.iter() {

    let hypercube: Vec<(usize, usize, usize, usize)> = hypercube.collect();

    // only keeping part of the hypercube
    let chunk_size = hypercube.len() / tot;
    // let hypercube = hypercube[id * chunk_size..(id + 1) * chunk_size];

    // vec![(0usize, 0, 0, 0); polynomial_sizes.len() * levels.len() * base_logs.len() * glwe_dimensions.len()];
    println!(
        "-> Computing chunk [{}..{}]",
        id * chunk_size,
        (id + 1) * chunk_size
    );
    for (b, k, l, size) in hypercube[id * chunk_size..(id + 1) * chunk_size]
        .iter()
        .progress()
    {
        if b * l <= 64 {
            let sample_size = SampleSize(POT * max_polynomial_size / *size);
            let glwe_dimension = GlweDimension(*k);
            let poly_size = PolynomialSize(*size);
            let dec_level_count = DecompositionLevelCount(*l);
            let dec_base_log = DecompositionBaseLog(*b);
            let ggsw_noise = Variance::from_variance(minimal_variance_for_security_64(
                glwe_dimension,
                poly_size,
            ));
            let glwe_noise = Variance::from_variance(minimal_variance_for_security_64(
                glwe_dimension,
                poly_size,
            ));

            let parameters = GlweCiphertextGgswCiphertextExternalProductParameters {
                ggsw_noise,
                glwe_noise,
                glwe_dimension,
                polynomial_size: poly_size,
                decomposition_base_log: dec_base_log,
                decomposition_level_count: dec_level_count,
            };

            let noise_prediction = concrete_npe::estimate_external_product_noise_with_binary_ggsw::<
                u64,
                _,
                _,
                BinaryKeyKind,
            >(
                poly_size,
                glwe_dimension,
                glwe_noise,
                glwe_noise,
                dec_base_log,
                dec_level_count,
            );

            let mut errors = vec![0.; sample_size.0 * *size * REPETITIONS.0];

            if noise_prediction.get_variance() < 1. / 12. {
                for (_, errs) in (0..REPETITIONS.0).zip(errors.chunks_mut(sample_size.0 * *size)) {
                    let repetitions =
                        <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
                            Precision,
                            CoreEngine,
                            (GlweCiphertext64, FourierGgswCiphertext64, GlweCiphertext64),
                        >>::generate_random_repetition_prototypes(
                            &parameters, &mut maker
                        );
                    let outputs = <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
                        Precision,
                        CoreEngine,
                        (GlweCiphertext64, FourierGgswCiphertext64, GlweCiphertext64),
                    >>::sample(
                        &mut maker,
                        &mut engine,
                        &parameters,
                        &repetitions,
                        sample_size,
                    );
                    let (raw_inputs, output): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
                    let raw_input_plaintext_vector =
                        raw_inputs.into_iter().flatten().collect::<Vec<_>>();
                    let output_plaintext_vector = output.into_iter().flatten().collect::<Vec<_>>();

                    // errors[rep * sample_size.0 * *size..(rep + 1) * sample_size.0 * *size] =
                    compute_error(
                        errs,
                        output_plaintext_vector,
                        raw_input_plaintext_vector,
                        1 as u64,
                    );
                }
                let _mean_err = mean(&errors).unwrap();
                let std_err = std_deviation(&errors).unwrap();
                if DEBUG {
                    write_to_file_debug(&parameters, &errors, id);
                } else {
                    write_to_file(
                        &parameters,
                        variance_to_stddev(glwe_noise),
                        std_err,
                        variance_to_stddev(noise_prediction),
                        id,
                    );
                }
            } else {
                if DEBUG {
                    write_to_file_debug(&parameters, &vec![], 0usize)
                } else {
                    write_to_file(
                        &parameters,
                        variance_to_stddev(glwe_noise),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        id,
                    )
                }
            }
        }
    }
}
//                     }
//                 }
//             }
//         }
//     }
// }
