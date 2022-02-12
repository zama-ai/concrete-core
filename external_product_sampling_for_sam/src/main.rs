use concrete_commons::dispersion::{DispersionParameter, StandardDev, Variance};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    AbstractEngine, CoreEngine, GgswCiphertextComplex64, GlweCiphertext64,
};
use concrete_core_fixture::fixture::{
    Fixture, GlweCiphertextGgswCiphertextExternalProductFixture,
    GlweCiphertextGgswCiphertextExternalProductParameters,
};
use concrete_core_fixture::generation::{IntegerPrecision, Maker, Precision64};
use concrete_core_fixture::raw::generation::RawUnsignedIntegers;
use concrete_core_fixture::SampleSize;
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
) {
    let data = format!(
        "{}, {}, {}, {}, {}, {},{}, {}, {}, {}\n",
        params.poly_size.0,
        params.glwe_dimension.0,
        params.dec_level_count.0,
        params.dec_base_log.0,
        input_stddev.get_log_standard_dev(),
        output_stddev.get_log_standard_dev(),
        pred_stddev.get_log_variance(),
        input_stddev.get_variance(),
        output_stddev.get_variance(),
        pred_stddev.get_variance() // glwe_std.get_variance(),
                                   // Variance::from_variance(output_variance).get_log_standard_dev()
    );
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open("test.acquisition_external_product.txt")
    {
        Err(why) => panic!("{}", why),
        Ok(file) => file,
    };
    file.write(data.as_bytes());
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
    match (mean(data), data.len()) {
        (Some(data_mean), count) if count > 0 => {
            let variance = data
                .iter()
                .map(|value| {
                    let diff = data_mean - (*value as f64);

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

fn compute_error(output: &[u64], input: &[u64], bit: u64) -> Result<Vec<f64>, NotABit> {
    match bit {
        1 => Ok(output
            .iter()
            .zip(input.iter())
            .map(|(out, inp)| (out.wrapping_sub(*inp)) as i64 as f64)
            .collect()),
        0 => Ok(output.iter().map(|out| *out as i64 as f64).collect()),
        _ => Err(NotABit(bit)),
    }
}

fn main() {
    // TODO: faire plus de samples quand petits polynomes

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
    let glwe_dimensions = vec![1usize, 2, 3, 4, 5];
    let mut base_logs = vec![1usize; 64];
    for b in 1..65 {
        base_logs[b - 1] = b;
    }
    let mut levels = vec![1; 64];
    for level in 1..65 {
        levels[level - 1] = level;
    }

    // Xperiment
    for l in levels.iter() {
        for b in base_logs.iter() {
            if l * b <= 53 {
                for k in glwe_dimensions.iter() {
                    for size in polynomial_sizes.iter() {
                        let sample_size = SampleSize(5 * max_polynomial_size / size);
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
                            poly_size,
                            dec_level_count,
                            dec_base_log,
                        };

                        let raw_inputs = (
                            1 as u64,
                            // <Precision as IntegerPrecision>::Raw::uniform(),
                            // ^ Sampling of the raw message put in the ggsw
                            <Precision as IntegerPrecision>::Raw::uniform_n_msb_vec(3, poly_size.0),
                            // ^ Sampling of the raw messages put in the glwe coefficients
                        );

                        // The output is a vec containing polynomials with integer coefficients (here u64).
                        let output: Vec<Vec<_>> =
                            <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
                                Precision,
                                CoreEngine,
                                (GlweCiphertext64, GgswCiphertextComplex64, GlweCiphertext64),
                            >>::sample(
                                &mut maker,
                                &mut engine,
                                &parameters,
                                &raw_inputs,
                                sample_size,
                            )
                            .into_iter()
                            .map(|(v,)| v)
                            .collect();

                        let input_bit = raw_inputs.0;
                        let input_polynomial = raw_inputs.1;

                        let err: Vec<f64> = output
                            .iter()
                            .map(|out| compute_error(out, &input_polynomial, raw_inputs.0).unwrap())
                            .into_iter()
                            .flatten()
                            .collect();

                        let mean_err = mean(&err).unwrap();
                        let std_err = std_deviation(&err).unwrap();
                        // println!(
                        //     "-> Mean: {} \n-> Log2StdDev: {}",
                        //     mean_err,
                        //     std_err.get_log_standard_dev()
                        // );
                        let noise_prediction =
                            concrete_npe::estimate_external_product_noise_with_binary_ggsw(
                                poly_size,
                                glwe_dimension,
                                glwe_noise,
                                glwe_noise,
                                dec_base_log,
                                dec_level_count,
                            );
                        write_to_file(
                            &parameters,
                            variance_to_stddev(glwe_noise),
                            std_err,
                            variance_to_stddev(noise_prediction),
                        );
                    }
                }
            }
        }
    }
    // You can now save the output the way you want
}
